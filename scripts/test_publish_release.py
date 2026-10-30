import contextlib
import copy
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from publish_release import GitHub, publish_release
from test_release_assets import COMMIT, VERSION, make_archive


class FakeGitHub:
    repository = "gatework/derper-go"

    def __init__(self):
        self.commit = COMMIT
        self.release = None
        self.remote = {}
        self.uploaded = []
        self.deleted = []
        self.published = 0
        self.fail_upload_once = False
        self.tag_moves = False
        self.lookup_error = False
        self.next_id = 1

    def tag_commit(self, tag):
        return self.commit

    def find_release(self, tag):
        if self.lookup_error:
            raise subprocess.CalledProcessError(1, "gh", stderr="HTTP 403")
        return copy.deepcopy(self.release)

    def create_draft(self, tag, commit, prerelease, notes):
        self.release = {"id": 1, "draft": True, "tag_name": tag, "prerelease": prerelease, "html_url": "https://example.invalid/release"}
        return copy.deepcopy(self.release)

    def assets(self, release):
        return [{"id": item["id"], "name": name, "size": len(item["data"]), "state": item["state"]} for name, item in self.remote.items()]

    def upload(self, tag, path):
        self.uploaded.append(path.name)
        self.remote[path.name] = {"id": self.next_id, "state": "uploaded", "data": path.read_bytes()}
        self.next_id += 1
        if self.fail_upload_once:
            self.fail_upload_once = False
            raise subprocess.CalledProcessError(1, "gh", stderr="response lost after upload")

    def download(self, tag, name, directory):
        path = Path(directory) / name
        path.write_bytes(self.remote[name]["data"])
        if self.tag_moves:
            self.commit = "b" * 40
        return path

    def delete_incomplete(self, asset):
        self.deleted.append(asset["id"])
        del self.remote[asset["name"]]

    def publish(self, release, prerelease):
        self.published += 1
        self.release["draft"] = False
        return copy.deepcopy(self.release)


class PublishReleaseTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.directory = Path(self.directory.name)
        make_archive(self.directory)
        make_archive(self.directory, "arm64")
        self.github = FakeGitHub()

    def publish(self, tag=VERSION):
        with contextlib.redirect_stdout(io.StringIO()):
            publish_release(self.github, tag, COMMIT, self.directory)

    def test_publish_and_rerun_never_replace_uploaded_bytes(self):
        self.publish()
        self.assertEqual(self.github.published, 1)
        self.assertEqual(len(self.github.uploaded), 3)
        before = copy.deepcopy(self.github.remote)
        self.publish()
        self.assertEqual(self.github.remote, before)
        self.assertEqual(self.github.published, 1)
        self.assertEqual(len(self.github.uploaded), 3)

    def test_upload_response_loss_resumes_existing_draft(self):
        self.github.fail_upload_once = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish()
        self.assertTrue(self.github.release["draft"])
        self.assertEqual(self.github.published, 0)
        self.publish()
        self.assertFalse(self.github.release["draft"])
        self.assertEqual(len(self.github.uploaded), 3)

    def test_only_incomplete_draft_placeholders_can_be_deleted(self):
        self.github.create_draft(VERSION, COMMIT, False, "")
        name = next(self.directory.glob("*amd64.tar.gz")).name
        self.github.remote[name] = {"id": 99, "state": "starter", "data": b""}
        self.publish()
        self.assertEqual(self.github.deleted, [99])

    def test_published_asset_mismatch_is_never_overwritten(self):
        self.publish()
        name = next(iter(self.github.remote))
        self.github.remote[name]["data"] = b"wrong content"
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(len(self.github.uploaded), 3)
        self.assertEqual(self.github.deleted, [])
        self.assertEqual(self.github.published, 1)

    def test_missing_published_asset_is_not_repaired_in_place(self):
        self.publish()
        del self.github.remote[next(iter(self.github.remote))]
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(len(self.github.uploaded), 3)

    def test_corrupted_draft_asset_refuses_clobber(self):
        self.github.fail_upload_once = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish()
        item = next(iter(self.github.remote.values()))
        item["data"] = b"x" * len(item["data"])
        with self.assertRaisesRegex(ValueError, "tested bytes"):
            self.publish()
        self.assertEqual(self.github.published, 0)
        self.assertEqual(self.github.deleted, [])

    def test_api_failure_is_not_missing_release(self):
        self.github.lookup_error = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish()
        self.assertIsNone(self.github.release)
        self.assertEqual(self.github.uploaded, [])

    def test_moved_tag_does_not_publish(self):
        self.github.tag_moves = True
        with self.assertRaisesRegex(ValueError, "tag moved"):
            self.publish()
        self.assertTrue(self.github.release["draft"])
        self.assertEqual(self.github.published, 0)

    def test_unexpected_remote_asset_is_preserved_and_blocks_publication(self):
        self.github.create_draft(VERSION, COMMIT, False, "")
        self.github.remote["operator-file"] = {"id": 99, "state": "uploaded", "data": b"keep"}
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.publish()
        self.assertEqual(self.github.uploaded, [])
        self.assertEqual(self.github.deleted, [])

    def test_prerelease_stays_prerelease(self):
        for path in self.directory.iterdir():
            path.unlink()
        tag = "v0.1.0-rc.1"
        make_archive(self.directory, version=tag)
        make_archive(self.directory, "arm64", version=tag)
        self.publish(tag)
        self.assertTrue(self.github.release["prerelease"])

    def test_github_latest_policy(self):
        github = GitHub("gatework/derper-go")
        with patch.object(github, "api") as api:
            github.publish({"id": 12}, True)
            self.assertEqual(api.call_args.args[2]["make_latest"], "false")
            github.publish({"id": 12}, False)
            self.assertEqual(api.call_args.args[2]["make_latest"], "legacy")

    def test_annotation_is_peeled_to_commit(self):
        github = GitHub("gatework/derper-go")
        with patch.object(github, "api", side_effect=[{"object": {"type": "tag", "sha": "b" * 40}}, {"object": {"type": "commit", "sha": COMMIT}}]):
            self.assertEqual(github.tag_commit(VERSION), COMMIT)
