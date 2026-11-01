import subprocess
import tempfile
import unittest
from pathlib import Path

from release_assets import source_snapshot


class SourceSnapshotTest(unittest.TestCase):
    def repository(self, directory):
        root = Path(directory) / "repository"
        root.mkdir()
        def git(*args):
            return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL).decode().strip()
        git("init", "-q")
        git("config", "user.email", "fixture@example.com")
        git("config", "user.name", "Fixture")
        (root / "source.go").write_text("package main\n")
        (root / ".gitignore").write_text("*.token\n")
        git("add", ".")
        git("commit", "-qm", "fixture")
        return root, git, git("rev-parse", "HEAD")

    def test_excludes_ignored_secrets_and_untracked_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, commit = self.repository(directory)
            (root / "fixture.token").write_text("not-a-real-token")
            (root / "untracked.md").write_text("must not ship")
            destination = Path(directory) / "snapshot"
            source_snapshot(root, commit, destination)
            self.assertEqual((destination / "source.go").read_text(), "package main\n")
            self.assertFalse((destination / "fixture.token").exists())
            self.assertFalse((destination / "untracked.md").exists())

    def test_rejects_dirty_or_mismatched_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root, git, commit = self.repository(directory)
            with self.assertRaises(ValueError):
                source_snapshot(root, "0" * 40, Path(directory) / "wrong")
            (root / "source.go").write_text("modified\n")
            with self.assertRaises(ValueError):
                source_snapshot(root, commit, Path(directory) / "dirty")
            git("add", ".")
            with self.assertRaises(ValueError):
                source_snapshot(root, commit, Path(directory) / "staged")

    def test_rejects_tracked_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root, git, _ = self.repository(directory)
            (root / "linked.go").symlink_to("source.go")
            git("add", ".")
            git("commit", "-qm", "link")
            with self.assertRaises(ValueError):
                source_snapshot(root, git("rev-parse", "HEAD"), Path(directory) / "snapshot")
