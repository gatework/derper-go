import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

from release_assets import package_name, validate_version, verify_package, write_checksums

COMMIT = "a" * 40
VERSION = "v0.1.0"


def make_archive(directory, arch="amd64", version=VERSION, commit=COMMIT, extra=None, interpreter=False):
    root = package_name(version, arch)
    path = Path(directory) / (root + ".tar.gz")
    binary = bytearray(120)
    binary[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", binary, 18, 62 if arch == "amd64" else 183)
    struct.pack_into("<Q", binary, 32, 64)
    struct.pack_into("<HH", binary, 54, 56, 1)
    struct.pack_into("<I", binary, 64, 3 if interpreter else 1)
    files = {"derper-go": bytes(binary), "build-info.json": json.dumps({"version": version, "commit": commit, "os": "linux", "arch": arch}).encode()}
    for name in ("LICENSE", "NOTICE", "README.md", "CHANGELOG.md", "go.mod", "go.sum", "examples/config.json", "docs/DEPLOYMENT.md", "licenses/tailscale.com-LICENSE", "licenses/go-LICENSE"):
        files[name] = b"fixture"
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        for name, value in files.items():
            member = tarfile.TarInfo(root + "/" + name)
            member.mode = 0o755 if name == "derper-go" else 0o644
            member.size = len(value)
            archive.addfile(member, io.BytesIO(value))
        if extra:
            archive.addfile(extra)
    return path


class ReleaseAssetsTest(unittest.TestCase):
    def test_semver_and_prerelease(self):
        for tag, prerelease in (("v0.1.0", False), ("v12.2.3+build.12", False), ("v1.2.3-rc.1", True), ("v1.2.3-beta", True)):
            self.assertEqual(validate_version(tag), prerelease)
        for tag in ("1.0.0", "v01.0.0", "v1.0.0-01", "v1.0.0-rc..1", "v1.0.0\n", "v1.2.3;echo bad", "../v1.0.0", "dev"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                validate_version(tag)
        self.assertFalse(validate_version("dev", allow_dev=True))

    def test_exact_version_and_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = make_archive(directory)
            verify_package(path, VERSION, COMMIT, "amd64")
            with self.assertRaises(ValueError):
                verify_package(path, VERSION, "b" * 40, "amd64")
            with self.assertRaises(ValueError):
                verify_package(path, VERSION, COMMIT, "arm64")
            make_archive(directory, interpreter=True)
            with self.assertRaisesRegex(ValueError, "dynamic loader"):
                verify_package(path, VERSION, COMMIT, "amd64")

    def test_unsafe_archive_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                               (package_name(VERSION, "amd64") + "/link", tarfile.SYMTYPE),
                               (package_name(VERSION, "amd64") + "/README.md", tarfile.REGTYPE)):
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.mode = 0o644
                path = make_archive(directory, extra=entry)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    verify_package(path, VERSION, COMMIT, "amd64")

    def test_checksums_require_both_architectures_and_reject_stale_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            make_archive(directory)
            with self.assertRaises(ValueError):
                write_checksums(directory, VERSION, COMMIT)
            make_archive(directory, "arm64")
            files = write_checksums(directory, VERSION, COMMIT)
            self.assertEqual(len(files), 3)
            original = files[-1].read_bytes()
            write_checksums(directory, VERSION, COMMIT)
            self.assertEqual(files[-1].read_bytes(), original)
            (Path(directory) / "stale.tar.gz").write_bytes(b"old version")
            with self.assertRaises(ValueError):
                write_checksums(directory, VERSION, COMMIT)
