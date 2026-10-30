#!/usr/bin/env python3
"""Validate versioned release archives using only the Python standard library."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile


SEMVER = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)
ARCHITECTURES = {"amd64": 62, "arm64": 183}


def validate_version(version, allow_dev=False):
    if allow_dev and version == "dev":
        return False
    match = SEMVER.fullmatch(version)
    if not match or len(version) > 100:
        raise ValueError("version must be vMAJOR.MINOR.PATCH with optional SemVer prerelease/build metadata")
    prerelease = match[4]
    if prerelease and any(part.isdigit() and len(part) > 1 and part[0] == "0" for part in prerelease.split(".")):
        raise ValueError("numeric prerelease identifiers cannot have leading zeroes")
    return bool(prerelease)


def validate_commit(commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be the full 40-character Git SHA")


def package_name(version, arch):
    validate_version(version, allow_dev=True)
    if arch not in ARCHITECTURES:
        raise ValueError(f"unsupported architecture: {arch}")
    return f"derper-go_{version}_linux_{arch}"


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_package(path, version, commit, arch):
    validate_commit(commit)
    root = package_name(version, arch)
    path = Path(path)
    if path.name != root + ".tar.gz":
        raise ValueError("archive filename differs from its expected version/architecture")
    required = {"derper-go", "build-info.json", "LICENSE", "NOTICE", "README.md", "go.mod", "go.sum",
                "examples/config.json", "docs/DEPLOYMENT.md", "licenses/tailscale.com-LICENSE", "licenses/go-LICENSE"}
    with tarfile.open(path, "r:gz") as archive:
        seen = set()
        total = 0
        for member in archive:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != root
                    or member.name.rstrip("/") != str(name) or member.name in seen):
                raise ValueError(f"unsafe or duplicate archive path: {member.name}")
            seen.add(member.name)
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"links and special archive entries are forbidden: {member.name}")
            mode = 0o755 if member.isdir() or member.name == root + "/derper-go" else 0o644
            if member.mode != mode or member.uid != 0 or member.gid != 0:
                raise ValueError(f"unexpected archive ownership or mode: {member.name}")
            total += member.size
            if total > 128 * 1024 * 1024:
                raise ValueError("archive exceeds the uncompressed size limit")
        if not {root + "/" + name for name in required}.issubset(seen):
            raise ValueError("archive is missing the binary, metadata, documentation or licenses")
        metadata = json.load(archive.extractfile(root + "/build-info.json"))
        for key, value in {"version": version, "commit": commit, "os": "linux", "arch": arch}.items():
            if metadata.get(key) != value:
                raise ValueError(f"build-info.json {key} differs from the requested release")
        binary = archive.extractfile(root + "/derper-go")
        header = binary.read(64)
        if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != ARCHITECTURES[arch]:
            raise ValueError("binary ELF architecture is incorrect")
        offset, entry_size, count = struct.unpack_from("<Q", header, 32)[0], struct.unpack_from("<H", header, 54)[0], struct.unpack_from("<H", header, 56)[0]
        if entry_size < 56 or count < 1 or offset + entry_size * count > 1 << 20:
            raise ValueError("invalid ELF program headers")
        for index in range(count):
            binary.seek(offset + index * entry_size)
            program = binary.read(entry_size)
            if len(program) != entry_size or struct.unpack_from("<I", program)[0] == 3:
                raise ValueError("release binary is truncated or requires a dynamic loader")
    return path


def release_assets(directory, version, commit):
    directory = Path(directory)
    paths = [directory / (package_name(version, arch) + ".tar.gz") for arch in ARCHITECTURES]
    if set(directory.glob("*.tar.gz")) != set(paths):
        raise ValueError("release must contain exactly the two expected Linux archives")
    for arch, path in zip(ARCHITECTURES, paths):
        verify_package(path, version, commit, arch)
    return paths


def write_checksums(directory, version, commit):
    paths = release_assets(directory, version, commit)
    contents = "".join(f"{sha256(path)}  {path.name}\n" for path in paths)
    target = Path(directory) / "checksums.txt"
    target.write_text(contents, encoding="utf-8")
    return paths + [target]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    version = commands.add_parser("version")
    version.add_argument("version")
    version.add_argument("--allow-dev", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("archive", type=Path)
    verify.add_argument("version")
    verify.add_argument("commit")
    verify.add_argument("arch")
    manifest = commands.add_parser("checksums")
    manifest.add_argument("directory", type=Path)
    manifest.add_argument("version")
    manifest.add_argument("commit")
    args = parser.parse_args()
    try:
        if args.command == "version":
            prerelease = validate_version(args.version, args.allow_dev)
            print(f"version={args.version}\nprerelease={str(prerelease).lower()}")
        elif args.command == "verify":
            verify_package(args.archive, args.version, args.commit, args.arch)
        else:
            write_checksums(args.directory, args.version, args.commit)
    except (ValueError, OSError, tarfile.TarError) as error:
        parser.exit(1, f"release validation failed: {error}\n")


if __name__ == "__main__":
    main()
