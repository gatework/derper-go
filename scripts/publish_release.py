#!/usr/bin/env python3
"""Publish verified assets through a draft, without replacing released bytes."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import quote

from release_assets import sha256, validate_commit, validate_version, write_checksums


class GitHub:
    def __init__(self, repository):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid GitHub repository")
        self.repository = repository
        self.prefix = "repos/" + repository

    def command(self, *arguments, payload=None):
        result = subprocess.run(
            ["gh", *arguments], input=None if payload is None else json.dumps(payload),
            text=True, capture_output=True, check=True,
        )
        return result.stdout

    def api(self, endpoint, method="GET", payload=None):
        args = ["api", self.prefix + endpoint, "--method", method,
                "-H", "X-GitHub-Api-Version: 2026-03-10"]
        if payload is not None:
            args += ["--input", "-"]
        result = self.command(*args, payload=payload)
        return json.loads(result) if result else None

    def paginated(self, endpoint):
        values = []
        for page in range(1, 1001):
            batch = self.api(f"{endpoint}?per_page=100&page={page}")
            if not isinstance(batch, list):
                raise ValueError("GitHub returned an invalid list")
            values.extend(batch)
            if len(batch) < 100:
                return values
        raise ValueError("GitHub pagination limit exceeded")

    def find_release(self, tag):
        # List includes authenticated drafts. Do not treat API/auth/rate-limit
        # errors as absence or rely on the published-release-by-tag endpoint.
        matches = [item for item in self.paginated("/releases") if item["tag_name"] == tag]
        if len(matches) > 1:
            raise ValueError("more than one release has the requested tag")
        return matches[0] if matches else None

    def tag_commit(self, tag):
        item = self.api("/git/ref/tags/" + quote(tag, safe=""))["object"]
        for _ in range(10):
            validate_commit(item["sha"])
            if item["type"] == "commit":
                return item["sha"]
            if item["type"] != "tag":
                break
            item = self.api("/git/tags/" + item["sha"])["object"]
        raise ValueError("tag does not resolve to a commit")

    def create_draft(self, tag, commit, prerelease, notes):
        with tempfile.TemporaryDirectory(prefix="derper-release-") as directory:
            body = Path(directory) / "notes.md"
            body.write_text(notes, encoding="utf-8")
            args = ["release", "create", tag, "--repo", self.repository, "--verify-tag", "--draft",
                    "--target", commit, "--title", tag, "--notes-file", str(body), "--generate-notes"]
            if prerelease:
                args.append("--prerelease")
            self.command(*args)
        # GitHub may acknowledge creation before its release list exposes the
        # draft. Retry only this read-after-write absence, never an API error.
        for attempt in range(8):
            release = self.find_release(tag)
            if release is not None:
                return release
            if attempt < 7:
                time.sleep(min(0.5 * 2 ** attempt, 8))
        raise ValueError("draft was created but is not visible yet; rerun to resume it")

    def assets(self, release):
        return self.paginated(f'/releases/{release["id"]}/assets')

    def upload(self, tag, path):
        self.command("release", "upload", tag, str(path), "--repo", self.repository)

    def download(self, tag, name, directory):
        self.command("release", "download", tag, "--repo", self.repository,
                     "--pattern", name, "--dir", str(directory))
        return Path(directory) / name

    def delete_incomplete(self, asset):
        self.api(f'/releases/assets/{asset["id"]}', "DELETE")

    def publish(self, release, prerelease):
        return self.api(f'/releases/{release["id"]}', "PATCH", {
            "draft": False, "prerelease": prerelease,
            "make_latest": "false" if prerelease else "legacy",
        })


def check_tag(github, tag, commit):
    if github.tag_commit(tag) != commit:
        raise ValueError("remote tag moved or differs from the tested commit")


def check_release(release, tag, prerelease):
    if not release or release.get("tag_name") != tag or release.get("prerelease") != prerelease:
        raise ValueError("release tag/prerelease metadata differs from the requested version")


def asset_index(assets, expected):
    result = {}
    for asset in assets:
        name = asset["name"]
        if name not in expected or name in result:
            raise ValueError(f"unexpected or duplicate remote asset: {name}")
        result[name] = asset
    return result


def fingerprint(assets):
    return sorted((item["id"], item["name"], item["size"], item["state"]) for item in assets)


def changelog_notes(tag, path=None):
    validate_version(tag)
    path = Path(path) if path is not None else Path(__file__).resolve().parents[1] / "CHANGELOG.md"
    base = re.match(r"v[0-9]+\.[0-9]+\.[0-9]+", tag)[0]
    sections = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            if current in sections:
                raise ValueError("duplicate changelog version")
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    notes = "\n".join(sections.get(tag, sections.get(base, []))).strip()
    if not notes:
        raise ValueError("release version needs a non-empty CHANGELOG.md entry")
    return notes


def release_notes(tag, commit, repository):
    changes = changelog_notes(tag)
    return f"""{changes}

""" + f"""Linux amd64 / arm64 静态二进制，包含配置示例、部署说明和依赖许可证。

构建提交：`{commit}`。两个架构均经过原生运行检查，amd64 发行包通过隔离 systemd 安装与重启测试。

下载对应架构的归档及 `checksums.txt`，先校验再解压：

```sh
sha256sum --ignore-missing -c checksums.txt
tar -xzf derper-go_{tag}_linux_amd64.tar.gz
cd derper-go_{tag}_linux_amd64
sudo ./derper-go init
```

验证 GitHub 构建来源：

```sh
gh attestation verify derper-go_{tag}_linux_amd64.tar.gz --repo {repository}
```

首次配置通常仅需域名、邮箱和 Cloudflare Token；默认沿用本机已登录的 tailscaled。已有部署的现网切换需另行安排。

"""


def publish_release(github, tag, commit, directory):
    prerelease = validate_version(tag)
    validate_commit(commit)
    files = write_checksums(directory, tag, commit)
    expected = {path.name: path for path in files}
    check_tag(github, tag, commit)
    release = github.find_release(tag)
    if release is None:
        release = github.create_draft(tag, commit, prerelease, release_notes(tag, commit, github.repository))
    check_release(release, tag, prerelease)
    existing = asset_index(github.assets(release), expected)
    with tempfile.TemporaryDirectory(prefix="derper-readback-") as readback:
        verified = []
        for name, path in expected.items():
            asset = existing.get(name)
            # A failed upload can leave a GitHub 'starter' placeholder. Only an
            # unpublished incomplete placeholder may be removed automatically.
            if asset and release["draft"] and asset["state"] == "starter":
                github.delete_incomplete(asset)
                asset = None
            if asset is None:
                if not release["draft"]:
                    raise ValueError("published release is missing an asset; refusing to alter it")
                github.upload(tag, path)
                current = asset_index(github.assets(release), expected)
                asset = current.get(name)
            if not asset or asset["state"] != "uploaded" or asset["size"] != path.stat().st_size:
                raise ValueError(f"remote upload is incomplete: {name}")
            downloaded = github.download(tag, name, readback)
            if sha256(downloaded) != sha256(path):
                raise ValueError(f"remote asset differs from the tested bytes: {name}")
            verified.append(asset)
        if fingerprint(github.assets(release)) != fingerprint(verified):
            raise ValueError("release assets changed during verification")
        check_tag(github, tag, commit)
        current = github.find_release(tag)
        check_release(current, tag, prerelease)
        if current["id"] != release["id"] or current["draft"] != release["draft"]:
            raise ValueError("release changed while uploads were being verified")
        if release["draft"]:
            current = github.publish(release, prerelease)
        check_release(current, tag, prerelease)
        if current["draft"] or fingerprint(github.assets(current)) != fingerprint(verified):
            raise ValueError("published release verification failed")
        check_tag(github, tag, commit)
    print(f"published and verified {tag}: {current.get('html_url', '')}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("commit")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    args = parser.parse_args()
    try:
        publish_release(GitHub(args.repo), args.tag, args.commit, args.directory)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            error = error.stderr.strip() or "GitHub command failed"
        parser.exit(1, f"release publication failed: {error}\n")


if __name__ == "__main__":
    main()
