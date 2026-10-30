#!/usr/bin/env bash
set -euo pipefail
umask 022
cd "$(dirname "$0")/.."
GO=${GO:-go}
VERSION=${VERSION:-dev}
COMMIT=${COMMIT:-$(git rev-parse HEAD)}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct "$COMMIT")}
DIST_DIR=${DIST_DIR:-dist}
read -r -a architectures <<< "${ARCHES:-amd64 arm64}"
python3 scripts/release_assets.py version "$VERSION" --allow-dev >/dev/null
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]
((${#architectures[@]} > 0))
for arch in "${architectures[@]}"; do
  case "$arch" in amd64|arm64) ;; *) printf 'unsupported architecture: %s\n' "$arch" >&2; exit 1;; esac
done
mkdir -p "$DIST_DIR"
output=$(cd "$DIST_DIR" && pwd)
work=$(mktemp -d "$output/.package.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/common/licenses"
cp LICENSE NOTICE README.md go.mod go.sum "$work/common/"
cp -R docs examples "$work/common/"
goroot=$("$GO" env GOROOT)
cp "$goroot/LICENSE" "$work/common/licenses/go-LICENSE"
if [[ -f "$goroot/PATENTS" ]]; then cp "$goroot/PATENTS" "$work/common/licenses/go-PATENTS"; fi
archives=()
for arch in "${architectures[@]}"; do
  name="derper-go_${VERSION}_linux_${arch}"
  directory="$work/$name"
  mkdir "$directory"
  cp -R "$work/common/." "$directory/"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOAMD64=v1 GOARM64=v8.0 "$GO" build -mod=readonly -trimpath -buildvcs=false \
    -ldflags "-s -w -X github.com/gatework/derper-go/internal/cli.Version=$VERSION -X github.com/gatework/derper-go/internal/cli.Commit=$COMMIT" \
    -o "$directory/derper-go" ./cmd/derper-go
  # Only dependencies imported by this binary are distributed. Collect their
  # licenses after building, so module directories have been downloaded.
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO" list -mod=readonly -deps \
    -f '{{with .Module}}{{.Path}} {{.Dir}}{{end}}' ./cmd/derper-go | sort -u > "$work/modules"
  while read -r module module_directory; do
    [[ -n "$module_directory" && "$module" != github.com/gatework/derper-go ]] || continue
    label=${module//\//_}
    found=false
    for license in LICENSE LICENSE.md LICENSE.txt LICENCE COPYING; do
      if [[ -f "$module_directory/$license" ]]; then
        cp "$module_directory/$license" "$directory/licenses/$label-$license"
        found=true
      fi
    done
    if [[ "$found" != true ]]; then
      printf 'dependency license is missing: %s\n' "$module" >&2
      exit 1
    fi
  done < "$work/modules"
  python3 - "$directory/build-info.json" "$VERSION" "$COMMIT" "$arch" "$("$GO" env GOVERSION)" "$SOURCE_DATE_EPOCH" <<'PY'
import json, sys
from pathlib import Path
path, version, commit, arch, go, epoch = sys.argv[1:]
Path(path).write_text(json.dumps({"version": version, "commit": commit, "os": "linux", "arch": arch,
                                 "go": go, "source_date_epoch": int(epoch)}, indent=2) + "\n", encoding="utf-8")
PY
  # Normalize permissions, order and timestamps; gzip -n omits the current time.
  chmod -R u=rwX,go=rX "$directory"
  tar --sort=name --format=gnu --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    -C "$work" -cf - "$name" | gzip -n > "$work/$name.tar.gz"
  python3 scripts/release_assets.py verify "$work/$name.tar.gz" "$VERSION" "$COMMIT" "$arch"
  mv "$work/$name.tar.gz" "$output/$name.tar.gz"
  archives+=("$name.tar.gz")
done
# Enumerate only this invocation's output, never a stale dist/*.tar.gz glob.
(cd "$output" && sha256sum "${archives[@]}") > "$work/checksums.txt"
mv "$work/checksums.txt" "$output/checksums.txt"
printf 'packages ready: %s\n' "$output"
