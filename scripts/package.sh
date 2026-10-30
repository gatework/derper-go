#!/bin/sh
set -eu
mkdir -p dist/licenses
go list -m -f '{{if .Dir}}{{.Path}} {{.Dir}}{{end}}' all |
while read -r module directory; do
  test -n "$directory" || continue
  label=$(printf '%s' "$module" | tr '/' '_')
  for name in LICENSE LICENSE.md LICENSE.txt LICENCE COPYING; do
    if test -f "$directory/$name"; then
      cp "$directory/$name" "dist/licenses/$label-$name"
    fi
  done
done
for arch in amd64 arm64; do
  target="dist/derper-go_linux_$arch"
  mkdir -p "$target"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X github.com/gatework/derper-go/internal/cli.Version=${VERSION:-dev} -X github.com/gatework/derper-go/internal/cli.Commit=${COMMIT:-unknown}" \
    -o "$target/derper-go" ./cmd/derper-go
  cp LICENSE NOTICE README.md "$target/"
  cp -R dist/licenses "$target/"
  tar -C "$target" -czf "$target.tar.gz" .
done
(cd dist && sha256sum derper-go_linux_*.tar.gz > checksums.txt)
