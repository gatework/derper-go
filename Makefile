GO ?= go
VERSION ?= dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS = -s -w -X github.com/gatework/derper-go/internal/cli.Version=$(VERSION) -X github.com/gatework/derper-go/internal/cli.Commit=$(COMMIT)

.PHONY: build test race vet package
build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/derper-go ./cmd/derper-go
test:
	$(GO) test ./...
race:
	$(GO) test -race -timeout 5m ./...
vet:
	$(GO) vet ./...
package:
	VERSION=$(VERSION) COMMIT=$(COMMIT) sh scripts/package.sh
