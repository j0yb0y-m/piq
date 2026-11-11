SHELL := /bin/bash

BINARY  := bin/piq
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: all build test test-race lint integration release-snapshot clean

all: lint test build

build:
	@mkdir -p $(dir $(BINARY))
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/piq

test:
	go test ./...

test-race:
	go test -race ./...

lint:
	@files="$$(gofmt -l .)"; if [ -n "$$files" ]; then echo "gofmt needed on:"; echo "$$files"; exit 1; fi
	go vet ./...

integration:
	./scripts/integration.sh

release-snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin dist
