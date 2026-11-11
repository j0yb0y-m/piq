#!/usr/bin/env bash
# Run the bubblewrap integration test in a disposable Arch Linux container.
# The repository is mounted read-only in spirit; only the Go caches are
# chowned, and the test runs as a non-root user because makepkg refuses root.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if ! command -v podman >/dev/null 2>&1; then
  echo "podman is required for the integration test" >&2
  exit 1
fi

exec podman run --rm --privileged \
  -v "$repo:/src:Z" \
  -w /src \
  archlinux:latest \
  bash -euo pipefail -c '
    pacman -Syu --noconfirm --needed base-devel git go bubblewrap

    if ! id tester >/dev/null 2>&1; then
      useradd -m -s /bin/bash tester
    fi
    mkdir -p /tmp/gocache /tmp/gomodcache
    chown tester:tester /tmp/gocache /tmp/gomodcache

    su tester -c "cd /src && GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomodcache PIQ_INTEGRATION=1 go test -tags integration ./..."
  '
