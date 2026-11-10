# piq v2 — design

**Date:** 2026-11-10
**Status:** approved by the user (approach B)
**Repo:** `github.com/j0yb0y-m/piq`

## Context

piq is a security-first AUR helper. It clones a package, scans its PKGBUILD
and `.install` scriptlets with a rule engine, scores the result, and has an
install path that is currently non-functional. The code builds and its tests
pass, but the scanner produces gate-level false positives on mainstream
packages, `--json` is a no-op, colors render as literal hex, the alpm hooks
are invalid, and the bubblewrap build runs `makepkg` in the wrong directory.
Six packages have 0% test coverage, including every path that touches the
network, the build, or pacman.

## Intent

Make piq the tool a real Arch user reaches for when a package only exists in
the AUR: it shows what is about to run, refuses to build it unsandboxed,
inspects what came out, and only then installs. The scanner stops crying wolf;
the installer stops being aspirational.

## Goals

1. Zero gate hits across a corpus of mainstream AUR packages (`paru`, `yay`,
   `google-chrome`, `visual-studio-code-bin`), while unambiguous malicious
   fixtures still gate.
2. `piq install <pkg>` works end to end on Arch: clone, audit, fetch, scan
   extracted sources, sandboxed build, inspect artifact, confirm, `pacman -U`.
3. Everything executed is checksummed, signed, or scanned — including patches
   and local sources, not only the PKGBUILD.
4. Scriptable: versioned JSON on stdout, logs on stderr, exit codes 0/1/2/3.
5. Every package has tests; CI runs unit, race, and a containerized Arch
   integration job; tagged releases via goreleaser.

## Non-goals

- Full dependency solver with providers and conflicts, `-Syu`, `--devel`,
  chroot builds, TUI, or installing official-repo packages.
- A malware sandbox. The sandbox is containment, not a security boundary.
- Protecting against a kernel exploit, a compromised AUR account with a
  valid review, or a malicious upstream tarball that passes static checks.

## Anti-goals

- Auto-installing at SKETCHY or above.
- Gating on words such as `token` or `secret`.
- Claiming sandboxing makes untrusted builds safe.
- Letting `--yes` override a changed PKGBUILD.
- Silently falling back to an unsandboxed build.

## Constraints

- Linux/Arch only. Go 1.27.0. Module `github.com/j0yb0y-m/piq`.
- New dependency: Lip Gloss v1 (not the v2 beta). Existing deps stay unless a
  task removes one.
- `makepkg` refuses root; piq must run as the user and elevate only pacman.
- bwrap requires unprivileged user namespaces. `linux-hardened` users may need
  to enable them; piq surfaces this as an error, never as a silent fallback.
- No commit or push without explicit user approval.

## Approaches considered

- **A — harden in place.** Fix correctness, wire config, theme, tests, CI.
  Leaves piq a scanner with no install path.
- **B — scanner plus safe installer.** Everything in A, then a real fetch →
  scan → sandboxed build → inspect → install pipeline. Chosen.
- **C — full AUR-helper parity.** Solver, updates, split packages, chroot,
  TUI. Months of work, competes with paru on paru's terms.

## Architecture

| Package | Responsibility |
|---------|----------------|
| `cmd/piq` | Flag parsing, rendering, exit codes. No business logic. |
| `internal/ui` | Writers, color detection, styles. The only place that prints. |
| `internal/config` | Load, validate, defaults, env overrides. |
| `internal/aur` | RPC v5 client (UA, retries, batching) and git fetch. |
| `internal/pkgbuild` | PKGBUILD shell parsing and `.SRCINFO` loading. |
| `internal/scanner` | Rules, scoring, source-tree scanning, diffs. |
| `internal/history` | Git provenance: committers, recency, bounded walk. |
| `internal/build` | bwrap argument construction, fetch/build phases, artifacts. |
| `internal/inspect` | Read `.pkg.tar.zst` metadata without extracting. |
| `internal/alpm` | pacman/vercmp queries and privilege elevation. |
| `internal/review` | Per-package approval records with content fingerprints. |
| `internal/pipeline` | Scan/install orchestration, dependency closure, consent. |
| `internal/report` | Versioned JSON output types and encoding. |

Data flow for `install`:

```
AUR RPC info -> clone -> scan repo -> fetch+extract -> scan sources
   -> re-score -> deps -> confirm -> sandboxed build -> inspect
   -> confirm -> pacman -U -> write review record
```

## Trust model

- The PKGBUILD, `.SRCINFO`, scriptlets, patches, and local sources are
  untrusted input. They are parsed and scanned, never sourced by piq.
- `makepkg` runs inside bwrap with a read-only system, writable build dirs,
  and no network unless `--allow-net` is passed.
- Repository dependencies are installed on the host because `/var` is a
  tmpfs inside the sandbox; `makepkg` itself runs with `--nodeps`.
- The built artifact is inspected as a tar stream before `pacman -U`.
- The review record records commit, PKGBUILD, `.SRCINFO`, and scriptlet
  hashes. A changed package always re-prompts.

### Residual risks (documented, not hidden)

- `prepare()` may execute inside the sandbox before extracted sources are
  scanned. It cannot modify the host, but it can influence the build.
- Build-time network fetches are caught by heuristics, not blocked by
  construction unless the user keeps network disabled.
- Static scanning of an entire upstream tarball is noisy; deep scanning is
  opt-in and capped.
- bwrap is not a security boundary against kernel bugs or resource exhaustion.
- AUR account takeover with a plausible package still requires human review.

## CLI surface

```
piq scan <pkg> [--json] [--deep]
piq install <pkg> [--yes] [--dry-run] [--allow-net] [--no-sandbox] [--force] [--json]
piq info <pkg> [--json]
piq search <term> [--json] [--limit N]
piq audit [--deep] [--integrity] [--json]
piq config [--json]
piq version [--json]
piq completion <bash|zsh|fish>
```

`system` and `hooks` are removed. See "Spec corrections".

Exit codes: 0 success (including deliberate abort), 1 runtime error,
2 usage error, 3 blocked by verdict or score.

## Config

`~/.config/piq/piq.toml`:

```toml
severity   = "warning"   # info|warning|critical: minimum finding that prompts
threshold  = 80          # score at or above which install hard-blocks
cache_dir  = ""          # empty -> ~/.cache/piq

[rules]
ignore = ["reputation"]

[sandbox]
enabled = true           # nil/absent -> auto-detect bwrap

[pacman]
sudo_cmd = "sudo"        # fields are split; "doas" and "sudo -A" both work
```

`network` and `hooks` sections are removed: there is no separate reputation
scan to disable, and the hook design was unsound.

## JSON contract

`internal/report` emits one object per invocation with
`schema_version: 1`, a `command` field, and command-specific payload. ANSI is
never emitted in JSON mode. `schema/report-v1.json` documents the fields;
tests pin the version and required keys.

## Verification

- Unit tests per package, no network; `httptest` for AUR, temp git repos for
  history, temp tar.zst files for inspect, stubbed executables for pacman.
- `go test -race ./...`, `go vet ./...`, `gofmt -l .` empty.
- Container integration: `archlinux:latest` with `--privileged`, a non-root
  user, and real `makepkg`/`bwrap`; builds a fixture package and asserts the
  artifact and inspection findings.
- Release: GitHub Actions on push and tag, goreleaser snapshot on PRs.

## Spec corrections

1. **Hooks removed.** The approved design kept `piq hooks` as a backstop.
   pacman hooks execute as root, while review records live in the invoking
   user's cache; a root-side guard cannot read them without a system-wide
   attestation database and an extra privileged write path. That is a
   separate subsystem with its own threat model. v2 removes the command and
   documents that piq cannot intercept yay/paru safely.
2. **No chroot.** bwrap only, stated as containment. A chroot would require
   root and a second package manager workflow.
3. **AUR dependencies** are resolved as a linear closure (depth 10, cycle
   detection), installed leaf-first through the same sandboxed path. No
   provider or conflict resolution.

## Decisions delegated to the builder

- Exact Lip Gloss style values come from the existing Catppuccin palette.
- Exact wording of messages, subject to the output rules: sentence case, no
  emoji, one line per finding.
- File layout inside `internal/scanner` may split further if a file grows
  past roughly 250 lines.
