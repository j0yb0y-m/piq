# piq

A security-first AUR helper for Arch Linux. piq fetches a package, scans its
PKGBUILD and scriptlets, fetches and scans upstream sources, builds in a
bubblewrap sandbox, inspects the built package, asks for consent, and only
then installs it with pacman.

piq is deliberately small. It does not resolve AUR providers or conflicts, run
a full system upgrade, maintain a chroot, or provide a TUI. It is a review and
containment layer around the package manager you already have.

## Requirements

- Arch Linux (or an Arch-derived system) with `pacman`
- `bubblewrap` for sandboxed builds
- A non-root user: piq refuses to run `makepkg` as root
- Go 1.27 or newer to build from source
- Unprivileged user namespaces enabled (bubblewrap needs them)

If `bwrap` is missing, `install` fails instead of silently building without a
sandbox. Only an explicit `--no-sandbox` or `sandbox.enabled = false` permits
an unsandboxed build, and only when `bwrap` is unavailable; both options still
use bubblewrap when it is installed. The unsandboxed fallback has no
filesystem or network isolation.

## Install

From source:

```bash
git clone https://github.com/j0yb0y-m/piq.git
cd piq
make build
sudo install -Dm755 bin/piq /usr/bin/piq
```

With the bundled PKGBUILD (update `sha256sums` from the release's
`checksums.txt` first):

```bash
cd packaging
makepkg -si
```

Shell completion:

```bash
piq completion bash | sudo tee /usr/share/bash-completion/completions/piq >/dev/null
piq completion zsh  > ~/.zfunc/_piq
piq completion fish > ~/.config/fish/completions/piq.fish
```

## Quick start

```bash
# Inspect a package without installing it.
piq scan paru

# Fetch and scan upstream sources too.
piq scan --deep paru

# Scan, build in a sandbox, inspect, and install.
piq install paru

# Show the plan without building or installing (static scan only).
piq install --dry-run paru

# Audit installed foreign (AUR) packages.
piq audit

# Scan every foreign package's PKGBUILD and verify file integrity.
piq audit --deep --integrity

# Metadata, review status, and AUR search.
piq info paru
piq search "aur helper"

# Show the effective configuration and build metadata.
piq config
piq version
```

## What `install` does

1. **Fetch** the package's git repository from the AUR and record its history.
2. **Scan** the PKGBUILD, `.SRCINFO`, and every local `.install` scriptlet.
3. **Fetch sources** in two sandbox phases: download and verify with network
   access, then extract and run `prepare()`/`pkgver()` without network access.
   The AUR checkout stays read-only; `pkgver()` updates a staged PKGBUILD copy,
   and piq rejects any change outside strict `pkgver`/`pkgrel` assignments
   before scanning the prepared source tree. A package the static scan already
   blocks is not deep-fetched unless `install --force` is used, so its hooks do
   not run for a package that is already rejected.
4. **Resolve AUR dependencies** leaf-first (depth 10, cycle-safe) and scan each
   one the same way. Only missing official-repository dependencies are installed
   with `pacman -S --asdeps`; AUR names are never passed to `pacman -S`.
5. **Build** each package with `makepkg` inside bubblewrap from the scanned,
   prepared tree. The build phase has no network unless `--allow-net` is
   passed; `--allow-net` also grants network to source preparation.
6. **Inspect** every built artifact for setuid/setgid bits, world-writable
   files, system config paths, escaping symlinks and hardlinks, device nodes,
   and path traversal.
7. **Ask for consent.** A blocked package requires `--force` plus two
   confirmations. Suspicious artifacts require a confirmation unless `--yes`.
8. **Install** with `pacman -U`, then save the review record. A failed or
   aborted install never records a successful review.

`--yes` is not a blanket approval. It only skips the prompt for an unchanged
package whose saved review still matches the current PKGBUILD, `.SRCINFO`, and
scriptlets, and whose findings do not require confirmation.

## What piq does not do

- It does not run `-Syu`, upgrade the system, or manage repositories.
- It does not resolve virtual providers or package conflicts.
- It does not use a chroot; the sandbox is bubblewrap only.
- It does not intercept `yay`, `paru`, `pacman -U`, or direct `makepkg` use.
- It does not provide a pacman hook. Hooks run as root and cannot read
  per-user review records safely.
- It does not prove a package is safe. Static analysis is a filter, not a
  proof; see [the threat model](docs/threat-model.md).

## Review records

After a successful install, piq stores a review under
`<cache_dir>/reviews/<pkgbase>.json` with the HEAD commit, PKGBUILD,
`.SRCINFO`, and scriptlet fingerprints. The next install compares those
fingerprints and prompts again if anything changed.

Review records are local to the invoking user. They are not a system-wide
attestation database.

## Configuration

piq reads `~/.config/piq/piq.toml`. A missing file is fine; defaults apply.

```toml
severity  = "warning"   # info | warning | critical
threshold = 80          # 0-1000; 0 disables score-based blocking
cache_dir = ""          # empty -> ~/.cache/piq

[rules]
ignore = ["reputation"] # rule IDs, or "*" for everything

[sandbox]
enabled = true          # absent -> auto-detect bwrap

[pacman]
sudo_cmd = "sudo"       # fields are split: "doas", "sudo -A"
```

Environment overrides: `PIQ_SEVERITY`, `PIQ_THRESHOLD`, `PIQ_CACHE_DIR`,
`PIQ_SUDO_CMD`, `PIQ_RULES_IGNORE`.

See [docs/configuration.md](docs/configuration.md) for every key and its
validation rules. The old `network` and `hooks` sections were removed and are
ignored.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, including a deliberate abort |
| 1 | Runtime error (network, parse, build, pacman) |
| 2 | Usage error |
| 3 | Blocked by verdict or score (`scan`, `install`) |

## JSON output

Every report command (`scan`, `install`, `search`, `audit`, `info`, `config`,
`version`) emits one JSON object with `schema_version: 1` and a `command`
field. Progress and prompts go to stderr, so stdout stays pure JSON. ANSI color
is disabled for JSON, pipes, and `NO_COLOR`. `completion` emits a shell script,
not JSON.

```bash
piq scan --json paru | jq '.verdict, .score'
piq audit --json | jq '.packages[] | select(.review_status == "unreviewed") | .package'
```

See [docs/json-schema.md](docs/json-schema.md) and
[`schema/report-v1.json`](schema/report-v1.json).

## Rules

24 rules are registered. Six are gates: any gate finding forces a MALICIOUS
verdict and blocks installation regardless of the score.

| Rule | Severity | Gate | Catches |
|---|---|---|---|
| `pipe-to-shell` | CRITICAL | yes | Downloads content and pipes it into a shell |
| `data-exfiltration` | CRITICAL | yes | Pipes local files or secrets to the network |
| `destructive` | CRITICAL | yes | Destructive commands against system paths |
| `known-campaign` | CRITICAL | yes | Indicators from known AUR supply-chain campaigns |
| `reverse-shell` | CRITICAL | yes | Reverse shells, netcat/socat callbacks |
| `obfuscation` | CRITICAL | yes | Decode-and-execute payloads |
| `credential-theft` | CRITICAL | no | Reads SSH/GPG keys, cloud credentials, wallets, cookies |
| `privilege-escalation` | CRITICAL | no | `sudo`/`su`/`pkexec` from package functions |
| `suspicious-write-path` | CRITICAL | no | Writes to systemd, cron, sudoers, pacman hooks, shell rc files |
| `srcinfo-divergence` | CRITICAL | no | PKGBUILD differs from `.SRCINFO` |
| `missing-scriptlet` | CRITICAL | no | `install=` names a scriptlet that is not present |
| `insecure-source-url` | WARNING/CRITICAL | no | Plain HTTP sources; paste sites, shorteners, bare IPs |
| `checksum-completeness` | WARNING | no | Missing checksums, `SKIP` on non-VCS sources, weak hashes |
| `credential-reference` | WARNING | no | Reads credential-looking paths without clear exfiltration |
| `eval-usage` | WARNING | no | Dynamic `eval` |
| `obfuscation-hex` | WARNING | no | Hex payload patterns |
| `undeclared-fetch` | WARNING | no | Downloads in the build phase without a declared source |
| `maintainer-change` | WARNING | no | Recent committer handover |
| `maintainer-drift` | WARNING | no | Current maintainer authored little of the history |
| `scriptlet-no-functions` | WARNING | no | Non-empty `.install` without install-phase functions |
| `split-package-missing` | WARNING | no | Split package entry without its `package_*` function |
| `typosquat` | WARNING | no | Name close to a popular package |
| `reputation` | WARNING/INFO | no | Very new, low-trust package; out-of-date flag |
| `recent-commits` | INFO | no | Very recent commit on a small package |

## Verdicts and scoring

Findings contribute points per rule. A gate hit overrides the score.

| Verdict | Score | Meaning |
|---|---|---|
| TRUSTED | 0 | No findings |
| OK | 1-39 | Informational noise only |
| SKETCHY | 40-79 | Warnings worth reading |
| SUSPICIOUS | 80+ | Serious concerns |
| MALICIOUS | any gate hit | Unambiguous indicator of malice |

Installation is blocked when a gate fires or the score reaches `threshold`
(default 80). A blocked install needs `--force` and two separate confirmations.

## Development

```bash
make build             # bin/piq
make test              # go test ./...
make test-race         # go test -race ./...
make lint              # gofmt -l + go vet
make integration       # archlinux:latest under podman (privileged, non-root)
make release-snapshot  # goreleaser snapshot
```

See [docs/threat-model.md](docs/threat-model.md) before relying on piq as a
security boundary.

## License

[MIT](LICENSE)
