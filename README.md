# piq

A security-first AUR helper written in Go. Scans every package before it reaches your system, scores the risk, and blocks the worst offenders automatically.

## Why piq

The AUR is the single biggest attack surface on an Arch Linux system. Real supply-chain attacks have shipped through it:

- **CHAOS RAT** (2025): a hidden install hook exfiltrated SSH keys and crypto wallets to an attacker's C2 server.
- **Atomic Arch campaign** (June 2026): dozens of empty packages with `npm install atomic-lockfile` / `bun install js-digest` as a trusted-looking download chain.
- **xsnow worm** (June 2026): a malicious `.install` scriptlet injected persistence via systemd and cron.
- **xz-utils backdoor** (2024): a multi-year social-engineering attack that compromised a critical system library.

Standard AUR helpers (yay, paru) install whatever you ask for. piq sits between you and the AUR, scans everything, and tells you what's safe.

## Features

- **15 security rules** covering reverse shells, credential theft, data exfiltration, obfuscation, persistence, destructive commands, known campaigns, and more.
- **Scoring and verdicts** — every scan produces a risk score (0-100+) and a verdict: TRUSTED, OK, SKETCHY, SUSPICIOUS, or MALICIOUS.
- **Gate hits** — unambiguous indicators of malice (pipe-to-shell, known IOCs, reverse shells, destructive commands) force a MALICIOUS verdict and block installation.
- **`.install` scriptlet scanning** — companion scriptlets are scanned alongside the PKGBUILD, including phase-function validation.
- **Git provenance** — detects maintainer changes, author drift, and recent commits that signal a takeover.
- **Update-diff** — on reinstall, shows exactly what changed since your last review and flags newly-introduced dangers.
- **Configurable via TOML** — `~/.config/piq/piq.toml` with environment variable overrides.
- **JSON output** for scripting and CI integration.
- **`piq system`** audits all installed AUR packages in one pass.
- **Bubblewrap sandbox** — builds run in an isolated namespace with no network (except source fetch) and no write access outside the build dirs.

## Install

```bash
git clone https://github.com/j0yb0y-m/piq.git
cd piq
go build -o piq ./cmd/piq
sudo cp piq /usr/local/bin/
```

## Usage

```bash
# Scan a package
piq scan <package>

# Scan with JSON output
piq scan --json <package>

# Install a package (scan, review, build, install)
piq install <package>

# Audit all installed AUR packages
piq system

# Install yay/paru hooks
piq hooks

# Search the AUR
piq search <term>
```

## How it works

1. **Fetch** — clones the package's git repo from the AUR.
2. **Parse** — reads the PKGBUILD, `.SRCINFO`, and any `.install` scriptlets.
3. **Scan** — runs 15 security rules against the AST and metadata, including the scriptlets.
4. **Score** — aggregates risk points per rule, applies gate checks, and produces a verdict.
5. **Provenance** — inspects git history for maintainer changes and author drift.
6. **Report** — displays findings by severity with rule IDs and line numbers.
7. **Build** — fetches sources in a sandboxed network namespace, then builds without network.
8. **Inspect** — checks the built package for suspicious entries (setuid, setgid, world-writable).
9. **Install** — installs via `pacman -U` with a configurable sudo command.

## Configuration

Create `~/.config/piq/piq.toml`:

```toml
severity = "warning"    # minimum severity to show: info, warning, critical
threshold = 80          # minimum risk score to block on
cache_dir = "/home/user/.cache/piq"

[network]
no_scan = false         # skip AUR reputation scan

[rules]
ignore = ["typosquat"]  # silence specific rules by ID

[sandbox]
enabled = true          # false to disable bubblewrap (not recommended)

[pacman]
sudo_cmd = "sudo"       # or "doas", "sudo -A", etc.
```

Environment variable overrides (take precedence over the TOML file):

| Variable | Description |
|---|---|
| `PIQ_SEVERITY` | Minimum severity to show |
| `PIQ_THRESHOLD` | Risk score threshold |
| `PIQ_CACHE_DIR` | Package cache directory |
| `PIQ_NETWORK_NO_SCAN` | Skip AUR metadata scan |
| `PIQ_SUDO_CMD` | Sudo command for pacman |
| `PIQ_RULES_IGNORE` | Comma-separated rule IDs to ignore |

## Rules

| Rule | Severity | Gate | Description |
|---|---|---|---|
| `pipe-to-shell` | CRITICAL | yes | Downloads content and pipes directly into a shell |
| `known-campaign` | CRITICAL | yes | References a known AUR supply-chain campaign |
| `reverse-shell` | CRITICAL | yes | Opens a reverse shell or calls netcat/socat |
| `destructive` | CRITICAL | yes | Runs rm/mkfs/dd against system directories |
| `credential-theft` | CRITICAL | yes | Reads SSH keys, cloud credentials, wallets, cookies |
| `data-exfiltration` | CRITICAL | yes | Pipes local files to curl/wget/nc |
| `privilege-escalation` | CRITICAL | no | Calls sudo/su/pkexec from a PKGBUILD function |
| `suspicious-write-path` | CRITICAL | no | Writes to systemd units, cron, shell rc files |
| `obfuscation` | CRITICAL | no | Base64/hex decode into shell, xxd patterns |
| `skipped-checksum` | WARNING | no | SHA256 set to SKIP on non-VCS source |
| `insecure-source-url` | WARNING | no | Source over HTTP or pointing at paste sites |
| `srcinfo-divergence` | CRITICAL | no | PKGBUILD source differs from .SRCINFO |
| `eval-usage` | WARNING | no | Uses eval on a dynamic string |
| `typosquat` | WARNING | no | Name is close to a popular package |
| `reputation` | WARNING | no | Brand-new package with no votes |
| `checksum-completeness` | WARNING | no | No checksum or only weak algorithm (MD5/SHA1) |
| `maintainer-change` | WARNING | no | Git history shows different committers |
| `maintainer-drift` | WARNING | no | Current maintainer authored few commits |
| `recent-commits` | INFO | no | Very recent commit on a small package |
| `split-package-missing` | WARNING | no | Split pkgname entry missing its package function |

## Risk scoring

Each firing rule contributes points toward a cumulative risk score. Gates override the score entirely.

| Verdict | Score range | Meaning |
|---|---|---|
| TRUSTED | 0 | No findings, checksums present |
| OK | 1-39 | Only INFO-level noise |
| SKETCHY | 40-79 | One or more warnings |
| SUSPICIOUS | 80-99 | Serious concerns |
| MALICIOUS | 100+ or gate hit | Unambiguous indicator of malice |

## License
[MIT](LICENSE)
