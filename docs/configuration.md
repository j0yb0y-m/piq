# Configuration

piq works with zero configuration. It reads one TOML file and then applies a
small set of environment overrides.

## Location and precedence

The default file is:

```
$XDG_CONFIG_HOME/piq/piq.toml
```

`XDG_CONFIG_HOME` normally defaults to `~/.config`, so the usual path is
`~/.config/piq/piq.toml`. A missing file is not an error.

`--config PATH` overrides the path for that invocation. Environment variables
override values from the file. Command-line flags such as `--yes` and
`--force` are separate from this configuration and are not persisted.

Show the effective result with:

```bash
piq config
piq config --json
```

Unknown TOML keys are ignored. The removed `network` and `hooks` sections are
therefore harmless, but they do nothing.

## Keys

### `severity`

- Type: string
- Default: `"warning"`
- Values: `info`, `warning`, `critical` (case-insensitive; normalized to
  lower case)

The minimum finding severity that requires an install confirmation. It does
not affect the verdict, the score, or gate findings. Gate findings always
require the blocked-install path.

### `threshold`

- Type: integer
- Default: `80`
- Range: `0`–`1000`

The cumulative risk score at or above which a package is blocked. `0` disables
score-based blocking, but it does **not** disable gate rules: any gate hit
still produces a MALICIOUS verdict and blocks installation.

### `cache_dir`

- Type: string
- Default: `""`, which resolves to `~/.cache/piq`
- Validation: when set, the path must be absolute

The cache holds cloned PKGBUILDs, fetched sources, build trees, logs, built
packages, and this user's review records. Review records live under
`<cache_dir>/reviews/`.

### `rules.ignore`

- Type: array of strings
- Default: `[]`

Rule IDs to suppress. Suppression removes the rule's findings, its points, and
its gate. An unknown ID is accepted and has no effect. The special value `"*"`
suppresses every rule.

Ignoring a gate rule weakens the security model. The gate IDs are:

- `pipe-to-shell`
- `data-exfiltration`
- `destructive`
- `known-campaign`
- `reverse-shell`
- `obfuscation`

### `sandbox.enabled`

- Type: boolean, or absent
- Default: absent (auto-detect)

When absent, piq sandboxes builds if `bwrap` is available and fails loudly if
it is not. When `false`, an unsandboxed build is *authorized* if `bwrap` is
missing; if `bwrap` is installed, piq still uses it. When `true`, a build
requires bubblewrap and fails if it cannot be found.

`--no-sandbox` has the same authorization semantics for one invocation: it
permits a missing-bubblewrap fallback, but does not force piq to stop using an
available sandbox. The fallback has no isolation: `prepare()`, `build()`, and
`package()` run with the user's filesystem and network access.

### `pacman.sudo_cmd`

- Type: string
- Default: `"sudo"`
- Validation: must contain at least one non-space field

The command used to elevate `pacman -S` and `pacman -U`. It is split on
whitespace, not through a shell. These work:

```toml
[pacman]
sudo_cmd = "sudo"
```

```toml
[pacman]
sudo_cmd = "doas"
```

```toml
[pacman]
sudo_cmd = "sudo -A"
```

Shell syntax, quoting, pipes, and aliases are not interpreted. If your
elevation tool needs a wrapper with arguments, create a wrapper executable and
point `sudo_cmd` at it.

## Environment variables

| Variable | Overrides | Notes |
|---|---|---|
| `PIQ_SEVERITY` | `severity` | Same validation as the file |
| `PIQ_THRESHOLD` | `threshold` | Invalid integers are ignored |
| `PIQ_CACHE_DIR` | `cache_dir` | Must be absolute |
| `PIQ_SUDO_CMD` | `pacman.sudo_cmd` | Split on whitespace |
| `PIQ_RULES_IGNORE` | extends `rules.ignore` | Comma-separated IDs; **appends** to the file list |

`PIQ_RULES_IGNORE` cannot remove an ignore from the file. To narrow the list,
edit the file or point `--config` at a different file.

## Complete example

```toml
# Block at the default 80-point threshold.
severity  = "warning"
threshold = 80

# Empty means ~/.cache/piq.
cache_dir = ""

[rules]
# Remove only if you accept the loss of these checks.
ignore = ["reputation", "recent-commits"]

[sandbox]
# Omit this key to auto-detect bubblewrap.
enabled = true

[pacman]
sudo_cmd = "sudo"
```

## Security implications

- `threshold = 0` disables only score-based blocking. Gate rules still block.
- `rules.ignore = ["*"]` disables every rule, including gates. A clean scan
  then means only that piq did not look.
- `sandbox.enabled = false` does not make builds unsandboxed when `bwrap` is
  present. It only authorizes a fallback when `bwrap` is unavailable, and that
  fallback has no filesystem or network isolation.
- `--allow-net` grants network access to source preparation and the build
  phase. Prefer leaving it off.
- Builds never run as root. Running piq itself under `sudo` is unsupported.
- Review records are per-user. Do not copy them between users and treat them
  as an approval for someone else's account.

See [the threat model](threat-model.md) for the guarantees and the remaining
risk.
