# JSON output contract

Every report command (`scan`, `install`, `search`, `audit`, `info`, `config`,
`version`) writes exactly one JSON object to stdout when `--json` is set, and
nothing else. Human progress, prompts, warnings, and errors go to stderr.
`completion` is the exception: it emits a shell script and does not produce a
report. ANSI color is disabled for JSON output, for pipes, and when `NO_COLOR`
is set.

The contract is versioned:

- `schema_version` is currently `1`.
- The machine-readable schema is
  [`schema/report-v1.json`](../schema/report-v1.json).
- A rename, removal, or change in the meaning of a field bumps
  `schema_version`. Consumers should reject an unknown version rather than
  guess.
- Timestamps are RFC 3339 strings in UTC.
- Optional fields are omitted when they are empty or not applicable; they are
  never emitted as `null` except for `config.sandbox_enabled`, where `null`
  means "auto-detect".

Exit codes are part of the contract: `0` success (including a deliberate
abort), `1` runtime error, `2` usage error, and `3` blocked by the risk
policy. A blocked `scan` still emits its JSON object before exiting 3. An
aborted `install --json` exits 0 with empty stdout because no package report
exists.

The `command` field identifies the object shape. `scan` and `install` share
the same `Scan` shape and differ only in `command`.

## `scan` and `install`

Examples in this document are illustrative, not live AUR data.

`piq scan --json <package>` and `piq install --json <package>` emit:

```json
{
  "schema_version": 1,
  "command": "scan",
  "package": "paru",
  "verdict": "OK",
  "block_reason": "",
  "score": 20,
  "blocked": false,
  "findings": [
    {
      "rule": "credential-reference",
      "severity": "WARNING",
      "file": "PKGBUILD",
      "line": 42,
      "message": "PKGBUILD references a credential-looking path."
    }
  ],
  "provenance": {
    "commit_count": 120,
    "maintainer": "maintainer@example.com",
    "head_committer": "maintainer@example.com",
    "head_committed_at": "2026-11-01T12:00:00Z"
  },
  "generated_at": "2026-11-11T09:30:00Z"
}
```

| Field | Type | Meaning |
|---|---|---|
| `package` | string | Package base that was scanned |
| `verdict` | string | `TRUSTED`, `OK`, `SKETCHY`, `SUSPICIOUS`, `MALICIOUS`, or `UNKNOWN` |
| `block_reason` | string | Why the package was blocked; empty when not blocked |
| `score` | integer | Cumulative risk score |
| `blocked` | boolean | Whether the risk policy blocked installation |
| `findings` | array | Findings, always present, possibly empty |
| `provenance` | object | Omitted when git history could not be inspected |
| `generated_at` | string | Report creation time |

Each finding has `rule`, `severity` (`INFO`, `WARNING`, or `CRITICAL`),
`file`, `line`, and `message`. `file` may be empty for package-level
findings, and `line` is `0` when no line applies.

## `search`

```json
{
  "schema_version": 1,
  "command": "search",
  "results": [
    {
      "name": "paru",
      "version": "2.0.4-1",
      "description": "Feature packed AUR helper",
      "votes": 2500
    }
  ]
}
```

`results` is always present and may be empty.

## `audit`

```json
{
  "schema_version": 1,
  "command": "audit",
  "packages": [
    {
      "package": "paru",
      "installed_version": "2.0.4-1",
      "aur_version": "2.0.5-1",
      "outdated": true,
      "review_status": "reviewed",
      "verdict": "OK",
      "score": 20,
      "blocked": false,
      "findings": [],
      "integrity": [],
      "error": ""
    }
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `packages` | array | One entry per installed foreign package; always present |
| `installed_version` | string | Installed version, or empty if unknown |
| `aur_version` | string | AUR version, or empty if the package is no longer in the AUR |
| `outdated` | boolean | Installed version is older according to `vercmp` |
| `review_status` | string | `reviewed`, `unreviewed`, or `changed` |
| `verdict` | string | Present only with `--deep`; scanner verdict |
| `score` | integer | Present only with `--deep` and a non-zero score |
| `blocked` | boolean | Present only with `--deep` and a true block |
| `findings` | array | Present only with `--deep` when findings exist |
| `integrity` | array | Present only with `--integrity` when findings exist |
| `error` | string | Per-package scan or integrity error |

`review_status` is `changed` when a stored review no longer matches the
current commit, PKGBUILD, `.SRCINFO`, or scriptlet fingerprints. Because of
JSON `omitempty`, a zero score or a false block is omitted rather than
emitted as `0` or `false`.

`audit` exits 0 even if `--deep` finds blocked packages. It reports risks; it
does not install or block anything.

## `info`

```json
{
  "schema_version": 1,
  "command": "info",
  "name": "paru",
  "version": "2.0.4-1",
  "votes": 2500,
  "popularity": 25.42,
  "maintainer": "maintainer@example.com",
  "submitted": "2021-01-01T00:00:00Z",
  "url": "https://github.com/Morganamilo/paru",
  "review_status": "unreviewed"
}
```

`submitted` is omitted when the AUR does not report a valid timestamp.
`reviewed_at` is added when a review record exists and has a review time.
`maintainer` is empty for an orphaned package, and `url` may be empty.
`review_status` is only `reviewed` or `unreviewed` here; `info` does not
re-fetch the package to detect changes.

## `config`

```json
{
  "schema_version": 1,
  "command": "config",
  "config_path": "/home/user/.config/piq/piq.toml",
  "cache_path": "/home/user/.cache/piq",
  "severity": "warning",
  "threshold": 80,
  "ignore": [],
  "sandbox_enabled": null,
  "sudo_cmd": "sudo"
}
```

`sandbox_enabled` is `true` or `false` when explicitly configured and `null`
when piq will auto-detect `bwrap`. `config_path` is the selected path, whether
or not the file exists.

## `version`

```json
{
  "schema_version": 1,
  "command": "version",
  "version": "0.1.0",
  "commit": "a91a95f",
  "date": "2026-11-11T09:00:00Z"
}
```

Release builds set these values through `-ldflags`; a development build reports
`dev`, `none`, and `unknown`.

## Consuming the output

```bash
# Print only the verdict and score.
piq scan --json paru | jq -r '"\(.verdict) \(.score)"'

# List only unreviewed installed packages.
piq audit --json | jq -r '.packages[] | select(.review_status == "unreviewed") | .package'

# Fail a script when a package is blocked.
piq scan --json paru > /tmp/paru.json
case $? in
  0) echo "not blocked" ;;
  3) jq -r '.block_reason' /tmp/paru.json ;;
  *) echo "scan failed" >&2 ;;
esac
```

Validate a report against the schema with any JSON Schema 2020-12 validator,
for example:

```bash
python -m jsonschema -i /tmp/paru.json schema/report-v1.json
```
