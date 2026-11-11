# Threat model

piq reduces the risk of installing software from the AUR. It does not make
the AUR safe, and it does not replace reading a PKGBUILD before you trust it.

This document describes what piq protects, what it assumes, and where the
remaining risk sits.

## Assets

An AUR package can reach any of these through a PKGBUILD, a `.install`
scriptlet, an upstream source tree, or the built package:

- Your user account: shell configuration, SSH and GPG keys, cloud
  credentials, browser data, wallets, and any file your user can read.
- Your system: files owned by root during `pacman -U`, systemd units, cron
  jobs, pacman hooks, sudoers rules, and shared libraries.
- Your build environment: the build directory, source cache, package cache,
  and any secrets present in the environment.
- Your trust decisions: a previous review record can make a later, changed
  package look familiar if fingerprints are not checked.

## Adversaries

piq assumes all of the following are possible:

- A malicious or compromised AUR maintainer publishes a package that looks
  useful but contains a payload.
- An attacker takes over an AUR account and pushes a plausible update to an
  existing package.
- A legitimate upstream source is compromised, or a source URL is changed to
  an attacker-controlled host.
- A network attacker interferes with plain HTTP downloads or serves a
  different artifact than the maintainer intended.
- Malware hides in a `.install` scriptlet, a split-package function, an
  obfuscated string, or a post-build artifact rather than the PKGBUILD body.
- A build script fetches additional code at build time, after the static scan
  has already happened.

## Trust boundaries

### AUR metadata and git history

The AUR RPC API and the package's git repository are untrusted input. piq
uses them for package names, versions, dependency names, and provenance
signals. A compromised or inconsistent response can mislead the scanner, but
cannot by itself change a local build outside the pipeline described below.

### PKGBUILD and scriptlets

`piq scan` parses the PKGBUILD and local `.install` scriptlets and runs 24
static rules. Six rules are gates: a hit forces a MALICIOUS verdict. The
other rules contribute risk points. Static analysis is a heuristic filter,
not a proof; see [Residual risks](#residual-risks).

### Source tree

With `--deep`, piq fetches sources in the sandbox, extracts them, and scans
the resulting tree. The source tree is untrusted content. The scan is
best-effort and capped; a clean scan does not mean the upstream project is
trustworthy.

### Build sandbox

`piq install` runs `makepkg` inside bubblewrap unless the user explicitly
opts out. The sandbox:

- unshares all namespaces, including the network namespace;
- makes `/usr` and `/etc` read-only;
- mounts `/proc`, `/dev`, `/tmp`, and `/var` with sandbox-local state;
- keeps the package checkout read-only and writes only to a staged PKGBUILD
  copy, the source cache, the build tree, the package destination, and the log
  destination;
- runs from the package directory with `HOME` and makepkg destinations
  redirected into the cache;
- allows network access during source download, and denies it during source
  extraction/preparation and the build unless `--allow-net` is passed.

Checksums and PGP signatures are verified once, in the network-enabled download
phase. The offline extraction phase reuses that verified cache and skips a
second integrity pass. A PKGBUILD `verify()` hook runs only in the networked
phase.

`makepkg` is never run as root. The unsandboxed path is reachable only through
an explicit `--no-sandbox` or an explicit `sandbox.enabled = false`; a missing
`bwrap` with the default setting is an error.

The sandbox contains the build process, not the installed package. Once
`pacman -U` runs, files in the package are placed on the real system with
root privileges. Artifact inspection happens before that step.

### Artifact inspection

Before installation, piq opens every built package and flags setuid/setgid
files, world-writable files, system configuration paths, escaping symlinks and
hardlinks, device nodes, and path traversal. Suspicious entries require consent
unless `--yes` was passed; a blocked package requires `--force` and two separate
confirmations.

### Review records

A successful install writes a review record under
`<cache_dir>/reviews/<pkgbase>.json`. It records the HEAD commit, PKGBUILD,
`.SRCINFO`, and scriptlet fingerprints, plus the verdict and review time.
Later installs compare the fingerprints and prompt again when the package
changed.

Review records are per-user data. They are not system-wide attestations, and
piq deliberately does not install a pacman hook: hooks run as root and cannot
safely read or trust a user's review state.

## What piq guarantees

- A package with a gate finding is blocked unless the user forces the
  install and confirms twice.
- A package at or above the configured score threshold is blocked under the
  same rules.
- A missing bubblewrap binary does not silently produce an unsandboxed build
  when sandboxing was not explicitly disabled.
- Source preparation and builds run without network access by default.
- The reviewed AUR checkout is read-only inside the sandbox. `pkgver()` may
  update a staged PKGBUILD copy, and piq accepts only strict `pkgver`/`pkgrel`
  assignments there; any other change aborts the install.
- A failed or aborted install does not write a successful review record.
- JSON output is pure JSON on stdout; progress and prompts go to stderr.

These are process guarantees, not statements that an installed package is
safe.

## Residual risks

These risks are accepted and documented rather than hidden:

- **`prepare()` runs before the source-tree scan.** It executes in the
  no-network fetch sandbox after the PKGBUILD scan, and the source tree it
  produces is the tree that is scanned and built. It cannot modify the
  reviewed checkout, but a pathological `prepare()` can still influence what
  the subsequent build sees.
- **The unsandboxed fallback has no isolation.** When `--no-sandbox` or
  `sandbox.enabled = false` authorizes it because bubblewrap is missing,
  `prepare()`, `build()`, and `package()` run with the user's filesystem and
  network access. Network denial applies only to sandboxed runs.
- **Build-time network fetches are heuristic, not impossible.** The build
  phase has no network by default. If you pass `--allow-net`, or if a
  malicious build finds another channel, static rules may miss the fetch.
- **Deep source scanning is noisy and incomplete.** Static scanning of an
  entire upstream tarball produces false positives and misses
  context-dependent behavior. It is opt-in and capped.
- **bubblewrap is not a defense against kernel bugs.** Namespace escapes,
  kernel vulnerabilities, and resource exhaustion are outside piq's control.
- **A plausible takeover still needs human judgment.** A maintainer change
  with a clean diff, valid checksums, and ordinary-looking build steps can
  pass every automated check. Review the diff yourself.
- **AUR metadata is not authenticated by piq.** Package popularity, votes,
  and maintainer history are signals, not proof of trust.
- **Installed package contents can change after installation.** piq inspects
  the artifact it installs; later modifications are outside its scope.
- **The user's own configuration can weaken protection.** Ignoring a gate
  rule removes its finding and its gate, setting `threshold = 0` disables
  score-based blocking, and disabling the sandbox removes containment. See
  [configuration](configuration.md).

## What you must still review manually

piq is a filter. Before installing an unfamiliar AUR package, you should
still:

1. Read the PKGBUILD and any `.install` scriptlet, especially `prepare()`,
   `build()`, `package()`, and any command that fetches or executes code.
2. Check whether sources use HTTPS and whether checksums are present and
   meaningful. `SKIP` is acceptable only for moving VCS sources.
3. Look at the maintainer and recent commit history if the package is new to
   you.
4. Read the findings rather than only the verdict. Warnings can matter even
   when the score stays below the block threshold.
5. Treat `--force`, `--no-sandbox`, `--allow-net`, ignored rules, and a
   lowered threshold as deliberate trust decisions.
6. Keep backups and credentials out of reach of your user account. The best
   sandbox cannot protect a secret that the build did not need but could
   read.
