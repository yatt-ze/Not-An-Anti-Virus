# NAV — Not an Anti-Virus

[![CI](https://github.com/yatt-ze/Not-An-Anti-Virus/actions/workflows/ci.yml/badge.svg)](https://github.com/yatt-ze/Not-An-Anti-Virus/actions/workflows/ci.yml) ![Status: early development](https://img.shields.io/badge/status-early%20development-orange) ![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**A heuristic static scanner for macOS that tells you *why* a file looks suspicious**

NAV inspects Mach-O binaries, `.app` bundles, scripts, installer packages,
launchd property lists, etc. It scores them on how they are built and what they do,
not on virus signatures, and prints every signal that went into the score.
It never blocks, deletes or quarantines anything.


```console
$ navctl rules test crates/nav-core/fixtures/suspicious/packed_payload.sh
Threat score:        34
Evidence confidence: Medium
Scan completeness:   Partial

Signals matched:
  [ +15] high-entropy-content         binary data embedded in a script/text file (entropy: 7.9 bits/byte over 4369 bytes)
  [ +19] suspicious-strings           matched 3 indicator(s): decoded payload piped to a shell; references osascript (AppleScript/JXA interpreter); curl/download-pipe-to-shell pattern

Recommendation: notify
```

Every result has three separate parts:

- **Threat score**: how suspicious the file looks.
- **Evidence confidence**: how much evidence that score rests on.
- **Scan completeness**: whether every check could run. A file NAV couldn't
  fully check is never reported as clean.

## Philosophy

NAV treats you like an adult. It doesn't assume that unfamiliar, unsigned or
unusual software is malicious, and it doesn't make a decision for you.

NAV is a second set of eyes for technical users: it explains what triggered concern
and leaves the decision with the you.

- **It doesn't act on scan results.** NAV reports what it finds; it doesn't
  block, delete or quarantine the file being inspected.
- **It shows its working.** There are no black-box verdicts. Every score comes
  with the signals behind it, so you can judge the evidence for yourself.
- **It doesn't run the software it inspects.** NAV may invoke macOS
  verification utilities to assess signing and notarization.
- **It's upfront about its limits.** When NAV couldn't check something, it
  says so instead of calling the file clean.

**NAV is not protection.** It won't stop anything from running. It gives you
more information about a file before you decide what to do with it. Keep
macOS's built-in defences turned on.

## Status

NAV is in **early development** (v0.3.0).

- [x] `navctl scan`: a verdict for a file, a folder or a `.app` bundle
- [x] `navctl rules test`: the full signal-by-signal breakdown, as text or JSON
- [x] `navctl rules list`: the active ruleset

Scanning runs entirely as your own user: no background service, no root, no
special macOS permissions.

In progress: `navd`, a privileged background service. `navctl service
install | uninstall | status` can install it as a LaunchDaemon, but today it
only stays alive so its install and permission behaviour can be tested. It does not scan or monitor anything yet.

Planned, not built yet:

- [ ] Automatic scanning of newly downloaded files
- [ ] Persistence watching (new LaunchAgents / LaunchDaemons)
- [ ] Network monitoring
- [ ] Notification Center alerts
- [ ] Opt-in quarantine

`navctl` already lists the subcommands for these, but they tell you plainly
that they're unavailable rather than pretending to work.

## Install

Requires Rust 1.75 or newer. macOS is the target platform. NAV also builds
and runs on Linux, but the macOS-only checks (code signing, notarization, the
quarantine attribute) are skipped there, so results are marked `Partial`.

```sh
git clone https://github.com/yatt-ze/Not-An-Anti-Virus.git
cd Not-An-Anti-Virus
cargo install --locked --path crates/navctl
```

This puts `navctl` in `~/.cargo/bin`. Homebrew and signed release binaries
are planned.

## Usage

Use `navctl scan` for a quick verdict. Use `navctl rules test` when you want
the signal-by-signal evidence behind that verdict.

```sh
# Quick verdict for a file
navctl scan ./some-binary

# Scan a folder
navctl scan ./some-dir --recursive

# Scan a .app: one verdict line for the whole bundle (--verbose lists every file)
navctl scan ./Some.app

# Full breakdown of which signals fired, and why
navctl rules test ./suspicious.app

# The same breakdown as versioned JSON, for scripts
navctl rules test ./suspicious.app --json

# Show the active ruleset
navctl rules list
```

A `.app` bundle is scanned as one unit. NAV finds its main executable, skips
compiled resources (nibs, asset catalogs), and gives the bundle the verdict of
the worst file inside it.

### Recommendations

| Recommendation | When |
| --- | --- |
| `no action` | Score below 15 |
| `notify` | Score 15 or more |
| `notify + suggest quarantine` | Score 45 or more, with signals from at least two different categories |

These labels describe the response NAV recommends; they are not actions NAV
performs. In the current CLI, `notify` does not send a notification.
Notification Center delivery is planned, not implemented. Likewise,
"suggest quarantine" is a recommendation only: NAV does not quarantine the
file.

### Exit codes

Exit codes report whether the scan finished, as well as what it found, so a
script can tell "checked, clean" apart from "couldn't check":

| Code | Meaning |
| --- | --- |
| `0` | Nothing flagged, scan complete |
| `1` | Suspicious (`notify`) |
| `2` | High risk (`notify + suggest quarantine`) |
| `3` | Nothing flagged, but the scan was incomplete (e.g. a check couldn't run or the file couldn't be fully read) |
| `4` | Operational error |

A finding outranks an incomplete scan: a flagged file returns `1` or `2` even
if part of the scan came up short. Check each file's `completeness` in
`--json` output, and stderr for skipped coverage.

### JSON output

`--json` output has the same structure as the text breakdown, plus a
top-level `"schema_version"` (currently `1`). Check the version before
parsing further. Rule IDs such as `suspicious-strings` and
`macho-loader-anomaly` identify the signals in a result; consumers should
tolerate IDs they don't recognise as the ruleset evolves.

## What NAV looks for

| Category | Signals |
| --- | --- |
| **Code signing** | Unsigned, ad-hoc signed, invalid, revoked, or signed-but-not-notarized code, weighed in context rather than as an automatic pass or fail |
| **Mach-O structure** | Dylib/rpath load paths into writable or transient locations (`/tmp`, hidden directories, under `/Users/`); risky entitlements such as disabled library validation, weighted higher on unsigned binaries |
| **Obfuscation** | High-entropy regions where readable code or text is expected (packed sections, base64 blobs), judged by *where* they appear rather than by one whole-file number |
| **Scripts** | Shell, AppleScript, JavaScript and `.command` files with `curl \| sh`, base64 piped into an interpreter, and similar loader patterns |
| **Persistence** | LaunchAgent/LaunchDaemon plists in staging locations, unusual run-at-load + keep-alive + short-interval combinations, or an inline downloader as the program to run |
| **Installer packages** | `.pkg` structure, signature, Distribution scripts and install-script contents, inspected without executing installer scripts or payloads |
| **Archives** | ZIP files (documents such as `.docx` included) are read in memory and their contents scanned; `navctl` mounts a disk image read-only in a private scratch directory and scans its volumes (`--no-mount` to skip); anything NAV could not read is reported as not fully checked rather than clean |

Run `navctl rules list` for the full set of rule IDs.

**Conservative scoring is deliberate.** A high-risk verdict needs signals
from at least two different categories; no single generic signal can trigger
it alone. Across the several hundred thousand files of ordinary software
scanned during development, NAV has so far recorded zero false positives. That is a result on the corpus tested, not a
guarantee about every file or environment. NAV would rather leave a borderline
case for you to assess than present a weak signal as certainty.

## Reporting false positives and misses

Detection quality depends on real samples. If NAV flags something legitimate,
or misses something it should have caught, please
[open an issue](https://github.com/yatt-ze/Not-An-Anti-Virus/issues/new) with:

- the output of `navctl rules test <file> --json`
- where the file came from (a download link for legitimate software is ideal)
- **never attach live malware**: share its SHA-256 hash instead

## Contributing

Contributions are welcome.

### Repository layout

A Cargo workspace:

| Crate | What it is |
| --- | --- |
| `crates/nav-core` | The scoring engine. A plain library: no privilege, no I/O beyond reading the file it's handed. Every parser and heuristic lives here. |
| `crates/navctl` | The command-line tool. `scan` and `rules test` run in-process against `nav-core`. |
| `crates/navd` | The privileged background service. |
| `crates/nav-service` | Install layout for `navd` (LaunchDaemon plist, file manifest), shared by `navctl service` and `xtask`. |
| `crates/navnotify` | The per-user notifier. Not implemented yet. |
| `crates/xtask` | Dev tooling: the real-machine corpus comparison, the real-world malware benchmark and install/uninstall checks. |

### Checks

These must all pass before a commit, and CI runs the same ones on Linux and
macOS:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

To run them automatically on every commit:

```sh
git config core.hooksPath .githooks
```

### Test samples

`crates/nav-core/tests/fp_harness.rs` scans every fixture under
`crates/nav-core/fixtures/` on each test run. It fails if a change pushes a
benign sample over the alert threshold or makes scoring nondeterministic. To
add coverage, drop a file (or a `.app` directory) into `fixtures/benign/` or
`fixtures/suspicious/`; no code changes needed.

### Checking against real software

Before merging a change that can move scores, compare it against real
software on your machine. This builds `origin/main` and your working tree,
scans `/usr/bin`, `/Applications`, Homebrew's Cellar, `~/.cargo/bin` and Steam
with both, and exits 2 if any file's verdict or coverage got worse, or a file
went missing:

```sh
cargo xtask corpus compare            # or pass your own roots
```

`cargo xtask corpus scan` and `cargo xtask corpus diff` run the two halves
separately.

Maintainers can also run a benchmark against 100 real macOS malware samples
(`cargo xtask malware vm`). Samples are only ever fetched and scanned inside a
throwaway macOS VM; contributing never needs it. See §11.1a in
[`docs/design/gaps-and-requirements.md`](docs/design/gaps-and-requirements.md).

### Fuzzing

The parsers in `nav-core` (Mach-O, xar / `.pkg`, cpio, ZIP, property lists,
DEFLATE, bzip2) have libFuzzer targets under `crates/nav-core/fuzz/`. That is
a separate workspace and needs a nightly toolchain plus
`cargo install cargo-fuzz`:

```sh
cd crates/nav-core
cargo +nightly fuzz run parse_macho
```

### Design

Design rationale and the longer-term roadmap are in
[`docs/design.md`](docs/design.md). Read it for the reasoning behind the
architecture and the trade-offs NAV is making.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
