# NAV — Not an Anti-Virus

NAV is a heuristic, alert-only behavioral monitor for macOS. It is
deliberately *not* signature-based antivirus: it decides what looks
suspicious from static file analysis and behavioral signals, not from a
downloaded virus-definition feed. And it never silently blocks, deletes, or
quarantines anything — it inspects, scores, explains what it found, and
leaves the decision to you.

It is a command-line tool. There is no app to open and no menu-bar icon.

## Status

Early development

`navctl scan` and `navctl rules test` work today: point them at a file, a
folder, or a `.app` bundle and they produce a verdict with a full breakdown
of which signals fired. This runs entirely as your own user — no background
service, no root, no special macOS permissions.

Everything else is not built yet: automatic scanning of newly-downloaded
files, network monitoring, persistence-watching, Notification Center
alerts, quarantine. Those need a privileged background service (`navd`)
that doesn't exist yet. `navctl` lists those subcommands, but they tell you
plainly that they're unavailable rather than pretending to work.

## What the scanner looks for

- **Code signing & notarization** — unsigned, ad-hoc signed, or
  signed-but-not-notarized code, weighed in context rather than as an
  automatic pass or fail.
- **Mach-O structure** — unusual load commands, suspicious entitlements on
  unsigned binaries, packed or obfuscated code sections.
- **Obfuscation** — high-entropy regions where readable code or script text
  is expected (packed sections, base64 blobs), judged by *where* they
  appear rather than as one whole-file number.
- **Scripts** — shell / AppleScript / `.command` files with `curl | sh`
  patterns, base64 piped into an interpreter, and similar loader shapes.
- **Persistence** — LaunchAgent / LaunchDaemon property lists in staging
  locations, anomalous run-at-load + keep-alive + short-interval
  combinations, or an inline downloader as the program to run.
- **Installer packages** (`.pkg`) — the container structure, signature, and
  the contents of the install scripts, all read without executing the
  package.

High-severity verdicts needs corroborating
signals from different categories, or one narrow known-bad pattern. Keeping
false positives low is the priority over raw detection rate.

## Build

Requires a recent stable Rust toolchain.

```sh
cargo build --workspace
cargo test --workspace
```

The binary is then `target/debug/navctl` (or `target/release/navctl` with
`--release`).

## Usage

```sh
# Scan a file and print a verdict
navctl scan ./some-binary

# Scan a folder
navctl scan ./some-dir --recursive

# Full signal-by-signal breakdown for a file, folder, or .app bundle.
# A .app is scanned as one unit: its real executable is located, compiled
# resources (nibs, asset catalogs) are skipped, and the bundle's verdict is
# that of the single worst file inside it.
navctl rules test ./suspicious.app

# The same breakdown as JSON — identical structure to the text output
navctl rules test ./suspicious.app --json

# Show the active ruleset
navctl rules list
```

**Exit codes** report scan completeness as well as verdict, so a script can
tell "checked, clean" apart from "couldn't finish":

| Code | Meaning |
|---|---|
| `0` | Clean, scan complete |
| `1` | Suspicious |
| `2` | High risk |
| `3` | Indeterminate or incomplete (e.g. the file couldn't be fully read) |
| `4` | Operational error |

## Repository layout

A Cargo workspace:

| Crate | What it is |
|---|---|
| `crates/nav-core` | The scoring engine. A plain library — no privilege, no I/O beyond reading the file it's handed. Every parser and heuristic lives here. |
| `crates/navctl` | The command-line tool. `scan` and `rules test` run in-process against `nav-core`. |
| `crates/navd` | The privileged background service. Not implemented yet. |
| `crates/navnotify` | The per-user notifier — background-only, no window. Not implemented yet. |

The parsers in `nav-core` (Mach-O, xar / `.pkg`, property lists, DEFLATE) have
libFuzzer targets under `crates/nav-core/fuzz/`, which is a separate
workspace — it needs a nightly toolchain and `cargo install cargo-fuzz`:

```sh
cd crates/nav-core
cargo +nightly fuzz run parse_macho
```

`crates/nav-core/tests/fp_harness.rs` runs every fixture under
`crates/nav-core/fixtures/` (known-benign and synthetic-suspicious) on each
test run, and fails if a rule change pushes a benign sample over the alert
threshold or makes scoring nondeterministic. Add coverage by dropping files
— or `.app` directories — into `fixtures/benign/` or `fixtures/suspicious/`;
no code changes needed.

## Contributing

`cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo test --workspace` must all pass before a commit.

The design rationale and longer-term roadmap live in
[`docs/design.md`](docs/design.md) — worth reading before proposing
anything architectural, though you don't need it to build or use what's
here.
