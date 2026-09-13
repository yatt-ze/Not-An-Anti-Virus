# A2 — minimal `navd` scan skeleton (draft for review)

Second Stage A deliverable (`docs/plans/phase-0b.md` §A2; design §12, §9.1, §5.5,
§10, §11.8). Ad-hoc signed. **No `EventSource`, no socket, no correlator** — those
are Stage C. Nothing lands until the user says go (CLAUDE.md scope discipline).

## Goal

Give the root LaunchDaemon a way to **run the existing `nav-core` scan on a
requested path, headless**, so the B3 spike can compare `navd`'s file-read
behaviour under launchd/root TCC against `navctl rules test` run interactively in
a terminal. A1 left `navd` as a stay-alive skeleton; A2 makes it actually
exercise `nav-core` once, as a daemon-context instrument.

## The §9.1 constraint (read first — it shapes everything)

Design §9.1 is explicit: the daemon socket is **"not for on-demand scans, which
`navctl` runs locally against `nav-core` whether or not `navd` is installed."**
On-demand scanning is, and stays, `navctl`'s job — in-process, in the user's TCC
context. So A2 is **not** building a "scan a path" service or RPC, and must not be
read as one by a reviewer.

What A2 *is*: a **spike instrument**. B3 needs to observe whether `navd`, running
headless as root under launchd, can *read* a TCC-protected path at all, and how
that differs from the interactive CLI. The minimal honest way to expose that is a
one-shot self-scan mode on `navd` itself — no socket, no daemon-owned scan
service, no new privileged request path.

**`scan-once` is temporary scaffolding, not committed surface.** It exists to run
B3 and is **removed once B3 is answered** — a standing `navd scan-once` would be
dead surface contradicting §9.1 (on-demand scanning is `navctl`'s job) and has no
place in the shipped product; Phase 2's daemon scanning lives inside the event
pipeline, not behind a CLI subcommand. What is *not* thrown away: the `nav-core`
presentation-contract lift (Decisions 1 & 3) — that is genuine de-duplication that
stands on its own — and the plain fact that `navd` links `nav-core`. So it is
**not documented in §8's stable CLI surface**; it is recorded as an explicitly
temporary Phase 0b spike instrument with the removal condition below.

## Deliverable

One `navd` binary, **two process lifecycles** — this distinction is load-bearing,
don't blur it:

- **`navd` (no args) → the daemon. It does not exit after a scan.** The persistent
  A1 stay-alive run-loop, unchanged; runs until SIGTERM. It never scans-then-exits
  and so has no "scan exit code." The A1 LaunchDaemon plist invokes `navd` with no
  arguments, so this path stays byte-for-byte compatible — the plist is not
  touched in A2.
- **`navd scan-once <path> [--json] [--recursive]` → a separate short-lived
  invocation of the same executable.** Not the daemon doing a scan and dying — a
  one-shot process that runs `nav_core::scan_target`, prints the verdict, and
  returns like any CLI run. No run-loop, no stay-alive signal handling. This is
  what B3 kickstarts as a one-shot launchd job (`RunAtLoad`, no `KeepAlive`) to
  get a genuine headless/root read, then observes its exit code + logged JSON.

Behaviour of `scan-once`:
- Reuses `nav_core` exactly as `navctl` does (`scan_target(path, recursive)`) —
  **no second scoring/verdict logic in `navd`.** Same engine, same `ScanResult`.
- `--json` emits the same versioned JSON shape `navctl` emits (Decision 1).
  Human mode prints a terse one-line-per-file summary; the verdict content is
  secondary for B3 — **the load-bearing field is `completeness`**: an
  unreadable/TCC-blocked path surfaces as `Indeterminate`/`Low`, never as a clean
  read (§5.5, §10, §11.8). That distinction is exactly what B3 measures.
- **Exit code: the *same* §8 taxonomy `navctl` uses** (Decision 3), via the shared
  `ScanResult → code` mapping lifted into `nav-core` alongside the JSON contract:
  `0 CLEAN / 1 SUSPICIOUS / 2 HIGH_RISK / 3 INDETERMINATE / 4 OPERATIONAL_ERROR`.
  A TCC-blocked or unreadable path is `INDETERMINATE` (3), never folded into
  `CLEAN` — which is precisely the read-success signal B3 keys off. `navd
  scan-once` and `navctl scan` return identical codes for identical verdicts.

## Decisions to confirm before any code (these are the review-sensitive forks)

**Decision 1 — where the JSON verdict contract lives. [RESOLVED: lift into
`nav-core`.]** The `schema_version` envelope + `ScanResult` JSON shape were private
to `navctl/output.rs`. Both binaries must emit one identical contract, so the
`SCAN_JSON_SCHEMA_VERSION` constant + the `with_schema_version` merge move into
`nav-core` next to `ScanResult`, as a **no-behaviour-change refactor first**;
`navctl` consumes it (its existing `output.rs` tests prove no change), then `navd`
builds on top.
  - *Note:* `nav-core/lib.rs` currently says it "only turns a file path into a
    `ScanResult`." Holding that type's canonical presentation contract (JSON
    envelope + exit mapping, Decision 3) is a mild, deliberate widening of that
    charter — called out in §8/the changelog so it's a reviewed choice, not drift.

**Decision 2 — arg parsing. [RESOLVED: `clap` for `navd`, matching `navctl`.]**
One arg-parsing approach across both binaries (per the "change it everywhere or
nowhere" principle). Hand-rolling `navctl`'s rich derive-based subcommand tree is
a non-starter, and `clap` is already a workspace dependency the shipped, signed
`navctl` links — so adding it to `navd` doesn't widen the *project's* trust
surface, only that binary's. The earlier "minimise root deps" lean is outweighed
by consistency here.

**Decision 3 — exit codes. [RESOLVED: mirror `navctl`'s §8 taxonomy via a shared
mapping.]** The one-shot `scan-once` *process* (not the daemon — see Deliverable)
returns an exit code like any CLI run. Rather than a bespoke scheme, it reuses
`navctl`'s existing taxonomy — `0 CLEAN / 1 SUSPICIOUS / 2 HIGH_RISK /
3 INDETERMINATE / 4 OPERATIONAL_ERROR` — by lifting the `ScanResult → code`
mapping (today in `navctl/exit.rs`, and already dependent on `nav-core`'s
`TargetScan`) into `nav-core` alongside the JSON contract. `INDETERMINATE` already
means "couldn't fully examine", which is exactly the TCC-blocked-read signal B3
needs, kept distinct from `CLEAN`. `navd scan-once` and `navctl scan` then return
identical codes for identical verdicts.

## Non-goals / scope fence (state plainly so review can check us)

- **No** `EventSource`, FSEvents, DiskArbitration, socket, correlator, config
  file, or notification — all Stage C / later phases.
- **No** daemon-owned scan service or RPC (§9.1). `scan-once` is a self-contained
  one-shot; the persistent daemon never scans on request.
- **No** change to the A1 install/uninstall/residue machinery, the plist, or the
  `Layout` manifest. `navd`'s artifact footprint is unchanged.
- **No** `navctl` command changes — `status`/`setup fda` are A3.
- **No** privilege escalation or euid gating on `scan-once`: it reads with
  whatever rights the process has (the point of B3 is to observe that).

## Build order (each its own commit, green at every step)

1. **Refactor (no behaviour change):** move the canonical `ScanResult`
   presentation contract into `nav-core` — `SCAN_JSON_SCHEMA_VERSION` +
   `with_schema_version` (from `navctl/output.rs`) and the `ScanResult → code`
   mapping (`for_result`/`for_target`, from `navctl/exit.rs`). `navctl` consumes
   the moved code; its existing `output.rs`/`exit.rs` tests are the proof of no
   output or exit-code change. No behaviour delta.
2. `navd`: add `clap` (Decision 2) and the `scan-once` subcommand — call
   `scan_target`, human + `--json` rendering via the shared contract, exit codes
   via the shared mapping (Decision 3). No-arg path routes to the A1 daemon,
   untouched.
3. Tests + fixtures (below), in the same commit as the code they exercise.
4. Doc + changelog update (below), in the commit that introduces the behaviour.

## Tests

`navd` currently has no test module. A2 adds integration coverage
(`crates/navd/tests/scan_once.rs`), driving the built binary or the mode's entry
fn:
- benign temp file → exit 0, `NoAction`, `--json` parses and carries
  `schema_version` + `completeness`.
- suspicious content (a `suspicious-strings`-tripping script, mirroring the
  `nav-core` fixture style) → exit 0, at least one signal present.
- non-existent path → non-zero exit, stderr names the path, **not** reported as
  clean.
- unreadable path (temp file, perms stripped; skip if running as root can't be
  denied) → surfaces as `Indeterminate`/non-zero, never clean (§11.8). Mark
  `#[ignore]` or guard if the CI environment can't create a genuinely unreadable
  file.
- no-arg invariant: a cheap check that `navd` with no args still enters the
  stay-alive path and exits 0 on SIGTERM (spawn + signal, bounded timeout) — or,
  if that's flaky in CI, assert the arg dispatcher routes no-arg to the daemon
  branch without running it.

No new `nav-core` rule, so no `fp_harness` fixture is required; any test inputs
`navd` needs live under `crates/navd/tests/`.

## Doc updates (same commit as the behaviour, per CLAUDE.md)

- **Do not add `scan-once` to §8's stable CLI surface.** Record it instead as an
  explicitly **temporary** Phase 0b spike instrument (in the §12/Phase-0b spike
  text or a clearly-labelled note), with the §9.1 reminder that on-demand scanning
  is and stays `navctl` in-process, and the removal condition below stated. This
  keeps a throwaway from reading as committed surface.
- **§8 / changelog** — record the permanent part: the `nav-core` presentation
  contract (JSON envelope + `ScanResult → code` mapping) now lives in `nav-core`
  and both binaries consume it. Note the mild charter widening (§ nav-core now
  owns `ScanResult`'s canonical presentation).
- **`docs/design-changelog.md`** — dated top entry in the existing style; bump
  `docs/design.md` `**Status:**` version.

## Traps to get right in A2 (review must check these)

1. **`clap` no-arg dispatch must preserve the A1 plist.** The LaunchDaemon runs
   `navd` with **zero** args; that must route to the daemon loop — not print
   `--help`, not error on a missing subcommand. Use an **optional** subcommand
   (`Option<Command>`, `None` → daemon). A required subcommand turns bare `navd`
   into a usage error and silently breaks the installed daemon at bootstrap.
2. **Fix `nav-core`'s charter docstring in the same commit.** `nav-core/lib.rs`
   says it "knows nothing about … sockets, or notifications — it only turns a file
   path into a `ScanResult`." Moving presentation (JSON + exit mapping) in without
   updating that comment makes the crate contradict its own docs — an external
   reviewer will flag it.
3. **Do not give `navd` a `serde_json` dependency.** The lifted `nav-core` API
   exposes the verdict JSON as a **`String`** (and the exit code as the shared
   `u8`/enum); `navd` calls it and prints. Keeps the root binary minimal and the
   later removal a clean, localised delete.
4. **Strict lifecycle separation.** The daemon path never scans; the `scan-once`
   path never starts the stay-alive loop or its signal handlers. There must be no
   way a *running daemon* performs a scan (that would contradict §9.1).

## Carries into B3 / Phase 2 (not A2 code — recorded so it doesn't bite later)

- **B3 must measure the installed, re-signed copy.** TCC keys off code identity;
  A1 re-signs the copy as `com.nav.navd`. B3 must invoke
  `/Library/PrivilegedHelperTools/navd`, never a fresh `target/…/navd` (different
  ad-hoc identity → wrong question).
- **A launchd one-shot's exit code isn't cleanly observable**, and launchd
  throttles fast-exiting jobs. For the headless path the **logged JSON verdict is
  the primary B3 signal**; the exit code is directly useful only when `scan-once`
  is run under `sudo` in a shell.
- **Scanning as root is a threat surface (Phase 2 FDA-gated scanning).** A
  malicious symlink in a scanned tree could get root to read a protected file.
  Fine for B3 against a controlled path — but A2 is **not** a blessing to
  root-scan arbitrary trees; the threat model is a real Phase 2 item.

## Removal condition (tracked, not optional)

`navd scan-once` (the subcommand + its `clap` wiring and `navd`-side rendering) is
**deleted once B3 is answered.** Removal is a tracked follow-up item — carried in
the phase-0b plan / B3 wrap-up — not left to memory. **If `scan-once` was the only
user of `clap` in `navd`, `clap` comes out too**, returning `navd` to its
A1-minimal dep tree — otherwise the root daemon carries an orphaned parser
forever. What survives the removal: the `nav-core` presentation-contract lift,
`navd`'s `nav-core` linkage, and the B3 *findings* (the documented TCC behaviour).
A2 review should confirm nothing outside `navd`'s own arg-dispatch/rendering comes
to depend on `scan-once`, so the later deletion is a clean, localised revert.

## Gate before every commit (CLAUDE.md)

`cargo fmt --all` → `cargo clippy --workspace --all-targets -- -D warnings` →
`cargo test --workspace`. Commit small, on functional boundaries; no attribution
lines in commit messages.

## What A2 does *not* prove (honest boundary, §11.8)

A2 gives `navd` the *capability* to read a path headless and report completeness.
It does **not** by itself answer B3 — that's the spike: install via A1, kickstart
`navd scan-once` as a headless root launchd job against a TCC-protected path,
compare to `navctl rules test` in a terminal. Wiring that comparison into the
`xtask --real` harness is **B3's** work, not A2's.

## Team assignment (manager notes — not part of the deliverable)

- Sonnet agent writes commits 1–4; I review each against this plan + run the full
  gate before it's accepted, and hold the line on the scope fence above.
- Everything here lands on a `phase-0b/a2-scan-skeleton` branch off `main`, PR'd
  like A1, and goes through external code + security review — so the §9.1 framing
  and the root-binary dep-surface choice (Decision 2) need to read cleanly to an
  outside LLM reviewer, not just to us.
