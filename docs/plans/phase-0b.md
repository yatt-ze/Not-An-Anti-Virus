# Phase 0b execution plan — macOS platform integration feasibility

Companion to the roadmap (`docs/design/roadmap.md` §12). The roadmap holds the
*scope* and go/no-go of Phase 0b; this file holds the *sequence* — what order to
attack it in, what each spike asks and how it passes, and what the
Release-Readiness Gate still checks. Section numbers (`§10`, `§11.10`, …) refer
to the design doc.

## Framing

Phase 0a proved the scanner. Phase 0b answers "can this run as a privileged
macOS daemon at all?" Several of those answers can invalidate design
assumptions, so this phase is **spike-first**: cheap feasibility checks run
before the daemon is built in earnest, and the build is gated on them.

**The whole phase runs on ad-hoc signatures.** NAV doesn't sign with a
Developer ID (§13), so nothing here, or later, requires the Apple Developer
Program. FDA grant durability across upgrades (B2) is tested ad-hoc and with a
stable self-signed certificate; if neither keeps the grant, re-granting after a
`navd` upgrade is documented as a known gap rather than blocking the phase.

**Scope discipline:** no daemon / socket / root / FDA / network code lands until
the spike it depends on has been run and the user has said go (CLAUDE.md).

## Stage A — Spike enablement (test rig, not product)

Just enough to make the spikes runnable. Everything here is ad-hoc-signed.

- **A1. Install / uninstall / residue-verify — built first, as one unit.** A
  spike phase installs a root LaunchDaemon, root-owned files, and TCC state on
  the real dev machine, so a *verified* teardown is a prerequisite for every
  other spike, not a Phase 3 afterthought (it already exists in §11.10; this
  pulls it forward). Three pieces, shipped together:
  - `sudo navctl service install` (§11.10) — copy `navd` to a root-owned path
    (`/Library/PrivilegedHelperTools/`), write the LaunchDaemon plist pointing
    at the *copied* binary (never the Cellar path), create `/etc/navd` + state
    dirs, bootstrap launchd. Idempotent, safe to re-run.
  - `navctl service uninstall` — the inverse, and **tolerant of a partial or
    failed install**: best-effort removal of each known artifact, never "fail
    because the plist is already gone."
  - a **residue check** the test harness can call to *assert* clean — no plist,
    launchd unloaded, root paths removed, TCC probed and `tccutil reset`
    attempted. "Clean" is verified, not claimed.
  - **Caveat (honest):** fully hermetic for filesystem + launchd; **TCC/FDA
    grants have no clean programmatic removal** (`tccutil reset
    SystemPolicyAllFiles` is coarse and version-dependent; worst case a manual
    System Settings removal). How cleanly TCC resets is itself a B1/B2 finding,
    not something uninstall can guarantee up front.
- **A2. Minimal `navd` skeleton** — a root LaunchDaemon that only runs the
  existing `nav-core` scan on a requested path. No `EventSource` yet.
- **A3. `navctl setup fda` + per-area FDA probe matrix + `navctl status`
  (§10)** — the user-invoked FDA helper and the per-area probes
  (`Downloads: verified`, `Documents: degraded`, …) B1 measures against.

> There is no notarization pipeline (would-be A0): NAV doesn't notarize (§13).

**Test protocol for every spike:** `install → test → uninstall → assert-clean`.
Each run starts from a verified-clean baseline, so results (especially B1/B2's
FDA state) aren't contaminated by a prior run and the dev machine isn't polluted.
A spike that can't restore a clean baseline is a finding in its own right.

## Stage B — Go/no-go spikes

Each is a question, a method, and a pass bar. Run B1 first (highest risk: the
active Tahoe FDA-list bug, §10). B4/B6 need no privileged rig and can run in
parallel.

| # | Spike | Method | Pass bar |
|---|---|---|---|
| **B1** | FDA grantable to a bare daemon? | Drag ad-hoc `navd` into the FDA pane; run the A3 probe matrix; exercise the Tahoe 26.1/26.2 FDA-list bug. | Grant works + probe matrix documented, **or** §10 coverage gap scoped precisely (which paths degrade). |
| **B2** | FDA scope & durability | Grant, then reinstall / bump version / renew cert / update CLI-only (§11.10), once ad-hoc and once signed with a stable self-signed certificate. | Durability measured for both. If neither keeps the grant, re-grant-after-upgrade is documented (§10) and the install UX says so. Not a blocker. |
| **B3** | Interactive vs headless TCC | Compare `navctl rules test` (terminal) vs `navd` headless read of a protected path. | Behavior confirmed either way; on-demand scan may work without a `navd` grant. |
| **B4** | `navnotify` delivery (§9.2) | Bare LaunchAgent vs `LSUIElement` app; post via UserNotifications; test Fast User Switching routing. | A form that posts correctly-attributed notifications, **or** CLI-only fallback with `navctl status` showing `notify delivery: degraded`. |
| **B5** | Homebrew root-daemon attack (§11.10) | With A1 installed, attempt the Cellar-writable-binary → root swap; test Homebrew upgrade while `navd` runs. | Attack confirmed closed (plist runs only the root-owned copy); a regression test proving it. |
| **B6** | FSEvents + DiskArbitration robustness | Drive FSEvents under high event volume; basic mount-watcher. | Degradation is *observable* (`Lossless / Dropped / Coalesced / ResyncRequired`, §11.8), never silent. |

**Decision gate:** the §12 go/no-go — `navnotify` delivers (or CLI-only fallback
locked); Homebrew attack closed; FDA grantable + UX documented, or §10 coverage
gap scoped. Cleared provisionally on ad-hoc results. A hard fail reshapes the
design *before* build — the point of the phase.

## Stage C — Build-out (only after the gate)

The Phase 0b deliverables, now de-risked, still ad-hoc:

- `EventSource` abstraction + capability struct (the interface B6 validated).
- FSEvents watcher + DiskArbitration mount watcher.
- Socket protocol plumbing — the authenticated local channel (§9.1).
- `navctl status` fleshed out (per-area FDA, notify delivery, source health).
- Container / `.pkg` handling: scratch-mount machinery (§6) + decompression-bomb
  guardrails (§6.2, limits already locked). **Carries its own privileged /
  disk-mount threat model — treat as a sub-review, not a bolt-on.**

## Release-Readiness Gate (terminal step, before the first Homebrew release)

Run once, before the first Homebrew release (§13). No Developer ID:

1. Fix the signing identity: ad-hoc, or the self-signed certificate if B2
   showed it keeps the FDA grant.
2. Re-check under that identity: **B2** grant durability across the four §11.10
   upgrade scenarios; **B4-final** notification attribution; fresh-user install
   (script or tap) → `navctl service install` → FDA first-run UX.
3. Package the Homebrew tap formula and the install script's release assets
   (§13) → first Homebrew release.

The install script (§13) can ship pre-release `navctl` builds before the gate.

## Dependencies & risks

- **Biggest risk to the phase:** the active Tahoe FDA-list bug (§10) could make
  B1 a "no" on current macOS — why it runs first, and why §10 already designs
  the fallback (visible per-event `NOT SCANNED`).
- **No Developer ID** (§13): `navd`'s FDA grant may not survive upgrades. B2
  measures it; the self-signed certificate is the mitigation being tested.
