# A1 — install / uninstall / residue-verify (finalised)

First Stage A deliverable (`docs/plans/phase-0b.md` §A1; design §11.10, §10, §11.8).
Ad-hoc signed. No `EventSource` — that's A2. Nothing lands until the user says go
(CLAUDE.md scope discipline).

## Goal

`navctl service {install,uninstall,status}` + a `cargo xtask` verify runner, built
so **uninstall provably leaves zero residue** and CI proves it every push.

## Core design — one manifest, three consumers

`Layout::manifest()` is the sole enumeration of every artifact. **install** creates
exactly it, **uninstall** removes exactly it (whole list, tolerant of already-gone),
**residue check** asserts each entry absent. Uninstall can't drift behind install.

## Artifact inventory

| Artifact | Uninstall | Notes |
|---|---|---|
| `/Library/PrivilegedHelperTools/navd` | delete | copied, root:wheel 0755, re-signed `-i com.nav.navd` |
| `/Library/PrivilegedHelperTools/` | remove only if we created it **and** now empty | shared Apple dir — don't reclaim others' |
| `/Library/LaunchDaemons/com.nav.navd.plist` | delete | points at the *copied* binary, never Cellar/target |
| `/etc/navd/` (+`config.toml`) | rm -r | |
| `/private/var/db/navd/` (+logs/state) | rm -r | |
| launchd registration | `bootout system/com.nav.navd` | modern API, not load/unload |
| launchd disable override | `enable` **before** bootout | sticky; survives bootout otherwise |
| TCC/FDA grant | scoped `tccutil reset SystemPolicyAllFiles com.nav.navd` | best-effort; **honest residual**, reported not claimed clean |

Residue check also **name-sweeps** the parent dirs for `navd`/`com.nav.navd` as a
backstop against manifest drift.

## Settled decisions

1. **TCC:** scope to `com.nav.navd` (re-sign the copy with a stable id); never coarse-reset all apps.
2. **navd source:** resolved next to the running `navctl`.
3. **Runner:** `cargo xtask`, **also run in CI** against a fake prefix.

## Seam (so CI and the sudo run share one code path)

- `Layout { prefix }` — every path derived from it (`/` real, tempdir in CI).
- `SystemOps` trait — the un-fakeable ops (`chown`, `codesign`, `bootstrap`,
  `bootout`, `enable`, `service_loaded`, `tccutil_reset`).
  - `RealSystemOps` — actual macOS commands (sudo run, prefix `/`).
  - `FakeSystemOps` — records calls + simulates state (CI, tempdir prefix).

Orchestration is one body of code; only the seam swaps.

## What CI proves vs. the dev box

- **CI** (`cargo xtask verify --fake`, both runners): path derivation, dir/file
  create+remove, plist **golden-file** match, idempotent re-install, best-effort
  uninstall, residue predicates, and `FakeSystemOps` recorded the right
  `bootstrap`/`chown root:wheel` args. macOS runner uses **real** `codesign`.
  Pure-logic parts stay ordinary `cargo test`.
- **Dev box** (`sudo cargo xtask verify --real`, `RealSystemOps`, prefix `/`): the
  real `install → assert-clean → uninstall → assert-clean` — the only place
  launchd, root ownership, and TCC are actually exercised. Never in CI.

## Honest boundary

CI cannot prove: real launchd accepts the plist, root chown sticks, TCC actually
resets. Those are the sudo run + B-stage findings, never faked (§11.8).

## Build order (each its own commit, green at every step)

1. `Layout` + `manifest()` + plist rendering — pure, unit-tested (golden file).
2. `SystemOps` trait + `RealSystemOps` + `FakeSystemOps`.
3. Orchestration: install / uninstall / residue over the seam.
4. `navctl service {install,uninstall,status}` wiring (replaces the stubs).
5. Minimal `navd` run-loop (stay-alive only, no EventSource) so bootstrap has a real target.
6. `xtask` crate + cargo alias; `verify` (`--fake` default / `--real` sudo).
7. CI step on both runners.
