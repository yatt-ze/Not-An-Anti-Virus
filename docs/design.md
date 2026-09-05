# NAV ("Not an Anti-Virus") — System Design Document

**Status:** Living document, v0.21
**Purpose:** Reference for all future design/planning conversations on this project. Update this doc as decisions change rather than re-deriving them from scratch.
**Naming:** Project is called **NAV** — "Not an Anti-Virus." Deliberately undersells itself: positioned as a heuristic behavioral monitor, not a signature-based antivirus product, consistent with the honest-coverage-gaps stance in §10. Binaries: `navctl` (CLI), `navtop` (TUI, phase 2). Daemon: `navd`. Per-user notification agent: `navnotify` (background-only, no window — see §9.2). Socket: `/var/run/navd.sock`. Config: `~/.config/navctl/config.toml` (user), `/etc/navd/config.toml` (daemon).
**"No GUI app" clarified:** the constraint is no *openable* application (nothing with a Dock icon/window the user launches, like a Safari-style app). A background-only per-user LaunchAgent with no UI beyond posting to Notification Center is acceptable — this is how `navnotify` is designed (§9.2).

## Document map

This design doc is split across several files. Section numbers are **global and
stable** — `§5.2`, `§11.9`, etc. mean the same thing regardless of which file
they now live in, and remain the form to cite in code comments and commit
messages.

| File | Sections | Contents |
|---|---|---|
| `docs/design.md` (this file) | §1–§3 | Philosophy, architecture, tech-stack decision |
| [`docs/design/scanner.md`](design/scanner.md) | §5–§8 | Heuristics engine, container handling, verdict tiers, CLI surface |
| [`docs/design/platform.md`](design/platform.md) | §4, §9 | Event sources, daemon communication & notification delivery |
| [`docs/design/gaps-and-requirements.md`](design/gaps-and-requirements.md) | §10–§11 | Out-of-scope / known gaps, cross-cutting requirements |
| [`docs/design/roadmap.md`](design/roadmap.md) | §12–§14 | Phased roadmap, locked decisions, open decisions |
| [`docs/design-changelog.md`](design-changelog.md) | — | Revision history |

---

## 1. Project Philosophy

- **Heuristics-first, not signature-first.** No reliance on a virus definition feed. Detection is based on static file analysis and behavioral monitoring, not known-hash/signature matching.
- **Alert-only, non-blocking by default.** The product does not silently quarantine or block execution. It treats the user as an adult: it observes, scores, and alerts — action is opt-in.
- **Non-invasive.** No proactive mounting, extracting, or opening of containers (DMG, ZIP, PKG) the user hasn't already opened or explicitly asked the tool to inspect.
- **Low false-positive rate is the primary success metric** — more important than raw detection rate. Every threshold/weight decision should be biased toward this.
- **CLI/TUI-first**, weighted toward technical users. Scriptable, transparent, no black-box verdicts. No *openable* GUI app (no Dock icon/window) — confirmed viable now that Network Extension, which would have forced a host `.app` bundle, is no longer part of the design. A background-only per-user notification agent with no window (`navnotify`, §9.2) is in scope under this definition; a launchable application is not.
- **Primary threat focus:** commodity macOS malware (adware, trojanized installers) and infostealers (Atomic Stealer–class: Keychain/browser/crypto-wallet theft, AppleScript-based). APT-grade/fileless detection is explicitly out of scope for v1.
- **Behavioral coverage is honestly best-effort.** Without ESF or BSM, process exec/fork attribution relies on NSWorkspace (GUI-only) and polling (lossy for short-lived processes). This is a deliberate tradeoff for a smaller privilege footprint and no Apple entitlement dependency — not an oversight. See §10.

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Unprivileged Clients                   │
│         navctl (CLI) / navtop (TUI, phase 2)            │
│         links `nav-core` directly for on-demand scans   │
└───────────────────────┬─────────────────────────────────┘
                        │ Unix domain socket (JSON-RPC-ish) — status, events tail,
                        │ quarantine actions, config, and daemon-mediated scan history
┌───────────────────────┴──────────────────────────────────────┐
│                  Privileged Daemon (root)                    │
│         also links `nav-core` for automatic/background scans │
│                                                              │
│  Event Sources → Correlator → Heuristics/Scoring Engine      │
│  → Verdict Cache → Notification/Alert Layer → Quarantine     │
│  Manager (opt-in action only)                                │
└──────────────────────────────────────────────────────────────┘
```

**The scoring/heuristics engine is a shared library (`nav-core`), not logic exclusive to `navd`.** Both `navd` and `navctl` link against it. This matters architecturally, not just for code reuse: it's what lets `navctl scan`/`navctl rules test` run a full static analysis of a file the invoking user already has read access to **without `navd` installed or running at all** — no root, no socket, no daemon dependency. `navd` uses the same engine for the cases that genuinely need privilege: automatic write-time scanning triggered by event sources, anything under FDA-gated paths, and anything requiring the correlator/verdict-cache/notification pipeline. If `navd` happens to be running when an on-demand `navctl` scan completes, the verdict is best-effort pushed to the daemon's log/verdict-cache purely for unified history in `navctl events tail` — this push is non-blocking and never required for the scan itself to succeed. Two-tier split: the privileged daemon hosts the full monitoring pipeline (event sources, correlation, notification, quarantine) and is where the scoring engine runs for anything automatic; the CLI/TUI client can invoke the same engine standalone for anything on-demand, and otherwise talks to the daemon over a local socket for state that only the daemon owns (live event stream, quarantine state, config). No GUI app, no host App Extension bundle — pure CLI/daemon distribution.

---

## 3. Tech Stack Decision

- **Rust** for the daemon core, CLI (`clap`), TUI (`ratatui`), and Mach-O/xar parsing.
  - Rationale: memory safety matters because Mach-O/xar/archive parsing is attacker-controlled input; strong CLI/TUI ecosystem; good fit for a performance-sensitive always-on daemon.
  - **Bounds-check every read, and separately bound the total output.** Memory safety and per-read bounds checking stop out-of-bounds access, not resource exhaustion — a parser where every individual read is in range can still be driven to allocate orders of magnitude more than its input. Two ways this showed up in `nav_core::plist` (both found in review, both fixed): a text scanner that failed to advance past what it had already consumed went quadratic in time *and* output on a plain run of `&` characters, and a format that addresses objects by reference let a small file describe a DAG that re-materializes a shared object once per path reaching it. So a depth ceiling and a node-count ceiling are not a memory ceiling; parsers here carry an explicit cumulative byte budget as well, and their fuzz targets assert it. Note also that neither shape is reachable by mutating a valid-file seed corpus, so fuzzing alone will not find them — seed both deliberately.
- **No third-party code on the attacker-controlled-input path.** Narrower than "no dependencies" and stronger than "few": `nav-core` links `serde`/`thiserror` and `navctl` links `clap` without concern, but nothing that parses a file NAV was *pointed at* comes from outside this repo. `macho.rs`, `plist.rs` and `inflate.rs` are all hand-written for that reason. The thing being protected is the panic contract: the rule here is that hostile input yields `Err`, never a panic, and a third-party parser can only promise that by convention — under a root daemon (Phase 0b+) a panic reachable from a malformed `.pkg` is a denial of service, and wrapping a foreign state machine in `catch_unwind` is a worse shape than not having one. Two smaller benefits follow: the output budget above belongs to the decoder itself rather than being bolted onto a foreign stream from outside, and fuzzing (§11.9) spends its cycles on our code rather than on a library the ecosystem has already covered exhaustively. The tradeoff accepted in exchange is that a bug in our own decoder means a *coverage gap* — a legitimate file we fail to read and honestly report as unreadable per §10/§11.8 — rather than a memory-safety issue, which is why each such parser ships with a differential corpus checked against a reference implementation.
- **`nav-core`**: the heuristics/scoring engine (§5) lives in its own Rust crate, not inside the `navd` binary — see §2 for why. `navd` and `navctl` are both thin binaries that link `nav-core`; `navtop` will too. This is a build-organization decision as much as a runtime one: it keeps the engine testable and runnable in isolation (important for Phase 0a's corpus/CI harness, §12) without needing a daemon, root, or a socket connection to exercise it.
- **Thin Swift/Obj-C shim** only where required to call macOS frameworks with poor/no Rust bindings (Security.framework code-signing checks, NSWorkspace, DiskArbitration if needed). FFI bridge between Rust core and Swift shim.
- Avoid building the heuristics core in Swift — keep untrusted-input parsing in Rust.
