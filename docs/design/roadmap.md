# NAV Design — Roadmap & Decisions (§12–§14)

Part of the NAV design document — see [`design.md`](../design.md) for the
document map and section index. Section numbers are global; this file holds §12 through §14.

---

## 12. Phased Roadmap

Phase 0 is split into three sequenced sub-phases rather than one undifferentiated foundation phase. This matters because they carry very different risk: **0a needs no daemon, no root, and no platform permissions at all** — it can start immediately and answers the single most important open question (does the scanner actually produce accurate, low-noise, useful verdicts?) before any investment in the daemon/notification/network apparatus. 0b and 0c are deferred not because they're unimportant, but because building them before 0a's question is answered risks a large, sophisticated product built on an unproven core.

**Phase 0a — Scanner value validation (no daemon, no root, no FDA required)**

Building `nav-core` (§3) and exercising it directly through `navctl scan <path>` / `navctl rules test <path>` — `navctl` links `nav-core` and runs the scan in-process, with no `navd`, no socket, no privilege of any kind, since it's only ever reading files the invoking user already has ordinary access to. Scope: Mach-O inspection, code-signing/notarization checks, quarantine-xattr metadata, script/plist static analysis, directory and `.app`-bundle target resolution (§5.8), stable JSON output with the score/confidence/completeness split (§5.5), stable rule IDs. **False-positive eval harness scaffolding stood up here** — schema, golden-file format, small initial corpus, fuzzing on the Mach-O/xar parsers — not deferred later, and it exercises `nav-core` the same way `navctl` does, without a daemon in the loop either. Tested directly against real-world technical-user software: Homebrew formulas, local Rust/Go binaries, Electron apps, unsigned personal scripts, common admin tools, legitimate installer packages, synthetic suspicious fixtures. **Go/no-go**: if this doesn't produce meaningful, low-noise findings, the daemon/behavioral/notification work in 0b/0c isn't worth building yet — a working scanner and corpus is the actual product-validation bottleneck, not BPF or notification delivery.

**Phase 0b — macOS platform integration feasibility**

Daemon skeleton, `EventSource` abstraction + capability struct, FSEvents watcher, DiskArbitration mount watcher, `navctl status`, socket protocol plumbing, container/`.pkg` handling with the scratch-mount machinery (§6) and decompression-bomb guardrails (§6.2). Feasibility spikes, treated as go/no-go checks rather than assumed:
- **Full Disk Access grant behavior with no app bundle** — confirm whether `navd` can be added to the FDA pane in System Settings as a bare binary/daemon, track the active macOS Tahoe 26.1/26.2 FDA-list bug (§10), document exact steps, and run the per-area coverage probe matrix against real Downloads/Desktop/Documents access.
- Whether `navd`'s FDA grant is a one-time system-wide grant or needs repeating per logged-in user.
- Whether `navctl rules test` (interactive, user-invoked) has meaningfully different TCC exposure than `navd`'s headless background scanning (§10).
- FDA grant durability across the specific upgrade scenarios in §11.10 (same version reinstalled, new version same identifier, certificate renewal, CLI-only update).
- `navnotify` delivery mechanism and final packaging form — bare LaunchAgent vs. minimal agent-style `.app` bundle (§9.2) — and Multi-user/Fast User Switching behavior.
- Homebrew upgrade behavior while `navd` is running, and confirmation that the root-daemon binary (§11.10) resists replacement via a user-writable path.
- FSEvents behavior under high event volume (coalescing, loss/resync).

**Go/no-go**: `navnotify` delivers without requiring an openable app, or the design explicitly falls back to CLI-only per §9.2; the Homebrew-Cellar-writable-binary attack (§11.10) is confirmed closed; Full Disk Access can be granted to `navd` without an app bundle and the grant UX is documented, or the static-analysis coverage gap in §10 is scoped precisely (which paths are actually affected) rather than left as a vague caveat.

These criteria are cleared **provisionally on ad-hoc-signed builds** — the Developer ID is deferred to the Release-Readiness Gate (§13), so 0b runs with the ad-hoc signature the toolchain already applies. Everything above is answerable that way: FDA *grantability* to a bare daemon, the interactive-vs-headless TCC distinction, the Homebrew-attack closure (a filesystem-ownership property, not a signing one), and FSEvents robustness. The one criterion that stays *unverified* until the gate is FDA grant **durability across upgrades** (§11.10) — its whole question is whether a *stable* Developer ID preserves the grant across a version bump, which an ever-changing ad-hoc identity can't establish. It is carried as "expected, unverified" rather than blocking 0b.

**Phase 0c — Behavioral/network sensor feasibility (most speculative, deferred furthest)**

- BPF packet capture behavior under a root launchd daemon, including empirical Local Network Privacy exemption verification (§4.1) — don't just trust the DTS guidance, confirm it.
- **Process-attribution correctness, not merely attribution rate** — measure attempted-vs-successful-vs-ambiguous-vs-wrong across load levels (100/1,000/10,000 rapid connections), process-exits-immediately-after-connect, retransmitted SYNs, IPv4/IPv6, loopback, multi-interface, and VPN-interface traffic. A high attribution rate that's secretly wrong a meaningful fraction of the time fails this spike even if the raw percentage looks good.
- TCP reassembly sufficient for multi-segment ClientHello parsing; ECH recognition (distinguishing an ECH-protected handshake from a parse failure, even though the real hostname stays hidden either way).
- Process-polling miss rate for short-lived subprocesses — measures how bad the LOTL/behavioral gap actually is in practice, not just in theory.
- Sleep/wake and network-interface-change behavior for the packet-capture source.

**Go/no-go** — Phase 2's behavioral claims are not locked until these hold, not assumed at design time:
- No demonstrated false (as opposed to merely missing) process attribution in the test corpus.
- Ambiguous matches surface as `Ambiguous`, never forced into a single PID.
- Capture loss and FSEvents resync events are observable, not silent.
- Packet/container parsers stay within their configured memory bounds under the fuzz corpus.
- Idle CPU/wakeup rate stays inside the resource budget (§11.3).

**Phase 1 — Scanner scoring engine v1 + full container handling**
Builds on 0a's proven scanner core: category-based, interaction-term scoring (§5.4) replacing 0a's simpler prototype scoring, and the full container non-invasive handling (§6, both metadata-only passive path and explicit-command payload scan) built out in 0b. This is where the static scanner goes from "validated concept" to "production-quality," rather than where the concept is first proven — that already happened in 0a.

**Phase 2 — Behavioral pipeline**
Polling (process/socket snapshots), NSWorkspace lifecycle, Packet Capture (BPF/libpcap + bounded ClientHello reconstruction + SNI parsing + event-triggered attribution, with the fuzzing/minimization discipline from §11.9), Correlator/identity-based dedup layer, verdict cache, `navctl events tail`. Only claim detections actually supported by what Phase 0c's feasibility spikes measured — not aspirational coverage.

**Phase 3 — Quarantine, config, hardening**
Quarantine manager, allow/denylist, config file support, ruleset hot-reload + rollback, daemon self-termination detection, event log privacy hardening (redaction, retention), socket protocol hardening (§9.1), safe root-daemon installation path (§11.10), `navnotify` install/uninstall, clean uninstall path.

**Phase 4 — Polish / stretch**
`navtop` TUI, ruleset update distribution channel, optional on-device ML scoring layer, optional ESF-backed edition if the entitlement/packaging tradeoff is ever revisited.

---

## 13. Locked Decisions

- **Decompression-bomb limits** — locked, see §6.2 table. User-configurable via `navctl config`, defaults chosen to be generous enough for legitimate large archives while catching genuine bomb patterns; hitting a limit is treated as indeterminate, not automatically malicious (§6.2).
- **Distribution mechanism** — **Homebrew formula** (`brew install nav`) for the CLI is the primary target, chosen for minimal install friction. The privileged `navd` daemon requires a separate, explicit installation step (`sudo navctl service install`, §11.10) rather than relying on `brew services` alone, since the daemon must not execute from a Homebrew-user-writable path. A `.pkg` installer remains a fallback for non-Homebrew users. **All shipped binaries (`navctl`, `navd`, `navnotify`) must be signed and notarized** regardless of distribution channel — an unsigned root daemon asking a user to grant it Full Disk Access and run `sudo` is a hard sell even before Gatekeeper's first-run warnings make it worse. This is a hard requirement on the build/release pipeline, not optional polish.
- **Developer ID is acquired at the release boundary, not up front.** The signed-and-notarized requirement above is a gate on *shipping*, and shipping doesn't happen until the product is judged releasable — so the Apple Developer Program membership, the notarization pipeline, and the Developer-ID-dependent feasibility checks (FDA grant durability across upgrades §11.10, `navnotify` production-attribution delivery, the fresh-user download→Gatekeeper→install→FDA first-run UX) are deferred to a single **Release-Readiness Gate** run once, immediately before first distribution. Every pre-release phase (0b–3) develops and validates with the ad-hoc signature the toolchain already applies; those phases' go/no-go checks are cleared *provisionally* on ad-hoc results, with the Developer-ID-dependent subset the only part that stays unverified until the gate (see §12).
- **Build-from-source is the sanctioned no-Developer-ID fallback delivery** — and deliberately *not* `curl … | sh`. A source build (auditable `git clone && make`, or `brew install --build-from-source` from the tap) produces a locally compiled, ad-hoc-signed binary that needs no notarization, and for an open-source security tool that auditability is a feature, not a workaround. Piping a remote script straight into a shell to fetch-and-run is the exact inline-loader pattern NAV's own `launchd-persistence-plist`/`suspicious-strings` rules flag (§5.2); shipping a security product whose install command models the attack it warns against is ruled out. The fallback moves the trust decision into something the user can read, it doesn't remove it (an unsigned root daemon still asks for `sudo` + FDA), so it stays a fallback for technical users, never the recommended path.
- **Domain-reputation approach** — locked, see §5.6. Local-first by default (`LocalHeuristicProvider`, using precisely-named local-prevalence signals rather than overclaiming registration-age data), with an opt-in `CloudFeedProvider` extension point reserved for a future release.
- **Naming/positioning** — resolved: project is **NAV**, "Not an Anti-Virus."
- **Notification delivery** — locked, see §9.2. `navnotify`, a background-only per-user LaunchAgent, no openable window, opt-out respected end-to-end.

---

## 14. Open Decisions (Still Not Locked)

- Specific cloud domain-reputation API to integrate with `CloudFeedProvider`, once built.
- Exact behavior of `navnotify` under multi-user/Fast User Switching — pending Phase 0b spike.
- Whether the ECH gap (§10) meaningfully changes how much weight network-behavior heuristics should carry in the overall scoring model, once real-world ECH adoption data informs how much traffic it actually affects.
