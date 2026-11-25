# NAV Design — Roadmap & Decisions (§12–§14)

Part of the NAV design document — see [`design.md`](../design.md) for the
document map and section index. Section numbers are global; this file holds §12 through §14.

---

## 12. Phased Roadmap

Phase 0 is split into three sequenced sub-phases rather than one undifferentiated foundation phase. This matters because they carry very different risk: **0a needs no daemon, no root, and no platform permissions at all** — it can start immediately and answers the single most important open question (does the scanner actually produce accurate, low-noise, useful verdicts?) before any investment in the daemon/notification/network apparatus. 0b and 0c are deferred not because they're unimportant, but because building them before 0a's question is answered risks a large, sophisticated product built on an unproven core.

**Phase 0a — Scanner value validation (no daemon, no root, no FDA required)**

Building `nav-core` (§3) and exercising it directly through `navctl scan <path>` / `navctl rules test <path>` — `navctl` links `nav-core` and runs the scan in-process, with no `navd`, no socket, no privilege of any kind, since it's only ever reading files the invoking user already has ordinary access to. Scope: Mach-O inspection, code-signing/notarization checks, quarantine-xattr metadata, script/plist static analysis, directory and `.app`-bundle target resolution (§5.8), stable JSON output with the score/confidence/completeness split (§5.5), stable rule IDs. **False-positive eval harness scaffolding stood up here** — schema, golden-file format, small initial corpus, fuzzing on the Mach-O/xar parsers — not deferred later, and it exercises `nav-core` the same way `navctl` does, without a daemon in the loop either. Tested directly against real-world technical-user software: Homebrew formulas, local Rust/Go binaries, Electron apps, unsigned personal scripts, common admin tools, legitimate installer packages, synthetic suspicious fixtures. **Go/no-go**: if this doesn't produce meaningful, low-noise findings, the daemon/behavioral/notification work in 0b/0c isn't worth building yet — a working scanner and corpus is the actual product-validation bottleneck, not BPF or notification delivery.

**Phase 0b — macOS platform integration feasibility**

**Gate (threat model §7, §8): no event source (FSEvents, DiskArbitration) is wired to a scan until the broker/worker split of §11.13 exists:** the owner-credential opener (A), descriptor-only reads (B), the sandboxed worker (C), path tools run on a snapshot (D), and a broker that validates the worker's verdict (E). The first spike below is the one the opener depends on.

Daemon skeleton, `EventSource` abstraction + capability struct, FSEvents watcher, DiskArbitration mount watcher, `navctl status`, socket protocol plumbing, container/`.pkg` handling (§6) and decompression-bomb guardrails (§6.2). Feasibility spikes, treated as go/no-go checks rather than assumed:
- **Full Disk Access grant behavior with no app bundle** — confirm whether `navd` can be added to the FDA pane in System Settings as a bare binary/daemon, track the active macOS Tahoe 26.1/26.2 FDA-list bug (§10), document exact steps, and run the per-area coverage probe matrix against real Downloads/Desktop/Documents access.
- Whether `navd`'s FDA grant is a one-time system-wide grant or needs repeating per logged-in user.
- Whether `navctl rules test` (interactive, user-invoked) has meaningfully different TCC exposure than `navd`'s headless background scanning (§10). Measured via `navd scan-once <path> [--json] [--recursive]` (Phase 0b A2), a one-shot self-scan added to `navd` purely to give this spike a headless/root read to observe — **explicitly temporary, not §8's stable CLI surface**, and not a daemon-owned scan service or RPC (§9.1 is unchanged: on-demand scanning is and stays `navctl`'s job, in-process against `nav-core`). Removed once this spike is answered, tracked in the phase-0b plan; if `scan-once` was the only user of `navd`'s `clap` dependency, that comes out with it.
- FDA grant durability across the specific upgrade scenarios in §11.10 (same version reinstalled, new version same identifier, certificate renewal, CLI-only update), measured both ad-hoc and with a stable self-signed certificate, since NAV uses no Developer ID (§13).
- `navnotify` delivery mechanism and final packaging form — bare LaunchAgent vs. minimal agent-style `.app` bundle (§9.2) — and Multi-user/Fast User Switching behavior.
- Homebrew upgrade behavior while `navd` is running, and confirmation that the root-daemon binary (§11.10) resists replacement via a user-writable path.
- FSEvents behavior under high event volume (coalescing, loss/resync).
- Broker/worker claims the design depends on and nobody has run on macOS (threat model §9):
  - An FDA grant still applies after the opener drops to another uid, and to a descriptor passed to a process without the grant (§11.13, A and C).
  - The no-follow descriptor walk (§11.7) behaves the same on the minimum supported macOS (B).
  - The worker can sandbox itself with a custom profile, and `codesign`/`spctl` still work inside it and on a bare clone outside its bundle (C, D).
  - Per-process memory limits are enforceable for the worker (C).
  - Reading a cloud placeholder can be made to fail instead of downloading (B).
  - A user can hard-link a file they cannot read (R2).
  - How a root-initiated `hdiutil attach` treats setuid bits, device nodes and ownership by default (R9, E5).
  - Worker uid (§14): run the worker as a dedicated role account and as the file's owner, and compare. For each: whether it can mount a disk image through DiskArbitration with no login session, whether the removable-volume prompt (#187) blocks or denies it, whether its sandbox can allow the disk-image and DiskArbitration services while staying closed otherwise, and whether the mount comes out with setuid and device files disabled and ownership ignored (§6.2, §11.13).
  - `fs::copy` carries an ACL onto the installed binary, and whether `codesign -f` drops it (E3).
  - `sudo` on stock macOS keeps the caller's `PATH` and clears `TMPDIR` (#157, E5).

**Go/no-go**: `navnotify` delivers without requiring an openable app, or the design explicitly falls back to CLI-only per §9.2; the Homebrew-Cellar-writable-binary attack (§11.10) is confirmed closed; Full Disk Access can be granted to `navd` without an app bundle and the grant UX is documented, or the static-analysis coverage gap in §10 is scoped precisely (which paths are actually affected) rather than left as a vague caveat.

These criteria are cleared on **ad-hoc-signed builds**: NAV doesn't sign with a Developer ID (§13), so 0b uses the ad-hoc signature the toolchain already applies. Everything above is answerable that way: FDA *grantability* to a bare daemon, the interactive-vs-headless TCC distinction, the Homebrew-attack closure (a filesystem-ownership property, not a signing one), and FSEvents robustness. FDA grant **durability across upgrades** (§11.10) is expected to fail ad-hoc, because the ad-hoc identity changes with every build. The spike checks whether a stable self-signed certificate keeps the grant. If neither does, re-granting FDA after a `navd` upgrade is documented as a known gap (§10). It informs the install UX but doesn't block 0b.

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
Quarantine manager (findings bound to identity and digest, acted on with the owner's credentials, §11.7), allow/denylist, config file support ([candidate options](config-candidates.md), including an opt-in to copy a disk image on another volume from the scratch directory so `navctl` can mount it, at the cost of a longer scan; §6.2, #176), ruleset hot-reload + rollback, daemon self-termination detection, event log privacy hardening (redaction, retention), request audit log (§9.1), safe root-daemon installation path (§11.10), `navnotify` install/uninstall, clean uninstall path.

**Phase 4 — Polish / stretch**
`navtop` TUI, ruleset update distribution channel, optional on-device ML scoring layer, optional ESF-backed edition if the entitlement/packaging tradeoff is ever revisited.

---

## 13. Locked Decisions

- **Decompression-bomb limits** — locked, see §6.2 table for the enforced defaults. To become user-configurable via `navctl config` in Phase 3 (ranges not yet chosen), defaults chosen to be generous enough for legitimate large archives while catching genuine bomb patterns; hitting a limit is treated as indeterminate, not automatically malicious (§6.2).
- **Distribution mechanism** — two channels, chosen for minimal install friction: an **install script** (`curl … | sh`, below) and a **Homebrew formula** in a NAV tap (`brew install yatt-ze/nav/nav`; homebrew-core later, once eligible). The script can ship pre-release builds before the formula exists. Binaries are ad-hoc signed, with no Developer ID or notarization. Both channels avoid the quarantine attribute, so they never meet Gatekeeper. A browser-downloaded `.pkg` or `.dmg` would be quarantined and blocked without notarization, so neither is a channel. The privileged `navd` daemon requires a separate, explicit installation step (`sudo navctl service install`, §11.10) rather than relying on `brew services` alone, since the daemon must not execute from a user-writable path.
- **`curl … | sh` is an accepted install channel** and is planned, alongside build-from-source (`git clone && cargo install`, or `brew install --build-from-source` from the tap).
- **Domain-reputation approach** — locked, see §5.6. Local-first by default (`LocalHeuristicProvider`, using precisely-named local-prevalence signals rather than overclaiming registration-age data), with an opt-in `CloudFeedProvider` extension point reserved for a future release.
- **Naming/positioning** — resolved: project is **NAV**, "Not an Anti-Virus."
- **Notification delivery** — locked, see §9.2. `navnotify`, a background-only per-user LaunchAgent, no openable window, opt-out respected end-to-end.
- **Software versioning** — SemVer on one unified workspace version (`[workspace.package] version`, inherited by every crate), so all binaries release as one product. Pre-1.0 while the socket protocol, CLI surface, and config format are unsettled, using the usual pre-1.0 convention: the minor bumps for a release that adds features or changes behavior (a new rule, format, command, or score-moving change), the patch for a release that only fixes bugs. The minor is not tied to the roadmap phase (§12); the phase lives in the roadmap, not the version. Cut a release whenever a meaningful batch of work has landed, not once per phase, so the version reflects the work done. `1.0.0` is reserved for committed stability of the protocol/CLI/config, at or after the Release-Readiness Gate (§13), not merely "it works." Releases are annotated git tags `vX.Y.Z`; the signing identity (`com.nav.navd`) and launchd label stay constant across version bumps, independent of the version (§11.10). Distinct from the design-doc revision in `docs/design.md`'s `**Status:**`, which is a separate document-changelog counter, not the software version.

---

## 14. Open Decisions (Still Not Locked)

- **Scan worker uid** (§11.13). A dedicated role account (a uid boundary against malware running as the file's owner) or the file's owner (no extra account; likelier to be allowed to mount disk images). The user leans against role accounts; the Phase 0b spike runs both (§12).
- **Automatic disk-image mounting: on by default or opt-in** (§6.2). On by default reaches DMGs, the main delivery format, before the user opens them, but the kernel's filesystem code then reads every downloaded image, not only those the user opens.
- **Where behavioural scoring runs** (Phase 2). The correlator and behavioural engine are not placed in §11.13 yet. Settled: anything that parses file content, such as a plist that became persistence-capable, goes through the worker; event metadata may be scored in the broker.
- **Per-user agent as an opt-in deployment mode.** Not ruled out. For users who don't want a root daemon, a per-user agent can feed the same scan worker (§11.13) in place of the root broker, so the confused-deputy problem does not arise. Its guarantee is weaker: malware running as the same user can stop the agent or tamper with its results and record. The root broker is the default (§2). The design keeps the worker's interface independent of who feeds it so this mode stays possible; whether and when to build it is open.
- Whether, and how far, to make `nav-core` cross-platform (§3): Linux as a first-class scan target, perhaps Windows later. NAV itself stays macOS-only until decided. The prerequisite is a platform-aware rule set. A rule that is meaningless on the running OS is left out and adds no gap. A rule that matters for the file but cannot run there still reports one, because hiding it would turn "couldn't check" into "clean" (§10, §11.8). Portable file access must keep the no-follow walk's guarantees (`ScanRoot::open_file`, §11.7: no symlink in any component below the target, regular files only, a non-blocking open), and #170's Unix-only `compile_error!` is lifted last. Tracked in #218.
- Specific cloud domain-reputation API to integrate with `CloudFeedProvider`, once built.
- Exact behavior of `navnotify` under multi-user/Fast User Switching — pending Phase 0b spike.
- Whether the ECH gap (§10) meaningfully changes how much weight network-behavior heuristics should carry in the overall scoring model, once real-world ECH adoption data informs how much traffic it actually affects.
