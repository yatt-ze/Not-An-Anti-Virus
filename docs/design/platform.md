# NAV Design — Platform Integration (§4, §9)

Part of the NAV design document — see [`design.md`](../design.md) for the
document map and section index. Section numbers are global; this file holds §4 and §9.

---

## 4. Event Sources

**Decision: Neither ESF (Endpoint Security Framework) nor the legacy BSM audit subsystem are used.**

- **ESF is out by choice, not by capability gap.** ESF supports notify-only events (it isn't only about `AUTH_EXEC` blocking), so it would materially improve exec/fork attribution and injection visibility even in a non-blocking design. It's excluded because it requires a restricted Apple entitlement (manual approval), a System Extension deployment path, and ties the project's build/release pipeline to Apple's approval process — costs the project doesn't want to take on for v1, independent of the blocking question.
- **BSM audit (`/dev/auditpipe`) is out because it's not viable, not because of a design preference.** Confirmed via Apple's own `auditd`/`audit` man pages: deprecated since macOS 11, **disabled by default since macOS 14 (Sonoma)**, and Apple states it will be removed in a future release, directing developers to Endpoint Security instead. Re-enabling it requires manual `audit_control` file changes, re-enabling a launchd service, and a reboot — incompatible with a default-on, low-friction install. Not used at all, not even as an optional/legacy source.

The architecture is nonetheless built with an abstract `EventSource` interface so ESF *could* be added later without a rewrite, should requirements ever change (see §4.4).

### 4.1 The Five Active Event Sources

| Source | Gives you | Gaps | Entitlement |
|---|---|---|---|
| **FSEvents** | High-coverage file writes/creates system-wide, `com.apple.quarantine` xattr detection | No reliable process attribution; subject to coalescing and event-loss requiring resync under load | None |
| **DiskArbitration** | Volume mount/unmount detection (DMG mounts) | N/A, narrow purpose | None |
| **NSWorkspace** | GUI `.app` launch/terminate lifecycle | GUI apps only, no CLI tools/scripts/subprocesses | None |
| **Polling** (`libproc`/`sysctl`, `proc_pidinfo`) | Process table snapshots (PID/PPID/path), socket table lookups (`PROC_PIDLISTFDS` + `PROC_PIDFDSOCKETINFO`) | Lossy on a fixed interval — misses anything that starts/ends between polls. Mitigated for network specifically by event-triggered lookups (see Packet Capture below) | None |
| **Packet Capture** (BPF/`libpcap` on `/dev/bpf*`, same mechanism as `tcpdump`) | Real-time packet observations; connection attempts and TLS SNI hostname reconstructed on a best-effort basis; sees **raw-socket traffic regardless of which API a process used to open it** | No visibility into QUIC/HTTP3 or ECH-protected ClientHellos (RFC 9849, standardized March 2026 — encrypts SNI even over standard TLS 1.3, see §10); requires building our own bounded multi-segment ClientHello parser (a ClientHello can span multiple TCP segments/TLS records, not just one packet); root launchd daemons are expected to be exempt from macOS's Local Network Privacy packet filter per Apple DTS guidance, but this should be empirically verified per macOS version, not assumed | None — root access to `/dev/bpf*` is sufficient, same privilege level the daemon already runs at |

**Why Packet Capture instead of Network Extension:** `NEFilterDataProvider` requires being packaged as a System Extension hosted by a signed app bundle in `/Applications` — this is an Apple platform requirement with no unhosted path (confirmed: even Little Snitch, doing comparable network monitoring, ships this way). That conflicts with the CLI-only, no-openable-app distribution goal. Passive BPF/libpcap capture gets comparable visibility and hostname parsing without that packaging burden, and as a bonus sees raw-socket traffic that would bypass NE's standard-stack-only visibility.

**Process attribution is best-effort, not reliable, and this must not be overstated.** Attribution works by triggering a `proc_pidinfo` socket-table lookup at the moment a connection-establishing packet is observed, which narrows the race window versus fixed-interval polling — but the packet observation and the process-table lookup are not atomic. Between the two, the connection can close, the process can exit, the file descriptor can be reused, or multiple candidate processes can match. Attribution results carry an explicit confidence level, never a bare PID:

```rust
enum ProcessAttribution {
    ExactMatch { pid: u32, process_start_time: Option<MonotonicTimestamp> }, // socket tuple matched exactly
    Ambiguous { candidates: Vec<u32> },                                       // multiple processes matched
    Unattributed,
}
```

**Policy: an unattributed event is always preferred over a wrongly-attributed one.** The correlator and scoring engine must never force an `Ambiguous` result into a single PID just to produce a cleaner-looking event. Phase 0c's feasibility spike (§12) measures actual attribution accuracy, not just attribution *rate* — a high attribution rate with hidden misattribution is worse than a lower, honest one.

Every source runs in **observe-only mode** — logging, not filtering/blocking — consistent with the non-blocking philosophy. (Packet capture is inherently observe-only; there's no packet-dropping capability being built here.) Captured payload data is bounded and not persisted by default — see §11.9.

### 4.2 Normalized Event Model

All sources normalize into one `SecurityEvent` type before reaching the scoring engine. The scoring engine has no knowledge of which source produced an event beyond a `source` tag used for confidence-weighting, and an `attribution` field that makes attribution *quality* explicit rather than implying every event is equally trustworthy.

```rust
enum SecurityEvent {
    ProcessExec { pid: u32, ppid: u32, path: PathBuf, args: Sensitive<Vec<OsString>>, timestamp: SystemTime, source: EventSourceKind },
    ProcessExit { pid: u32, timestamp: SystemTime, source: EventSourceKind },

    // Named to reflect what FSEvents actually reports: a change was observed at this path.
    // Not a guaranteed one-to-one "process X wrote this file" fact — see §5.3.
    FileSystemChangeObserved { path: PathBuf, pid: Option<u32>, quarantine_xattr: bool, timestamp: SystemTime, source: EventSourceKind },

    // Inferred, not directly observed: packet capture sees packets, not connections.
    // A connection attempt/flow is reconstructed from those packets on a best-effort basis.
    NetworkConnect {
        remote_addr: SocketAddr,
        hostname: Option<String>,          // from SNI parsing; optional evidence — QUIC/ECH block this, see §10
        attribution: ProcessAttribution,    // defined in §4.1 — never a bare PID
        timestamp: SystemTime,
        source: EventSourceKind,
    },
    AppLifecycle { bundle_id: String, pid: u32, event: AppLifecycleKind, timestamp: SystemTime, source: EventSourceKind },

    // Reserved, unused until/unless ESF is added:
    ProcessInjection { source_pid: u32, target_pid: u32, method: InjectionMethod, timestamp: SystemTime, source: EventSourceKind },
}

enum EventSourceKind { FsEvents, DiskArbitration, NsWorkspace, Polling, PacketCapture, NetworkExtension /* reserved, unused */, Esf /* reserved, unused */ }

// Process arguments may contain secrets (tokens, passwords in CLI invocations) and are
// redacted by default in logs/persistence; full args require explicit opt-in config.
struct Sensitive<T> { value: T, redacted_display: String }
```

`args` uses `OsString`, not `String` — macOS process arguments are byte-oriented and not guaranteed valid UTF-8. `process_start_time` (used in `ProcessAttribution::ExactMatch`, §4.1) is a monotonic/boot-relative value where available, not raw wall-clock time — wall-clock can jump (NTP sync, manual changes) in ways that would corrupt identity comparisons.

**Deliberate scope note:** this is a flatter model than a full Observation/Entity/Finding separation (raw sensor output vs. resolved identity vs. scored verdict as distinct layers) — architecturally more correct for a mature product, but heavier than this project needs right now. The naming fixes above capture the important part of that critique (not implying more certainty than a source provides) without the larger restructure. Revisit if the event model outgrows this.

### 4.3 Correlator (Dedup Layer)

Multiple sources will report the same real-world event (e.g., a GUI launch fires both `NsWorkspace` and a `FileSystemChangeObserved`/polling-detected exec for the same PID within milliseconds). A correlation stage sits between ingestion and scoring, merging observations of the same real-world activity, to prevent duplicate scoring/alerts.

**Correlation identity preference order** (most to least reliable):
1. PID + process start time (closes the PID-reuse gap a bare PID match doesn't)
2. PID + executable identity (path + hash)
3. PID + narrow timestamp window (~1-2s) as a last-resort heuristic only, not the default mechanism

Correlation outcomes are explicit rather than binary merge/drop, so provenance is preserved and reprocessing stays possible:

```rust
enum CorrelationDisposition {
    ExactDuplicate,
    SameActivity,
    RelatedActivity,
    Ambiguous,
    Independent,
}
```

```
[5 raw event streams] → [Correlator: identity-based matching, PID+time as fallback] → [Unified SecurityEvent stream] → [Scoring Engine]
```

Building this now (with only 5 sources, none of which are ESF) means the correlator's matching logic is already exercised and trusted before a 6th/7th source is ever added.

### 4.4 Future ESF Slot (Reserved, Not Built)

If requirements ever change (e.g., BSM's removal or a future auth-time-blocking product variant prompts reconsideration):
- `EventSource` trait includes a `capabilities()` call (`real_time`, `process_attributed`, `auth_time`, `injection_visible` booleans) — every current source reports `auth_time: false, injection_visible: false`.
- `ProcessInjection` enum variant exists but is unpopulated by any current source.
- `EventSourceKind::Esf` already exists in the enum, unused.
- Adding ESF later = new source implementing the trait + correlator already handles cross-source dedup via identity matching, not just PID+time. Scoring engine and CLI output formatting do not need to change structurally. Reconsideration would be prompted by measured visibility gaps from Phase 0/2 (§12), not by BSM's removal specifically — that removal is already accounted for as the reason BSM isn't used at all, not a pending trigger.
- Similarly, `EventSourceKind::NetworkExtension` is reserved in case the app-bundle packaging tradeoff is ever revisited — NE would simply populate `hostname`/`attribution` with higher-confidence data on the same `NetworkConnect` variant Packet Capture already produces.

---

## 9. Daemon Communication & Notification Delivery

### 9.1 Daemon ↔ CLI Communication

Local Unix domain socket (e.g., `/var/run/navd.sock`), length-prefixed JSON-RPC-ish protocol. Used for anything that only the daemon owns — live event stream, quarantine state, config, ruleset reload, notification relay — **not for on-demand scans**, which `navctl` runs locally against `nav-core` (§2, §3) whether or not `navd` is installed. Auth via socket file permissions (root + admin group) for connection access; **per-method authorization on top of that** for sensitive operations (`quarantine purge`, `config set`, `rules reload`, `uninstall` should not be treated as equivalent to `status`/`events tail`). Chosen over XPC for easier reuse across future Rust-native tooling (`navtop`, scripting).

Hardening items deferred to Phase 3 (§11): versioned request framing with max frame size, peer credential checks per-method, request audit log with sensitive-argument redaction, protection against socket replacement/symlink attacks at startup.

### 9.2 Notification Delivery (`navnotify`)

**The problem:** `navd` is a root LaunchDaemon with no GUI session — it cannot post directly to Notification Center. But an always-on alert-only monitor needs some way to reach the user without them having to remember to run `navctl events tail`.

**Design: `navnotify` is a background-only per-user LaunchAgent.** No Dock icon, no window, no menu bar item — its only job is to receive verdicts from `navd` over an authenticated local channel and post them via the standard UserNotifications API, so alerts show up correctly attributed to NAV rather than a workaround like `osascript`/"Script Editor." This is consistent with the clarified "no GUI app" constraint (§1): a background agent with no openable interface beyond notifications is in scope; an openable app is not. **The locked constraint is the user-facing behavior ("no conventional application the user opens and operates"), not the literal packaging format** — Apple's UserNotifications framework consistently describes local notifications and actionable responses in terms of an application identity, and the exact form `navnotify` needs to take (a bare LaunchAgent executable vs. a minimal agent-style `.app` bundle with `LSUIElement` set, i.e. no Dock icon/window/Cmd-Tab presence) is an implementation detail for Phase 0b to resolve empirically. Either form satisfies what was actually asked for; don't lock the wrong layer.

```
navd (root, system LaunchDaemon)
  │  verdict crosses medium/high threshold (§7)
  ▼
authenticated local IPC (same socket-auth model as §9.1, scoped to this purpose)
  ▼
navnotify (per-user LaunchAgent, runs in each logged-in GUI session)
  │
  ▼
Notification Center (UserNotifications framework)
```

- **Configurable and opt-out by default respected**: `navctl notify disable` turns this off. When disabled, `navd` does not attempt delivery at all — it doesn't queue notifications the user will never see, it simply stops trying, consistent with "if the user doesn't want notifications, we don't deliver them."
- **Multi-user / Fast User Switching**: `navnotify` runs per logged-in GUI session, not system-wide — a verdict needs to reach whichever session(s) are actually active. Exact behavior here (which session gets notified for a system-wide event vs. a user-specific one) is a Phase 0b feasibility question, not an assumption (§12).
- **One-click quarantine action adds real attack surface — it reuses transport, not risk.** The action handler needs `navnotify` to relay a "quarantine this" request back to `navd` over the same authenticated local channel as §9.1, which limits duplicated infrastructure, but a notification action is still a new privileged request path: a new peer type, a new user-session identity to bind to, and a window between the original alert and the user's click where the target file could change. The request must carry an opaque finding reference and a nonce, never a raw filesystem path, and `navd` must re-resolve and revalidate the original evidence before acting rather than trusting the action payload directly:
  ```rust
  struct NotificationActionRequest { finding_id: FindingId, action: NotificationAction, nonce: ActionNonce }
  ```
- **Not a second general-purpose daemon** — `navnotify` has no scanning, no scoring, no filesystem/network monitoring of its own. It is deliberately minimal: receive a verdict, post a notification, relay an action back. Keeping its responsibility this narrow limits both its own footprint and the review surface a security-conscious user would need to audit.
- **Fallback**: if `navnotify` isn't installed/running (or the feasibility spike in Phase 0b turns up problems with reliable per-session delivery), NAV degrades to `navctl events tail`/logs-only, not a hard failure — the CLI surface is always the ground truth regardless of whether notification delivery is working. This degradation must be visible, not silent: `navctl status` reports a `notify delivery: ok / degraded / disabled` line (§8) so a user relying on notifications has a way to discover a stopped-working session rather than only noticing via logs after the fact.
