# NAV Design — Gaps & Cross-Cutting Requirements (§10–§11)

Part of the NAV design document — see [`design.md`](../design.md) for the
document map and section index. Section numbers are global; this file holds §10 and §11.

---

## 10. Explicitly Out of Scope / Known Gaps

- **No auth-time execution blocking** — by design, not a limitation to fix.
- **No process-injection/code-injection detection** (`mmap`-into-other-process, `task_for_pid`, `ptrace` tampering) — main capability gap versus ESF. Acceptable given threat-model focus (commodity malware + infostealers, not APT-grade).
- **Process exec/fork attribution is best-effort, not comprehensive.** Without ESF or BSM (both excluded, see §4), short-lived processes between polling intervals and non-GUI process chains are not reliably observed. This is the most significant honesty requirement in the whole document — do not let CLI output, documentation, or scoring confidence imply stronger process-tree visibility than actually exists.
- **TCC/permission-probing detection is not implemented in v1** — no current event source observes it; listed as experimental/future only.
- **NAV's own static-analysis coverage may be degraded by Full Disk Access requirements.** TCC restricts access to protected user-data locations (Desktop, Documents, Downloads, Mail, and parts of `~/Library`) regardless of privilege level — root does not bypass this. `navd` opening files under these paths for Mach-O/string/entropy analysis likely needs Full Disk Access granted explicitly via System Settings. FDA is the one TCC scope with no consent-prompt mechanism at all — it can only be added manually via the FDA pane, which is actually the more viable path for a headless daemon than Files & Folders-style prompts (those require a UI session TCC can attribute to a requesting app, which `navd` doesn't have). Never triggered automatically: `navctl setup fda` is a separate, explicitly user-invoked command (opens the correct System Settings pane and reveals the `navd` binary in Finder to speed up the manual add) — it is not run as a side effect of `navctl service install` or any other command the user didn't ask for, consistent with the non-invasive philosophy in §1.

  **Known active platform risk, not just a theoretical edge case:** as of macOS Tahoe 26.1/26.2 beta, there are confirmed, ongoing reports (Trellix, engaged directly by Apple DTS) of CLI/daemon binaries failing to appear in the FDA list at all after being added via drag-and-drop — a bug affecting exactly the mechanism `navctl setup fda` depends on, currently unresolved. This isn't hypothetical: it's happening to comparable tools right now. Phase 0b (§12) must track this rather than assume the manual-grant UX works as designed on every macOS version.

  **The check itself must not overclaim certainty.** There is no general supported API to determine whether FDA has been granted — Apple's own guidance is to spot-check the actual paths the product needs, using operations as close as possible to real usage, since even a failed read doesn't uniquely mean "FDA absent" (it could equally mean the path doesn't exist, an ACL denied it, the file was transiently unavailable, or the probe itself stopped being representative on a given macOS version). Accordingly, `navd` runs **a small matrix of per-area probes**, not a single canary, and reports each independently rather than collapsing to one boolean:

  ```rust
  enum ProtectedCoverageArea { Downloads, Desktop, Documents, BrowserProfiles, MailData, UserApplicationSupport }
  enum CoverageProbeResult { Accessible, Denied, Missing, Inconclusive, NotTested }
  ```

  `navctl status` reports per-area results (e.g. `Downloads: verified`, `Documents: degraded`, `Mail data: not tested`), not a single `Full Disk Access: granted/not granted` line — that single-boolean framing implies more certainty than any probe can actually establish. Probes read minimal metadata only; they don't retain user content. This state is re-checked periodically, not just at startup, since grants can be revoked at any time, and (see §11.10) may need re-verification after a binary update changes signing identity. **A file that can't be read is not silently skipped — it's reported as explicitly unscanned**, so the gap is visible per-event rather than only discoverable in aggregate:
  ```
  14:32:01  NEW FILE  ~/Downloads/installer.pkg  [NOT SCANNED: Full Disk Access not granted]
  ```
  Worst case without a grant: exactly the directories malware most commonly lands in (Downloads, Desktop) get visibly-flagged-as-unscanned static-analysis coverage, not silently weaker coverage. `navctl rules test` (on-demand, user-invoked from an interactive Terminal session) may have meaningfully different TCC exposure than `navd`'s automatic background scanning — an interactive process has a real UI attribution chain a Files & Folders prompt can attach to, or may inherit whatever the invoking terminal has already been granted — so on-demand scanning of a specific file could plausibly work even for a user who never grants `navd` FDA at all. This distinction is unconfirmed and is a Phase 0b feasibility question (§12), not a Phase 3 polish item, alongside whether the grant is system-wide (tied to `navd`'s code identity) or needs repeating per logged-in user.
- **Network hostname visibility is opportunistic, with named gaps**: NAV parses plaintext SNI from TLS ClientHellos it successfully captures and reconstructs. It does not recover the hostname for QUIC/HTTP3, for non-TLS protocols, for direct-IP connections, or for **ECH-protected connections** — Encrypted Client Hello (RFC 9849, standardized March 2026) encrypts the ClientHello, including SNI, even over otherwise-standard TLS 1.3, and adoption is expected to grow. This is a meaningfully different gap from QUIC — it affects traffic that would otherwise look like ordinary parseable TLS.
- **Fileless techniques** (memory-only payloads, `eval`'d scripts never written to disk) are not covered — rarer on macOS, explicitly out of v1 scope.
- **Daemon self-defense** is minimal by design choice — no kernel-level tamper resistance. Bare minimum: detect and surface unexpected daemon termination to the user on next launch (`launchd KeepAlive` + notification), not full anti-tamper hardening. **This is a conscious tradeoff worth stating plainly given the stated threat model**: Atomic-Stealer-class infostealers (§1's named primary threat) commonly include basic AV/EDR discovery and kill-attempts as standard tradecraft, so a motivated sample may detect and terminate `navd`. v1 accepts this and relies on the after-the-fact termination alert rather than resisting it — full anti-tamper hardening is a Phase 4+ question, not a v1 gap being overlooked.
- Naming/positioning should avoid overclaiming — "heuristic behavioral monitor" framing, not "virus protection," given the above gaps.

---

## 11. Cross-Cutting Requirements (Not Yet Designed In Detail)

### 11.1 False-Positive Evaluation Harness

Now targeted for Phase 0a, not Phase 1 (see §12). Start small (e.g., ~20 known-benign fixtures, ~10 synthetic suspicious fixtures, a malformed/fuzzed-input corpus) and expand continuously, rather than waiting for a large corpus before starting. Track more than pass/fail: final score, matched rule IDs, runtime, memory, files traversed. A rule change should fail CI if it pushes a known-benign sample over the alert threshold, introduces an unexpectedly high-severity signal, or produces nondeterministic output.

**Quantitative acceptance gate (NAV-015).** "Low false-positive rate is the primary success metric" (§1, §12 go/no-go) is enforced as a measured, asserted number, not left as a stated priority: the harness computes and reports the corpus's benign false-positive rate, suspicious signal coverage, verdict mix (high-risk/notify counts), partial/indeterminate count, and per-fixture runtime p50/p95, and asserts two corpus-size-independent criteria — benign false-positive rate is exactly 0%, and suspicious signal coverage is 100% (no deliberately-suspicious fixture scored silently clean). Runtime percentiles are reported but not asserted (environment-dependent, would flake CI). Peak memory stays deliberately untracked: cargo runs every test as a thread in one shared process with one allocator, so a per-fixture number would misattribute concurrent allocation — an honestly-absent metric beats a wrong one, and an honest external benchmark is the right home for it later.

### 11.2 Ruleset Rollback

`navctl rules rollback`, since there's no cloud-based auto-tuning safety net; a bad rule update needs a fast, user-triggerable reversion path.

### 11.3 Resource/Energy Budget

Explicit internal target (e.g., <1% average CPU, low Energy Impact rating in Activity Monitor), tested against, not assumed. `navctl status --resource-usage` should self-report honestly.

### 11.4 Event Log Privacy

Local SQLite log contains file paths, process args (redacted by default, see §4.2's `Sensitive<T>`), possibly hostnames. Needs encryption-at-rest consideration, retention/rotation policy, and access controls so another local user can't read root's log without permission.

### 11.5 Clean Uninstall

`navctl uninstall` must fully remove the LaunchDaemon, the `navnotify` LaunchAgent (§9.2), and all local data with no orphaned processes/files. No System Extension to clean up given the packet-capture approach (§4.1), which simplifies this considerably versus a Network-Extension-based design.

### 11.6 Decompression-Bomb Guardrails

Numerically specified in §6.2 (depth/size/count/time/ratio limits, all user-configurable). Remaining work is implementation, empirical validation of the defaults against real-world large-but-legitimate archives, and override UX.

### 11.7 File-Race (TOCTOU) Handling

A path referenced by an event may be replaced before it's scanned. Scan through an opened file descriptor, capture device+inode identity, and detect/record if the underlying file changed between observation and scan.

**Implemented for the path-based external checks (NAV-003, gate P0.3, from #5).** `ScanContext::load` captures an `ObjectIdentity` (dev, inode, size, mtime) at the moment it reads a file's bytes, and every path-based external check re-stats the path after running and drops the tool's result if that identity changed — the tool would have inspected a different object than the one this scan scored, so its verdict is treated as inconclusive (`None` → the signing rules already fold that into `NotApplicable`), never as clean. This covers all three tools uniformly: `codesign -dv` and `spctl` through their memoized `ScanContext` accessors, and `codesign --verify` (revocation) through the un-memoized `run_object_bound` wrapper over the same guard, so no signing rule reaches disk by a path the guard doesn't cover.

This deliberately *narrows*, not closes, the window, and must not be presented as a complete TOCTOU guarantee. The re-stat runs after the tool, so it catches the ordinary "swap the path and leave it swapped" race — what the shared-context model (one bounded read, no per-rule re-reads) was already relying on informally — but not a swap reverted before the re-stat, and, given `mtime` granularity and inode reuse, not a same-size, same-mtime swap into a reused inode. The real close — scanning content through a held file descriptor rather than re-opening by path, and binding a cryptographic digest of the scanned bytes into the reported result (JSON provenance) — remains for when the privileged daemon acts on verdicts (Phase 0b+), where a wrong-object trust decision becomes a security boundary, not only a correctness bug.

### 11.8 Loss/Degradation Reporting

Every source should be able to report `Lossless / Dropped{estimated} / Coalesced / ResyncRequired` rather than silently dropping events. A monitor that silently loses visibility is worse than one that honestly reports degraded coverage.

### 11.9 Packet-Capture Data Minimization

Captured payload bytes are attacker-controlled input, same category of risk as Mach-O/xar parsing (§3), and also a privacy concern beyond what §11.4 already covers (paths/args/hostnames) — raw packets can contain far more: credentials, internal IPs, arbitrary cleartext payload. Bounded reassembly only, never persisted by default:
```rust
struct CaptureLimits {
    max_bytes_per_flow: usize,
    max_reassembly_flows: usize,
    max_reassembly_bytes_total: usize,
    flow_idle_timeout: Duration,
    handshake_timeout: Duration,
}
```
For SNI parsing specifically: retain only the minimum bytes needed for a bounded ClientHello reconstruction, then release the buffer. The packet parser needs the same fuzzing discipline as the Mach-O/xar parsers (malformed link-layer types, IP fragmentation, TCP option edge cases, deliberately oversized advertised lengths, overlapping retransmissions).

### 11.10 Safe Root-Daemon Installation Path (Homebrew-Specific)

`brew services start` conventionally targets a user-level `launchd` service; `navd` needs a genuine system-level LaunchDaemon (root, BPF access, cross-user file/process visibility). More importantly, a LaunchDaemon plist must **never** point directly at a binary living in the Homebrew Cellar, since that path is writable by the Homebrew-owning user — if an unprivileged user can replace the daemon binary, the next `navd` restart runs their code as root. Split installation:
- `brew install nav` installs `navctl` (unprivileged CLI) normally.
- `sudo navctl service install` is a separate, explicit privileged step that copies the `navd` binary to a root-owned location (e.g. `/Library/PrivilegedHelperTools/`), creates `/etc/navd`, `/private/var/db/navd`, and the scratch/quarantine directories with correct ownership, writes a `/Library/LaunchDaemons/...plist` pointing at the *copied*, root-owned binary (not the Cellar path), and bootstraps the system `launchd` service.
- `navctl service uninstall` reverses this and doesn't touch/change ownership of the Homebrew-managed CLI install.

This preserves Homebrew as the primary discovery/install path (§13) while giving the privileged component its own, more defensible installation story — worth treating as its own small threat model rather than an afterthought. **This also plausibly helps the Full Disk Access grant from §10, though this must be tested, not assumed**: TCC's "responsible code" determination is not fully documented by Apple and can change across macOS versions. A stable path and a consistently-maintained Developer ID code requirement are *expected* to improve grant continuity across `navd` upgrades, but grant survival is an empirical question, not a guarantee — Phase 0b should test at minimum: same version reinstalled, new version with the same identifier and Developer ID, a certificate renewal, and a Homebrew CLI update that doesn't touch the daemon version.

### 11.11 Ruleset/Config Integrity

A tool whose entire purpose is detecting local file tampering has an obvious blind spot if its own ruleset and config files aren't protected against the same thing — e.g. malware writing itself into `denylist`/allowlist as a bypass, or quietly degrading a rule's weight below threshold before the persistence-write heuristic even fires. Baseline requirements: the ruleset file and `/etc/navd/config.toml` are root-owned and root-write-only (`navd` reads them as root; edits go through `navctl config set`/`navctl rules reload`, which are themselves gated by the per-method socket authorization in §9.1, not direct file edits by an unprivileged process). Whether to add an integrity check on load (checksum/signature against the last-known-good state, surfaced the same way a corrupted-state warning would be) is worth deciding during Phase 3 alongside rollback (§11.2), rather than left unaddressed.

### 11.12 Whole-Target Scan Budget

The per-file read cap (§3) and per-container extraction limits (§6.2) bound the work *one* file or archive can cause, but a target that is a directory or `.app` bundle can still expand to an unbounded amount of work through sheer file count, directory depth, or aggregate size — a concern that grows in Phase 0b+ once event ingestion turns arbitrary filesystem activity into daemon workload. `scan_target` therefore enforces a `ScanBudget` (`max_files`, `max_total_bytes`, `max_depth`; conservative defaults, later tunable via `navctl config`). Hitting any ceiling stops the scan and records a structured `BudgetOutcome::Exhausted(limit)` rather than silently dropping coverage: the target is reported with incomplete coverage (`coverage_complete() == false`, surfaced in both human and `--json` output), never as a clean scan, consistent with §11.8's "a monitor that silently loses visibility is worse than one that honestly reports degraded coverage." This mirrors the §6.2 container path, where hitting a limit is `partial`/indeterminate, not automatically malicious. The budget is the target-level counterpart to those local limits, not a replacement for them. Budget exhaustion is uniform across the CLI surface: both `navctl scan` and `navctl rules test` print a partial-coverage warning and return exit code `3` (§8), so a script can't read a truncated traversal as a clean `0`.

The budget governs *traversal*, so a directly named single-file target does not consult it — there is nothing to traverse, and the file is already bounded by the per-file read cap (§3). `max_files`/`max_total_bytes`/`max_depth` apply only when a directory or `.app` bundle expands into a file set.
