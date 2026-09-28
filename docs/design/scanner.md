# NAV Design — Scanner (§5–§8)

Part of the NAV design document — see [`design.md`](../design.md) for the
document map and section index. Section numbers are global; this file holds §5 through §8.

---

## 5. Heuristics Engine

### 5.1 Model

Weighted, multi-signal scoring system (not a single decision tree) — easier to tune, easier to explain individual verdicts, easier to extend incrementally.

**Score policy invariant:** no single generic signal (unsigned status, high entropy, network use, AppleScript use, persistence-path write) may independently push a verdict to a high-severity alert. High-severity requires either two independent signal families, or one narrowly-scoped, high-specificity signal (e.g., a specific known-bad combination, not a broad category). This is a testable requirement for the rule engine, not just a tuning guideline — enforced by the false-positive harness (§11.1).

The engine's current proxy for "independent families" is the `SignalCategory` of each matched signal (two distinct non-informational categories → corroboration). That proxy only holds if a rule's category reflects the *kind* of evidence it actually has: several static rules reading the same bytes must not spread themselves across categories, or one artifact would corroborate itself. Hence static analysis stays inside static categories (`StaticSuspicion`/`ProvenanceConcern`/`TrustReduction`), and `BehavioralConcern`/`TemporalCorrelation` are reserved for the runtime pipeline (§5.3). A stronger explicit evidence-origin/correlation model (distinguishing content vs. metadata vs. signing vs. runtime as first-class provenance, rather than inferring it from category) is the intended successor once the behavioral sources exist — category diversity is a serviceable interim proxy, not the final word on independence.

### 5.2 Static Heuristics (file-arrival / on-demand scan time)

- Mach-O structural anomalies: unusual load commands, suspicious entitlements requested by unsigned binaries, packed/obfuscated sections, high entropy in `__TEXT`. The load-command/entitlement half is the `macho-loader-anomaly` rule (`StaticSuspicion`), built on the `macho` parser's full load-command walk (dylib/rpath paths, code-signature presence, an embedded entitlements plist recovered from the signature's SuperBlob): it flags an `LC_LOAD_DYLIB`/`LC_RPATH` path into a writable/transient location (`/tmp`, `/private/tmp`, `/var/tmp`, `/private/var/tmp`, `/var/folders`, `/private/var/folders` (per-user `$TMPDIR`), `/Users/Shared`, anywhere under `/Users/`, or a hidden directory component — never the normal `@executable_path`/`@loader_path`/`@rpath` relative forms or an Apple system location) — this list is shared with the `launchd-persistence-plist` rule's program-location check so the two can't drift (#39) — and a handful of "exempt me from a platform protection" entitlements (`com.apple.security.cs.disable-library-validation`, `...allow-dyld-environment-variables`, `...disable-executable-page-protection`), weighted higher when the binary is only ad-hoc signed rather than under a real signing identity. Ad-hoc is `CS_ADHOC` set in any CodeDirectory found (slot 0 or one of the 5 alternate slots XNU also accepts, since an attacker can put its only CodeDirectory there) **or** — since `CS_ADHOC` is self-declared by the signer — no non-empty CMS blob backing the signature at all: a real identity signature (Developer ID/Apple) wraps a non-empty `CSMAGIC_BLOBWRAPPER` at `CSSLOT_SIGNATURESLOT`, a hand ad-hoc signature has that wrapper but empty, and a linker signature has none. Entitlements only ever come from inside a code signature, so the distinction that matters is ad-hoc-vs-identity, not signed-vs-unsigned; a slice whose CodeDirectory couldn't be read at all falls back to the real-identity weight rather than assuming the worse case. `com.apple.security.get-task-allow` is scored differently from the other three: Xcode adds it to every Debug build, and a Debug build is always ad-hoc signed ("Sign to Run Locally"), so requesting it on an ad-hoc binary is the ordinary dev-build state, not an anomaly — it only contributes, at the real-identity weight, when the CodeDirectory confirms a real (non-ad-hoc) identity; an ad-hoc or unrecoverable CodeDirectory means it isn't scored, or named in the finding, at all (#37). Both anomalies are corroboration-only and share a capped weight, so the rule alone never reaches the §5.1 high-severity threshold. The entitlements blob sits near the end of the file (in `__LINKEDIT`), exactly where an 8 MiB bounded capture (§3) is most likely to have been cut off — a signed binary with no entitlements *recovered* is only read as "no entitlements" when the capture wasn't truncated; a truncated capture reports `RuleOutcome::NotApplicable` for that half instead of a false-clean read (§10/§11.8), while a real anomaly already found in the load paths still fires. A signature region that was read but whose SuperBlob can't be parsed (bad magic, over 256 blobs) is equally undetermined (`SignatureRegion::Malformed`, #55). A slice carrying a second `LC_CODE_SIGNATURE` load command has no legitimate meaning or documented kernel precedence — rather than guess which one wins, the parser rejects the whole slice as malformed (no image for a thin file; a skipped slice within a fat one) instead of risking the second command silently overwriting the first's entitlements/CodeDirectory facts (#37). A fat/universal binary is judged on **all** its architecture slices, not just the first — the rule walks every slice via `macho::parse_all_slices`, and unions **both** the load-path anomalies and the suspicious entitlement keys across slices: a key requested by more than one slice is weighted once, by the worst (most ad-hoc) of the slices that request it, rather than scored and its text repeated per slice. This keeps a malicious arm64 slice from hiding behind a benign x86_64 one and keeps a universal binary from scoring higher than its thin equivalent just for repeating the same anomaly in every slice; a declared arch slice the parser can't walk at all degrades the rule to `NotApplicable` (and the scan to `Partial`) when no other finding survives, rather than letting a malformed sibling hide behind a clean one (§11.8, #38). A `0xCAFEBABE`-magic file only counts as a fat Mach-O if some declared arch entry's offset points at a real thin Mach-O header — or the read was truncated with an entry past what was captured — which is how a Java `.class` file (sharing the same magic) is told apart; this is deliberately **not** an arch-count cap, since the kernel will run a fat binary with far more bogus arch entries than any real toolchain emits, as long as one slice is real (#46). High/obfuscated-section entropy is the separate `high-entropy-content` rule (§5.1), which scores `__TEXT`'s entropy using the same parser's `text_range`.
- Code-signing status via Security.framework: unsigned / ad-hoc / revoked cert / signed-but-not-notarized. The `unsigned-binary` rule only applies to actual code objects: it checks for Mach-O magic before consulting `codesign`, because `codesign -dv` answers "code object is not signed at all" for *anything* it doesn't recognize — a README, a tarball, a `.pkg` — so its message alone cannot distinguish an unsigned binary from something that was never a binary. Package signing in particular is a xar signature `codesign` cannot read, so without the gate it called even a correctly signed installer unsigned. Notarized status is a *contributing negative signal*, not an automatic benign override — a signed/notarized binary exhibiting genuinely suspicious behavior should still be scoreable.
  Implemented as five rules sharing the Mach-O gate and a `codesign -dv` classification: `unsigned-binary`, `adhoc-signed-binary`, `revoked-code-signature` (`TrustReduction` — a revoked Developer ID cert is a narrow, high-specificity signal under §5.1, not a broad category), `signed-not-notarized`, and `notarized-binary` (`Informational`, negative weight, per the "contributing negative signal" line above). `adhoc-signed-binary` deliberately does not fire on a *linker-signed* ad-hoc signature — every Apple Silicon binary gets one from the linker at build time regardless of provenance, so only a hand-applied ad-hoc sign (`codesign -s -`, no `linker-signed` flag) scores; scoring the automatic kind would flag effectively every locally-built binary, exactly the low-noise regression the §11.1 harness exists to catch. In practice the exemption is narrower than "every locally-built binary": it spares linker/source-built binaries (a from-source `cargo`/`go build`), but Homebrew re-signs relocated bottles ad-hoc *by hand* (`codesign -s -` after patching install names), producing a plain `flags=0x2(adhoc)` indistinguishable from any other manual ad-hoc sign — so `adhoc-signed-binary` does fire on a meaningful fraction of installed Homebrew binaries (≈115 of 372 in a September 2026 real-corpus run). There is no reliable way to tell a Homebrew re-sign from an attacker's manual sign, so this is left as-is and kept low-noise structurally: the signal is corroboration-only — weight 3, never enough to reach `notify` without a second category (§5.1). A real 554-file corpus of Homebrew/Rust/system binaries produced zero non-`no-action` verdicts. `revoked-code-signature` and `signed-not-notarized`/`notarized-binary` only run their respective `codesign --verify`/`spctl -a -t exec` checks against a binary already classified as carrying a real (non-ad-hoc) identity, since revocation and notarization aren't meaningful questions for an unsigned or ad-hoc one. `notarization_from_source` only classifies `Notarized Developer ID` and `(Unnotarized )Developer ID` — an Apple System or Mac App Store source is left unscored, since "notarized or not" doesn't apply to those and guessing would false-positive on every system binary and App Store app.
- Suspicious strings/imports: `dlopen`, `NSAppleScript`/`osascript` references, TCC database paths, Keychain API references
- plist/persistence anomalies: LaunchAgent/LaunchDaemon plists in unusual locations, `RunAtLoad`+`KeepAlive` combinations. Implemented as the `launchd-persistence-plist` rule (`StaticSuspicion` category): it recognizes a launchd *job* (a plist dict with `Label` plus `Program`/`ProgramArguments`) via `nav_core::plist` and scores only anomalies — `RunAtLoad`+`KeepAlive` together, a program path in a transient/hidden location, an inline `sh -c`/`osascript -e` loader that fetches or decodes, a sub-5-minute `StartInterval`, or the job plist itself staged inside an `.app` bundle or on a mounted volume. A well-formed ordinary LaunchAgent scores nothing (§1). This is **purely static** — it makes no claim about which process installed the job; that attribution is §5.3 behavioral work. It is deliberately **not** `BehavioralConcern`: a static rule reads bytes, it does not observe a persistence *event*, and since §5.1 treats each category as an independent evidence family, labelling this behavioral would let a single plist that also trips `suspicious-strings` corroborate itself into a high-severity verdict (NAV-002). `BehavioralConcern` is reserved for `navd`'s runtime pipeline (§5.3).
  - Two location heuristics carry explicit carve-outs, because the naive form of each flagged an entire class of ordinary software at `notify`. `Contents/Library/Launch{Agents,Daemons}/` is Apple's documented home for an app's own `SMAppService`/`SMJobBless` helper, and `RunAtLoad`+`KeepAlive` is that helper's ordinary configuration — so it is the *installed* location for a bundled job, not staging, and does not score. Likewise a hidden program directory is only an anomaly when it isn't a per-user tool root: `~/.local`, `~/.cargo`, `~/.nvm` and peers are where `pipx`, `cargo install` and nvm legitimately put binaries. The tool-root exemption is positional — it applies only directly under a home directory, so `/Applications/X.app/.cargo/evil` still scores. Both are pinned by benign fixtures.
- Script payloads: shell/AppleScript/`.command` files with obfuscation, base64 payloads, curl-pipe-to-shell patterns
- `.pkg`/xar container structure, distribution script contents, signature — scored by the `installer-script-suspicious` and `unsigned-installer-package` rules (see below), and parsed as a container format alongside Mach-O (same "safely parse attacker-controlled input" work). Implemented as `nav_core::xar` over `nav_core::inflate` and `nav_core::cpio`: the 28-byte header, the zlib-compressed TOC, and a bounded walk of the TOC's XML **tree** (a nested `.pkg` is a `<file type="directory">` with children, so §6.2's recursion-depth ceiling applies here, and entries are identified by full path since names repeat across levels). Reading the install scripts means going through the heap, not the TOC: they are a gzip stream wrapping an odc cpio archive. Only the named metadata entries (`PackageInfo`, `Distribution`, `Scripts`) are read back — never `Payload`, which has the identical shape and is deliberately left to Phase 0b (§6.1). The TOC's `encoding` attribute is not trusted: its labels are backwards in practice, so decompression dispatches on the leading bytes. `unsigned-installer-package` counts a package as signed only when the TOC has a `<signature>` that is a direct child of `<toc>` with an `offset` and a non-zero `size` whose heap range lies inside the whole archive (the true file length, not the held prefix); validity is not checked. A nested `<signature>`, a bare one, or an out-of-range one is treated as unsigned, since a bogus signature claim is itself worth flagging (#40).

**Entropy is scored structurally, not whole-file.** High entropy is a suspicion signal only *within a Mach-O `__TEXT` section* (packed/obfuscated code) or *embedded in a script/text file*. On an opaque non-Mach-O binary — a compressed archive, an image, encrypted data — high entropy is expected and is not scored, since treating whole-file entropy as suspicious flags ordinary downloads and works against the §1 low-false-positive-rate priority. The `__TEXT` location relies on a bounded, dependency-free Mach-O parser (thin and fat/universal) that parses attacker-controlled input under the §3/§11.9 discipline (no panics, no unbounded reads, every offset bounds-checked).

For a script/text file, whole-content entropy only catches raw binary appended to the script — base64's 64-symbol alphabet caps whole-content Shannon entropy at 6.0 bits/byte, below the 7.0 threshold, so an encoded payload can never trip that check regardless of what it decodes to. `high-entropy-content` therefore also scans for a maximal base64-alphabet run of at least 1024 characters, decodes it with a small bounded hand-written decoder (`nav_core::base64`, shared with the plist `<data>` reader; no new dependency, §3/§11.9 discipline: no panics), and scores the *decoded* bytes' entropy once decoded length is at least 768 bytes — but at weight 8, not 15: unlike the whole-content/`__TEXT` cases, a script embedding a compressed or encoded payload as base64 is common in benign software (installers, bundlers), so this alone must stay below Notify and needs a second signal to reach it. Every candidate is examined — content is already capped at 8 MiB and each candidate's decode is bounded by its own length, so there is no separate work cap to hide a payload behind. Run-finding treats `=` as a run byte only as genuine trailing padding: one followed by more alphabet bytes (an unquoted `P=<payload>` shell assignment) ends the run there instead of being read as malformed padding that silently decodes to nothing.

A multi-line run is split into candidate *blocks* rather than judged as a single all-or-nothing candidate: consecutive lines merge into one block if they either share one exact width of at least 16 characters (`base64 -b 32`-style uniform wrapping) or are all individually at least 48 characters wide regardless of exact width (wrapping that varies by a column or two — real wrapping otherwise uses 64/76-column lines), optionally followed by one shorter final line (the wrap remainder); a line that fits neither pattern is its own single-line candidate instead. This means a wordlist or dictionary's one-token-per-line text (every character coincidentally in the base64 alphabet, joined across lines since a line break inside a run doesn't end it) can't fuse into one fake giant candidate and fire on ordinary word/password lines — its short, uneven lines never form a block. It also means the reverse doesn't happen: a genuinely wrapped payload sitting right next to an unrelated short line — a blank MIME separator, a heredoc terminator word — still forms its own correct block and isn't blinded by what's adjacent to it, since each block is delimited on its own terms rather than requiring uniformity across the *whole* run.

A run claimed as an ordinary data-URI/PEM carrier by the text before it (`;base64,`, or a `-----BEGIN ` line found by looking back up to 8 header/blank lines) is skipped only once a candidate's own *decoded* bytes back that claim up — a data URI's decoded bytes must start with its mime's known magic (png/jpeg/gif/webp/woff/woff2/pdf/zip/gzip); PEM/PGP armor must decode to a DER SEQUENCE, an OpenPGP packet tag, or carry a `Proc-Type: 4,ENCRYPTED` header. The carrier is decided once per run, from the first candidate long enough to decode meaningfully, and applied to every candidate in it — not just the one nearest the claim text — so a spoofed prefix in front of an unrelated payload no longer suppresses it, and a genuine carrier re-wrapped into multiple blocks doesn't leak past its first one. Base64 of plain text (e.g. an encoded shell script) decodes to *low* entropy and is deliberately not this rule's signal; that encode-then-hand-to-an-interpreter shape belongs to the string-marker rule (§5.2, issue #35), not this one.

### 5.3 Behavioral Heuristics (from the unified event stream)

Each item below is tagged with its actual coverage confidence given the event sources in §4 — this replaces treating all behavioral detections as equally dependable.

- **Persistence-path changes** (LaunchAgents/Daemons, cron, login items) — **high-coverage on detection, best-effort on attribution**. FSEvents reliably watches the relevant directory trees under normal operation (subject to its own coalescing/loss-and-resync behavior), so *that something changed* is well-observed. *Which process caused it* is a separate, weaker inference — do not conflate the two in scoring or in `rules test` output. Distinguish, as separate facts rather than one signal: a file created in a persistence directory, an existing plist modified, plist content becoming persistence-capable, and the item actually being loaded/executed — these are not the same observation.
- **Network behavior**: connections to raw IPs on unusual ports shortly post-exec, lexical/DGA-pattern hostnames (via packet-capture SNI parsing), beaconing periodicity — coverage is **opportunistic, not reliable**, bounded by what §4.1 already states: standard TLS-over-TCP ClientHellos can be parsed when captured and reconstructed successfully; QUIC/HTTP3 and ECH-protected handshakes (RFC 9849) are invisible to this source regardless of attribution quality.
- **Ransomware pattern**: rapid sequential file renames/writes with rising entropy across user directories — reframed as **file-change-burst detection with post-hoc process correlation**, not attributed "ransomware detection." FSEvents gives reliable burst/entropy signal; which process caused it is inferred, not observed directly.
- **Privilege escalation patterns** (`do shell script with administrator privileges`, sudo invocation patterns) — **best-effort**, depends on catching the relevant process via polling or NSWorkspace; short-lived invocations can be missed.
- **Living-off-the-land**: legitimate signed binaries (`osascript`, `curl`, `bash`, `python3`) spawned by unusual parent processes — **best-effort/opportunistic**. Polling at a 1-2s interval will miss short-lived children in a chain like `app → osascript → sh → curl` if they complete between samples. Coverage comes from whatever artifacts they leave behind (files written, network connections held open long enough to be polled/captured), not dependable process-tree visibility.
- **TCC/permission probing** (repeated failed access attempts to Contacts/camera/mic/Full Disk Access) — **moved to experimental/future**, not a v1 detection claim. None of the current event sources observe TCC denial events directly; this would need a dedicated, currently-unidentified telemetry source to implement honestly.

### 5.4 Scoring & Confidence Weighting

- Each signal contributes a weighted score toward an aggregate, grouped into categories (static suspicion, provenance concern, behavioral concern, temporal correlation, trust reduction) rather than one flat additive list — this keeps any single category from dominating a verdict.
- **Source and attribution confidence matter, not just signal type** — a `NetworkConnect` with `ProcessAttribution::ExactMatch{..}` is weighted differently than one with `ProcessAttribution::Ambiguous{..}` or `Unattributed`.
- Interaction terms matter more than solo flags: e.g. `unsigned` alone contributes a small score; `unsigned + persistence-write` contributes substantially more; `notarized + suspicious behavior` does not get a blanket benign override.
- No default action above "alert" without explicit user opt-in (see §7 Verdict/Alert Tiers).

### 5.5 `navctl rules test` Transparency Output

Every scan surfaces the full signal breakdown, not just a final score:

```
$ navctl rules test ./suspicious.app
Threat score:        78/100
Evidence confidence: Medium
Scan completeness:   Complete

Signals matched:
  [+18] unsigned + launch-agent-write     binary is unsigned AND writes to ~/Library/LaunchAgents/com.sync.helper.plist
  [+15] obfuscated-strings                high-entropy string blocks in __TEXT (entropy: 7.2)
  [ -2] interactive-user-launch           spawned from Finder (informational only — not a strong trust signal; Finder-launched is common for both benign and trojanized software)

Attribution:
  Persistence change: process unattributed

Recommendation: notify + suggest quarantine (no auto-action without opt-in)
```

This is an illustrative target. The engine today emits one signal *per rule* (e.g. `launchd-persistence-plist`, `high-entropy-content`), not the fused cross-rule terms shown above (`unsigned + launch-agent-write`) — a combined "unsigned binary AND a persistence-plist sibling in the same bundle" signal is the §5.4 interaction-term work, still to come.

A scan is `Complete` only when the whole object was actually examined. Reading that stops short of the whole file — the 8 MiB bounded content read (§3), or a container member whose extraction hit a §6.2 limit — yields at most `Partial`, never `Complete`, so relevant content placed past the read boundary is never mistaken for absent. That is decided centrally from the context's truncation flag, with a per-rule opt-out (#45). A truncated result is `Partial` unless every rule that ran declares, for that file, that its result doesn't depend on the unread bytes (`Rule::covers_truncation`). A rule may declare that because it doesn't read content (e.g. a `codesign`/`spctl` check on the file itself). It may also declare it because it read what it needed past the prefix through the scan's own file handle (`ScanContext::read_at`/`for_each_window`, §11.7), in which case, when a read fails, it returns `NotApplicable` or — to keep a finding it already made — records the failure (`ScanContext::mark_stream_failed`) so its `covers_truncation` returns `false`; `scan_context` therefore calls `covers_truncation` after `evaluate`. The default is `false`, so a new rule keeps the conservative behaviour until it is checked. Today the codesign family, the quarantine-attribute check, `launchd-persistence-plist` (unless the content could be a plist) and the package rules (unless it's a xar archive) cover truncation without reading further. `suspicious-strings` streams the whole file, `high-entropy-content` streams a Mach-O's whole `__TEXT,__text`, and `macho-loader-anomaly` reads each slice's header, load commands and code signature by offset, with caps on load commands (2 MiB), signature (16 MiB) and total ranged reads (64 MiB) per file. Files over the 512 MiB streaming limit, `.pkg` archives and scripts larger than the prefix still come out `Partial`.

`--json` output mirrors this structure (score, matched signals with id/weight/description, recommendation) rather than being a separate schema, plus a top-level `schema_version` (currently `1`, NAV-008) so scripts can detect a future breaking change before it surfaces as a parse error — since §8 promises `--json` everywhere and this is the command most likely to get scripted against.

`Recommendation` is only action-safe when `Scan completeness` reads `Complete` — a `Partial`/`Indeterminate` result must not be acted on as if it were, so a caller reading a `ScanResult` gates on `ScanResult::is_actionable()` rather than `recommendation` alone (NAV-005). The §8 exit code is a report, not an action: a partial result that reached `Notify` or higher still exits `1`/`2`, and `is_actionable()` still gates anything automatic.

### 5.6 Domain Reputation (Local-First, Cloud Opt-In)

For hostnames obtained via packet-capture SNI parsing (§4.1), reputation scoring is structured behind a trait so the default stays fully local and offline:

```rust
trait DomainReputationProvider {
    fn score(&self, hostname: &str) -> ReputationSignal;
}
```

**Default: `LocalHeuristicProvider`** — no network calls, no third-party data dependency:
- Lexical/DGA-pattern scoring: character-bigram improbability, label entropy, consonant-run length, digit-ratio in hostname labels — catches algorithmically-generated C2 domains without needing a blocklist.
- **Local first-seen/prevalence tracking**, named precisely: `locally_first_seen_domain`, `low_local_prevalence`, `recent_first_observation`. This answers "when did this Mac first observe this domain," which is a real, useful signal (a brand-new-to-this-machine, high-entropy domain contacted immediately post-exec is meaningfully more suspicious than one seen for months) — but it is **not** domain-registration-age data, and must not be labeled `newly-registered-domain` in code, rules, or `rules test` output. That stronger, more specific claim requires a data source with actual registration information (WHOIS/RDAP-derived or similar), which the local provider does not have. If a cloud provider with that data is ever added, `newly_registered_domain` is reserved for it specifically.
- TLD weighting is included as a very weak contextual signal only — it's externally curated knowledge (which TLDs skew toward abuse) shipped in the ruleset rather than downloaded dynamically, but it's still someone else's classification, it goes stale, and entire TLDs host large amounts of benign content. Per the §5.1 invariant, **a TLD classification alone can never affect the alert tier** — it may only shift a score when paired with a lexical anomaly or low local prevalence.

**Optional: `CloudFeedProvider`** (disabled by default, explicit opt-in) — reserved for a future release once a suitable free/low-cost domain-reputation API is identified. Explicitly gated behind opt-in because it's a real privacy tradeoff: enabling it means hostnames the machine connects to leave the device.
- Batched and cached queries, not a live lookup per connection, to limit both rate-limit exposure and the volume of hostnames actually transmitted.
- Never gates core functionality — `LocalHeuristicProvider` must remain fully sufficient on its own.
- Config/docs must state plainly what leaves the device when enabled.

**Philosophy precision:** "no signature feed" means NAV does not depend on continuously-downloaded malware-hash signatures for its core detection. It does not mean zero externally-curated data of any kind — the TLD list and an eventual opt-in cloud reputation provider are both externally curated context that supplements, but never replaces, local heuristic analysis.

### 5.7 ML Layer (Deferred)

Not part of v1. Once enough labeled telemetry exists, a lightweight on-device classifier (e.g., gradient-boosted trees over extracted static features) could replace/augment hand-tuned weights. Hand-crafted heuristics are sufficient for v1 and avoid a training-data cold start.

### 5.8 Directory and `.app` Bundle Targets

`navctl scan` and `navctl rules test` accept a file, a directory, or a macOS `.app` bundle, and both resolve it the same way (`nav_core::scan_target`) so the two commands can never disagree on what a target means — `scan` renders the result tersely, `rules test` renders the full breakdown, but the underlying per-file scan set is identical. (Before this was unified, `rules test` passed the directory path straight to the file scanner, the read failed, and the resulting all-`NotApplicable` scan was rendered as "no action (clean)" — the "couldn't check" → "clean" collapse §10/§11.8 forbid.)

- **File:** scanned as itself.
- **Directory:** every file under it is scanned — recursively only with `--recursive` (both commands take the flag; both default off). Traversal is sorted for deterministic output (§11.1) and does not follow directory symlinks (traversal-cycle and scan-escape hazard).
- **`.app` bundle:** a directory named `*.app` containing `Contents/`. Scanned as **one logical unit** regardless of `--recursive`, because a bundle is inherently nested and a trojanized `.app` commonly hides its payload in `Contents/Resources/` or a helper tool rather than the main binary. The main executable is resolved from `Contents/Info.plist`'s authoritative `CFBundleExecutable` key, read via the bounded plist reader (`nav_core::plist`, §11.9), and only when that is missing/unreadable/malformed/keyless does resolution fall back to the `Contents/MacOS/<bundle-name>` naming convention (or the sole file in `Contents/MacOS/` when the name doesn't match). The `CFBundleExecutable` value is reduced to its final path component before use, so a hostile key like `../../elsewhere` can't point resolution outside `Contents/MacOS/`. A bundle whose executable can't be resolved either way is still fully scanned.

**Verdict aggregation:** a directory/bundle verdict is the *worst single file's* — per-file scores are never summed, so a bundle with hundreds of inert files and one suspicious script scores like that script, not higher. `rules test` prints the worst file's full signal breakdown plus a one-line-per-file roll-up (main executable marked), preserving §5.5 transparency for every member. An unreadable or empty directory/bundle target exits `3` (indeterminate), never `0`.

**False-positive control:** the primary defenses are unchanged — the score thresholds and the §5.1 single-category cap already stop a low-scoring member from alerting. On top of that, a narrow fixed set of compiled bundle resources that cannot carry an executable payload is traversed but **not scored**: `Info.plist`, `PkgInfo`, `_CodeSignature/`, `.nib` / `.car` / `.strings` / `.icns` / `.xcprivacy` files, and `.lproj` / `.storyboardc` / `.momd` directories. Anything that could plausibly hold code — scripts, dylibs, nested helper apps, plists other than `Info.plist` — is still scored. A benign `.app` fixture in the FP harness (§11.1) locks in that a well-formed bundle stays clean.

---

## 6. Container Handling (DMG / ZIP / PKG) — Non-Invasive Policy

**Core principle (quotable, for docs/positioning):** *the daemon never opens a container the user hasn't either opened themselves or explicitly asked it to open.*

### 6.1 Passive Path (no self-mounting)

- DMG mounts detected via **DiskArbitration** (`DADiskAppearedCallback`), not proactively mounted.
- **Correction from v0.1:** mounting a volume does *not* generate FSEvents write events for files that already existed on it — those files aren't newly created by the mount operation, so the earlier "treated as freshly-arrived files" framing was wrong. Instead, on a `DiskArbitration`-observed mount of a user-mounted volume: schedule a **bounded metadata inventory** — enumerate top-level `.app`, `.pkg`, `.command`, and executable objects, read signatures/metadata. Do not recursively traverse arbitrary document trees by default (this stays consistent with non-invasiveness even though the user already mounted the volume — reading everything on it isn't automatically justified just because reading *something* is). Full recursive traversal is available via explicit `navctl scan /Volumes/... --full`.
- Archive extraction (Finder, `unzip`, etc.) produces ordinary file-write events under the extraction target — this part was correct in v0.1 and needs no change; the existing FSEvents write-monitoring pipeline covers it natively since extraction genuinely does write new files to disk.
- `.pkg` container metadata (xar structure, signature, distribution script contents) can be statically analyzed pre-execution without opening it. This is distinct from **payload** inspection — see below.

### 6.2 Active Path (explicit user command only)

Triggered only by `navctl scan` / `navctl rules test` invoked directly by the user against a container file.

- **Read-only, private scratch mount:** `hdiutil attach -readonly -nobrowse -mountpoint /private/var/navd/scratch/<uuid>` — kept out of Finder/`/Volumes/` visibility.
- **Archives extracted to scratch space**, never into the user's real filesystem.
- **`.pkg` payload scan (distinct from metadata scan)**: bounded extraction into scratch space, since inspecting the actual payload contents (versus just xar TOC/signature/scripts) normally requires decompression. Metadata-only scanning is what happens passively/pre-execution; payload extraction is explicit-command-only, same as DMG/ZIP handling.
- **Detach/cleanup immediately** after scan completes (success or failure).
- **Bounded recursion** for nested containers (archive-in-dmg-in-pkg), with limits that are user-configurable in `navctl config` but ship with sane defaults:

| Limit | Default | Configurable range |
|---|---|---|
| Recursion depth | 4 | 1–10 |
| Total extracted size | 2 GB | 100 MB – 20 GB |
| Single extracted file size | 500 MB | 50 MB – 5 GB |
| Extracted file count | 50,000 | 1,000 – 500,000 |
| Wall-clock time per scan | 60s | 10s – 600s |
| Compression ratio (extracted:compressed) | 300:1 | configurable |

  Hitting *any* limit halts extraction. **This does not automatically imply the container is malicious** — legitimate archives (large datasets, highly repetitive text/scientific data, big installers) can genuinely exceed these defaults. The result is recorded as `scan-halted: extraction-limit-exceeded`, scan completeness `partial`, security implication `indeterminate` — a small, non-independent contextual signal (consistent with the §5.1 invariant that no single generic signal alone triggers high severity), not a `possible decompression bomb` finding. That stronger framing is reserved for cases where multiple bomb-like properties stack (e.g. absurd ratio *and* file count *and* depth all hit simultaneously).
- **Startup sweep:** daemon clears any scratch directories left behind by a killed/crashed prior process on every boot, so orphaned mounts/extracted files can't accumulate.

---

## 7. Verdict / Alert Tiers

| Confidence | Default action |
|---|---|
| Low score | Log only (visible via `navctl events tail` / logs), no interruption |
| Medium score | Notification Center alert, file left in place, one-click quarantine offered |
| High score | Notification alert, quarantine strongly suggested, still requires confirmation unless auto-quarantine opted in |
| User-opted-in auto-quarantine | Only tier that acts without confirmation, and only because the user explicitly enabled it in config |

No default action is ever silent/unconfirmed. This tiering is the concrete implementation of the "alert-only, treats user as adult" philosophy — keep it consistent across CLI, TUI, and notification UX.

Every verdict retains the ruleset version, engine version, and score-at-evaluation-time it was produced under, so rollback (§11.2) and later explanation stay reliable even as rules change.

---

## 8. CLI Surface (`navctl`)

```
navctl status [--resource-usage]      # reports notify delivery: ok/degraded/disabled AND per-area protected-path coverage: verified/degraded/unknown
navctl setup fda                      # explicitly user-invoked; opens System Settings + reveals navd binary in Finder. Never run automatically.
navctl service install                # install navd as a root LaunchDaemon and bootstrap it (needs root); see §11.10
navctl service uninstall              # remove navd and its artifacts (needs root), best-effort/zero-residue; see §11.10
navctl service status                 # report install state: which artifacts are present + the launchd job status
navctl scan <path> [--recursive] [--json] [--quick|--full]
navctl rules test <path> [--recursive] [--json]   # full signal breakdown (file / dir / .app bundle, §5.8), dry-run, no action taken
navctl rules list
navctl rules reload
navctl rules rollback                 # revert to previous ruleset if update misbehaves
navctl events tail [--min-score N] [--signal exec,network] [--json]
navctl quarantine list / restore <id> / purge <id> --force
navctl allowlist add <hash|path> --reason "..."
navctl denylist add <hash>
navctl config get/set <key> <value>
navctl logs [--since 1h] [--grep ...]
navctl notify [enable|disable|status]  # opt-out control for navnotify delivery, see §9.2
navctl uninstall                      # full clean removal, see §11
```

`service uninstall` is the daemon-lifecycle teardown of exactly what `service install` created (§11.10), driven off the single install manifest; the top-level `navctl uninstall` is the Phase 3 umbrella full-product removal (§11) that subsumes it once quarantine/config/allowlist state also exists.

Design principles: `--json` everywhere for scriptability, versioned via a top-level `schema_version` field (currently `1`) so a future breaking change bumps it instead of silently reshaping what scripts parse; config mirrored in `~/.config/navctl/config.toml` (user) and `/etc/navd/config.toml` (daemon) for reproducible/version-controllable setups.

**`ScanResult`'s presentation is canonical in `nav-core`, not duplicated per binary.** The `schema_version` envelope and the exit-code mapping below live in `nav_core::presentation` (Phase 0b A2) so every binary that renders a verdict — `navctl` today, `navd` for its Phase 0b A2 `scan-once` spike instrument (§12) — emits the identical contract. This is a deliberate, small widening of `nav-core`'s charter beyond scoring alone, recorded here rather than left as silent drift.

**Exit codes distinguish completeness from verdict**, not just clean/malicious — a partial scan (e.g. a decompression-bomb limit hit, §6.2) must never return the same code as a complete clean scan, since those mean very different things to a script consuming the exit status:

| Code | Meaning |
|---|---|
| 0 | No significant findings, scan complete |
| 1 | Suspicious |
| 2 | High risk |
| 3 | Nothing flagged, but the scan was indeterminate or incomplete (e.g. scan halted, evidence insufficient) |
| 4 | Operational error |

A finding outranks incompleteness; incompleteness only ever overrides a clean result (#34). Per file, a result that scores `Notify` or `NotifyAndSuggestQuarantine` returns `1` or `2` whatever its `ScanCompleteness`, and a `NoAction` result short of `Complete` returns `3`, never `0`. Content past a read boundary can only add weight, because the only negative-weight rule (`notarized-binary`, −3) asks `spctl` about the file itself. `Partial` also arises when a rule returns `NotApplicable`, though, and that includes `notarized-binary` itself (container-extracted bytes, `spctl` failing, non-macOS). So a partial score can overstate by at most 3. That errs toward alerting, never toward a false clean, which is the acceptable direction for an alert-only tool. Across a directory/bundle, the code is the most severe per-file code in the order `2` > `1` > `3` > `0` (not numeric order), and a target whose coverage was cut short — a §11.12 scan-budget ceiling, or a subdirectory it couldn't read partway through (permission denied, a race) and skipped rather than aborting — is raised from `0` to `3`. Either way an incomplete scan never returns `0`, applied uniformly across `navctl scan`, `navctl rules test` and `navd scan-once`. Target-level gaps also print a partial-coverage warning on stderr naming what was missed; a per-file `Partial` shows only in that file's `completeness`. The cost is that `1`/`2` no longer say whether the scan was complete. Per-file `completeness` is in every `--json` object, but target-level coverage reaches `--json` only for `navctl rules test`; `navctl scan --json` and `navd scan-once --json` report it on stderr only (#51). Ranking incompleteness first would hide a high-risk verdict behind any ordinary file over the 8 MiB read cap (§3), which almost every real directory contains. The named target *root* being unreadable is a different case, unchanged: an operational error (`4`), since there's nothing to traverse or report partial coverage over.

**`navtop`** (phase 2, optional): `htop`-style live TUI dashboard — event stream, daemon resource usage, quarantine queue, drill-down into `rules test`-style breakdowns.
