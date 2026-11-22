# Config candidates

Inventory of values that could become `navctl config` / `config.toml` options in Phase 3 (§12). Listing an item here is not a decision to make it configurable. Snapshot of main at v0.8.0 (2026-11-19); line numbers drift, so check the source.

## Classes

Each item has one class, by what changing it puts at risk.

| Class | Meaning | Examples |
|---|---|---|
| **Boundary** (security boundary) | Must not be freely user-overridable; changing it can hand an attacker code execution, root writes or a TCC grant | Executable paths, service paths and permissions, the socket |
| **Detection** (detection integrity) | Changing it can let a malicious file evade detection or change its verdict | Verdict thresholds, rule weights, pattern tables, detection heuristics' bounds |
| **Resource** (resource protection) | Changing it affects resource exhaustion and scan completeness (§11.12); raising it lets a hostile input cost more, lowering it makes more scans `Partial` | Archive limits, read caps, timeouts |
| **Privacy** | Changing it changes what NAV records or sends off the device | Cloud lookups, process arguments in logs, log retention |
| **Operational** (operational preference) | Changing it affects convenience or performance only | Output defaults, polling interval, display caps |

## Scan limits

| Option | Value | Location | Controls | Class |
|---|---|---|---|---|
| ScanBudget.max_files | 50,000 | nav-core/src/target.rs:57 | Files scored per target (`--max-files` overrides) | Resource |
| ScanBudget.max_total_bytes | 4 GiB | nav-core/src/target.rs:58 | Bytes read plus bytes decompressed from containers across one target (`--max-total-bytes` overrides) | Resource |
| ScanBudget.max_depth | 64 | nav-core/src/target.rs:59 | Directory recursion depth | Resource |
| ScanBudget.max_entries | 1,000,000 | nav-core/src/target.rs:60 | Directory entries examined | Resource |
| MAX_CONTENT_BYTES | 8 MiB | nav-core/src/context.rs:16 | Per-file prefix read | Resource |
| MAX_RANGE_READ | 16 MiB | nav-core/src/context.rs:19 | Largest single `read_at` | Resource |
| STREAM_CHUNK | 1 MiB | nav-core/src/context.rs:22 | Streamed-read window | Operational |
| MAX_STREAM_BYTES | 512 MiB | nav-core/src/context.rs:25 | Largest file streamed past the prefix | Resource |
| MAX_CAPTURE | 1 MiB/stream | nav-core/src/process.rs:14 | Child-process output kept | Resource |
| MAX_INFO_PLIST_BYTES | 1 MiB | nav-core/src/bundle.rs:16 | Info.plist read cap | Resource |
| plist MAX_DEPTH / MAX_NODES / MAX_DATA_BYTES / MAX_TOTAL_BYTES | 32 / 100,000 / 4 MiB / 16 MiB | nav-core/src/plist.rs:11-21 | Plist parse bounds | Resource |
| MAX_ENTITLEMENTS_BYTES | 256 KiB | nav-core/src/macho.rs:100 | Entitlements plist parsed | Resource |
| MAX_SIZEOFCMDS | 2 MiB | nav-core/src/macho.rs:111 | Load-command bytes | Resource |
| MAX_SIGNATURE_BYTES | 16 MiB | nav-core/src/macho.rs:113 | Code signature region | Resource |
| MAX_RANGED_BYTES | 64 MiB | nav-core/src/macho.rs:116 | Total ranged reads per file | Resource |
| MAX_FAT_ARCHES | 1024 | nav-core/src/macho.rs:105 | Fat slices; source comment: don't lower | Resource |
| MAX_NCMDS / MAX_NSECTS / MAX_SECTIONS_PER_IMAGE / MAX_SEGMENTS | 4096 / 4096 / 4096 / 1024 | nav-core/src/macho.rs:78-83 | Mach-O structure counts | Resource |
| MAX_DYLIBS / MAX_RPATHS / MAX_LC_STR_BYTES / MAX_CS_BLOBS | 4096 / 256 / 4096 B / 256 | nav-core/src/macho.rs:96-99 | Mach-O list bounds | Resource |
| MAX_ALTERNATE_CODEDIRECTORIES | 5 | nav-core/src/macho.rs:62 | Alternate CDs examined | Resource |
| MAX_PAYLOAD_REGIONS | 4096 | nav-core/src/rules/entropy.rs:47 | Payload regions measured | Resource |

## Detection heuristics' bounds

| Option | Value | Location | Controls | Class |
|---|---|---|---|---|
| MIN_SAMPLE_BYTES | 256 B | nav-core/src/textclass.rs:7 | Smallest sample classified as text or binary | Detection |
| PAYLOAD_MIN_BYTES | 64 KiB | nav-core/src/rules/entropy.rs:44 | Smallest payload region | Detection |
| WINDOW_BLOCK_BYTES | 32 KiB | nav-core/src/rules/entropy.rs:87 | Entropy window block | Detection |
| MIN_BASE64_RUN | 1024 chars | nav-core/src/rules/entropy.rs:92 | Shortest base64 payload run | Detection |
| MIN_DECODED_BYTES | 768 B | nav-core/src/rules/entropy.rs:96 | Shortest decoded run measured | Detection |
| MIN_WRAPPED_LINE_LEN / MIN_FREEFORM_LINE_LEN | 16 / 48 | nav-core/src/rules/entropy.rs:102, 108 | Wrap-merge line widths | Detection |
| PEM_LOOKBACK_LINES / MAX_PEM_LINE_BYTES / MAX_MIME_LOOKBACK / CARRIER_MAGIC_PREFIX_BYTES | 8 / 1024 B / 64 B / 8 B | nav-core/src/rules/entropy.rs:907-963 | Entropy exemption lookbacks | Detection |
| PATTERN_SPAN | 4096 B | nav-core/src/rules/strings.rs:99 | Span of a multi-token pattern | Detection |
| CONTEXT_LOOKBACK | 64 B | nav-core/src/rules/strings.rs:103 | Pattern context lookback | Detection |
| MAX_WALK_BACK / MAX_ASSIGNMENTS / MAX_PIPE_TOKENS / MAX_FORM_ARG | 256 B / 16 / 64 / 256 B | nav-core/src/rules/strings.rs:211-428 | Shell-command parsing bounds | Detection |
| SYSTEM_PREFIXES | `/system/`, `/usr/lib/`, `/library/` | nav-core/src/rules/macho_structure.rs:389 | Load paths exempt from loader-anomaly | Detection |

## Containers

| Option | Value | Location | Controls | Class |
|---|---|---|---|---|
| XarLimits.max_toc_bytes | 8 MiB | nav-core/src/xar.rs:57 | Inflated TOC size | Resource |
| XarLimits.max_entries | 10,000 | nav-core/src/xar.rs:58 | TOC `<file>` nodes | Resource |
| XarLimits.max_depth | 4 | nav-core/src/xar.rs:59 | TOC nesting | Resource |
| XarLimits.max_entry_bytes | 4 MiB | nav-core/src/xar.rs:60 | One heap entry decoded; per-script scan cap | Resource |
| XarLimits.max_read_back_bytes | 256 MiB | nav-core/src/xar.rs:61 | Read-back budget per archive | Resource |
| HELD_ENTRY_MULTIPLE | 4 | nav-core/src/xar.rs:715 | Nested gzip hold = 4 × entry cap | Resource |
| SCANNED_ENTRY_MULTIPLE | 4 | nav-core/src/rules/package.rs:458 | Scripts text scanned per entry | Resource |
| ZipLimits.max_entries | 10,000 | nav-core/src/zip.rs:79 | Headers across views and nesting | Resource |
| ZipLimits.max_depth | 4 | nav-core/src/zip.rs:80 | Zip nesting | Resource |
| ZipLimits.max_member_bytes | 8 MiB | nav-core/src/zip.rs:81 | Decoded bytes per member | Resource |
| ZipLimits.max_read_back_bytes | 256 MiB | nav-core/src/zip.rs:82 | Read-back budget | Resource |
| ZipLimits.max_ratio | 300:1 | nav-core/src/zip.rs:83 | Per-member ratio | Resource |
| ZIP ENTRY_COST | 1024 B | nav-core/src/zip.rs:52 | Fixed charge per member | Resource |
| ZIP MAX_GAPS | 64 | nav-core/src/zip.rs:55 | Gap records kept | Operational |
| CpioLimits.max_entries | 1024 | nav-core/src/cpio.rs:37 | Cpio members | Resource |
| CpioLimits.max_total_bytes | 4 MiB | nav-core/src/cpio.rs:38 | Bytes per cpio archive | Resource |
| inflate BLOCK_WORK / DYNAMIC_BLOCK_WORK | 64 / 1024 | nav-core/src/inflate.rs:25, 28 | Work charged per block | Resource |
| inflate WORK_PER_BUDGET_BYTE / WORK_SLACK | 4 / 1 MiB | nav-core/src/inflate.rs:30-31 | Decode-work cap | Resource |
| bzip2 MAX_RUN_WEIGHT | 2 MiB | nav-core/src/bzip2.rs:65 | RUNA/RUNB run refused | Resource |
| Display caps (MAX_NAME_CHARS 256, MAX_LISTED 10, SHOWN_GAPS 3) | — | zip.rs:57, rules/zip_member.rs:20, rules/container.rs:164 | Report text length | Operational |

## Disk images

| Option | Value | Location | Controls | Class |
|---|---|---|---|---|
| MAX_IMAGE_BYTES | 16 GiB | navctl/src/diskimage.rs | Largest image mounted | Resource |
| MAX_VOLUME_BYTES | 64 GiB | navctl/src/diskimage.rs | Largest logical size mounted | Resource |
| BUSY_RETRIES | 10 (~14 s) | navctl/src/diskimage.rs | hdiutil EAGAIN retries | Operational |
| Copy off-volume images | not built | — | Mount an image on another volume from `$TMPDIR` via a full copy; decided 2026-11-19 (#176) as a future opt-in, at the cost of longer scans | Operational |

## Timeouts

| Option | Value | Location | Controls | Class |
|---|---|---|---|---|
| MOUNT_TIMEOUT | 60 s | navctl/src/diskimage.rs | `hdiutil attach` | Resource |
| QUERY_TIMEOUT | 30 s | navctl/src/diskimage.rs | Other `hdiutil` calls | Resource |
| CANCEL_GRACE | 2 s | navctl/src/diskimage.rs | Worker wait after a signal | Operational |
| SETTLE | 5 s | navctl/src/diskimage.rs | Watch for a killed attach to land before cleanup | Operational (with nothing seen, the run directory is kept anyway) |
| TOOL_TIMEOUT | 60 s | nav-core/src/rules/codesign.rs:47 | `codesign` / `spctl` | Resource |
| PIPE_GRACE | 2 s | nav-core/src/process.rs:17 | Output collection after exit | Resource |
| POLL_INTERVAL | 1 s | navd/src/daemon.rs:18 | Daemon loop tick | Operational |

## Scoring and verdicts

All Detection: raising a threshold or lowering a weight hides content.

| Option | Value | Location | Controls |
|---|---|---|---|
| HIGH_SCORE_THRESHOLD | 45 | nav-core/src/scan.rs:20 | High verdict |
| MEDIUM_SCORE_THRESHOLD | 15 | nav-core/src/scan.rs:22 | Notify |
| ENTROPY_THRESHOLD | 7.0 bits/byte | nav-core/src/rules/entropy.rs:28 | Entropy gate |
| TEXT_PACKED_THRESHOLD | 7.5 bits/byte | nav-core/src/rules/entropy.rs:32 | Packed `__TEXT` |
| TEXT_ELEVATED / TEXT_PACKED weights | 4 / 15 | nav-core/src/rules/entropy.rs:37, 40 | `__TEXT` entropy |
| PAYLOAD_STRUCTURAL / PAYLOAD_CORROBORATING weights | 15 / 4 | nav-core/src/rules/entropy.rs:54, 58 | Payload regions |
| PAYLOAD_TEXT_RATIO | 4 | nav-core/src/rules/entropy.rs:61 | Small-text shape |
| BASE64_PAYLOAD / CONTAINER_BLOB / EMBEDDED_BLOB weights | 8 / 5 / 15 | nav-core/src/rules/entropy.rs:115-123 | Blobs in text |
| NAME_WEIGHT / NAME_FLOOR_CAP | 2 / 5 | nav-core/src/rules/strings.rs:12, 16 | Name markers |
| Intent pattern weights | 15, 15, 15, 10, 10 | nav-core/src/rules/strings.rs:127-143 | download→shell, decoded→shell, osascript download, TCC.db, curl upload |
| UNSIGNED / ADHOC_MANUAL / UNANCHORED_IDENTITY / INVALID_SIGNATURE weights | 4 / 3 / 5 / 5 | nav-core/src/rules/codesign.rs | Signing |
| REVOKED_CERT_WEIGHT | 14 | nav-core/src/rules/codesign.rs:636 | Revoked cert |
| UNNOTARIZED / NOTARIZED weights | 2 / −3 | nav-core/src/rules/codesign.rs:818, 823 | Notarization (only negative weight) |
| TRANSIENT_LOCATION / USER_HOME_PATH weights | 15 / 5 | nav-core/src/rules/macho_structure.rs:27, 31 | Load paths |
| ENTITLEMENT weights (signed / ad-hoc / signed cap) | 10 / 18 / 10 | nav-core/src/rules/macho_structure.rs:34-43 | Suspicious entitlements |
| macho_structure / persistence MAX_WEIGHT | 30 / 30 | macho_structure.rs:46, persistence.rs:22 | Rule ceilings |
| SHORT_INTERVAL_SECS | 300 s | nav-core/src/rules/persistence.rs:25 | Beaconing interval |
| Persistence weights (RunAtLoad+KeepAlive, unusual location, inline interpreter, short interval, staged location) | 8 / 12 / 12 / 6 / 10 | nav-core/src/rules/persistence.rs:85-113 | launchd findings |
| MAX_SCRIPT / DISTRIBUTION_INTERPRETER / INSTALLER_SCRIPTS_STARVED / UNSIGNED_PACKAGE weights | 20 / 8 / 10 / 6 | nav-core/src/rules/package.rs:28-44 | Packages |
| MAX_ZIP_MEMBER_WEIGHT | 20 | nav-core/src/rules/zip_member.rs:17 | Zip members |
| Lists: TRANSIENT_PREFIXES, TOOL_ROOTS, SUSPICIOUS_ENTITLEMENTS, SCRIPT_EXTS, MARKERS, PATTERNS, STANDARD/PAYLOAD_EXCLUDED_SEGMENTS, IMAGE_FORMATS, INSTALL_SCRIPT_NAMES, INTERPRETERS | — | rules/mod.rs:50, persistence.rs:232, macho_structure.rs:89, textclass.rs:50, strings.rs:28/125, entropy.rs:65/68, container.rs:29, package.rs:427/1376 | Allowlist/denylist-like tables |

## Paths

All Boundary: a user-chosen tool path runs that binary, and the service paths are written by root.

| Option | Value | Location |
|---|---|---|
| HDIUTIL / CODESIGN / SPCTL / LAUNCHCTL / TCCUTIL | `/usr/bin/hdiutil`, `/usr/bin/codesign`, `/usr/sbin/spctl`, `/bin/launchctl`, `/usr/bin/tccutil` | diskimage.rs, rules/codesign.rs, nav-service/src/ops.rs; absolute by design (§11.10) |
| Scratch root | `<temp dir>/navctl-scratch` | navctl/src/diskimage.rs |
| Helper binary / LaunchDaemon plist | `Library/PrivilegedHelperTools/navd`, `Library/LaunchDaemons/com.nav.navd.plist` | nav-service/src/lib.rs:46-48 |
| Config / state dirs | `etc/navd`, `private/var/db/navd` | nav-service/src/lib.rs:49-50 |
| Daemon logs | `navd.out.log`, `navd.err.log` under the state dir | nav-service/src/lib.rs:51-52 |
| launchd label / codesign id / TCC service | `com.nav.navd`, `com.nav.navd`, `SystemPolicyAllFiles` | nav-service/src/lib.rs:36-42 |

## CLI defaults a config file could set

| Flag | Default | Location | Class |
|---|---|---|---|
| `--max-files` / `--max-total-bytes` | 50,000 / 4 GiB | navctl/src/main.rs | Resource |
| `--recursive` / `--json` / `--verbose` | off | navctl/src/main.rs | Operational |
| `--no-mount` | off | navctl/src/main.rs | Operational (an unmounted image is reported `Partial`, not clean) |
| Stubs: `status --resource-usage`, `events tail --min-score/--signal`, `logs --since/--grep`, `quarantine purge --force`, `config get/set` | — | navctl/src/main.rs | Operational |

## Daemon and service

| Option | Value | Location | Class |
|---|---|---|---|
| DIR_MODE / PLIST_MODE / BIN_MODE | 0o755 / 0o644 / 0o755 | nav-service/src/orchestrate.rs:17-19 | Boundary |

## In the design, not in code

| Option | Where | Class |
|---|---|---|
| Config files `~/.config/navctl/config.toml`, `/etc/navd/config.toml` | design.md (naming); scanner.md §8 | Boundary (daemon file root-owned, edited via the socket; gaps-and-requirements.md §11) |
| Socket `/var/run/navd.sock` | design.md; platform.md §9.1 | Boundary |
| Ruleset hot-reload + rollback | roadmap.md Phase 3 | Boundary |
| Opt-in auto-quarantine | scanner.md §7 | Boundary (acts on files without confirmation) |
| Allowlist / denylist | scanner.md §8; roadmap.md Phase 3 | Detection |
| Container limits (defaults in the §6.2 table; config ranges not yet chosen, #196) | scanner.md §6.2 | Resource |
| Opt-in `CloudFeedProvider` | scanner.md | Privacy |
| Full process args (redaction opt-out) | platform.md | Privacy |
| Event log retention | roadmap.md Phase 3 | Privacy |
| Notification opt-out | platform.md §9.2 | Operational |
