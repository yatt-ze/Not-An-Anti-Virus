# NAV container/archive parser conformance & robustness audit

Defensive review of NAV's container and archive parsers, written 2026-11-10
against commit `20cda67` (v0.4.0, design doc v0.90).

This is a review, not a design change. No production code under `crates/` and
nothing under `docs/design/` was edited; §7 lists the regression tests and
remediations it proposes. No GitHub issues were filed.

**Scope.** ZIP/DEFLATE, XAR, CPIO, bzip2/gzip, property lists, installer
`Scripts` archives, and Mach-O within archives. The question is narrow:
does NAV interpret these formats the way the trusted native macOS reader
does (libxar for `.pkg`, CoreFoundation for plists, Info-ZIP/`ditto` for
zips, libarchive for cpio), does it fail safe on malformed input, and does
it report what it could not inspect rather than passing it as clean (§10,
§11.8).

**Method.** All fixtures are synthetic and inert — no extracted content,
installer script, or downloaded sample was executed. NAV behaviour was
observed by linking `nav-core` into a small out-of-tree probe that calls the
public parser entry points (`zip::read`, `xar::parse`/`read_entry`,
`cpio::parse`, `inflate`/`gzip`/`bzip2`, `plist::parse*`) and `scan_file`.
The macOS oracle for `.pkg` is Apple's published libxar source
(`apple-oss-distributions/xar`, files `lib/archive.c`, `lib/filetree.c`,
`lib/io.c`), read directly; for ZIP, Info-ZIP `unzip` 6.00; for plists,
`plistlib`/CoreFoundation semantics. `ditto`/`bsdtar` were not available on
the Linux audit host — the two places that depend on them are marked
accordingly and left open, consistent with issue #135.

**Relationship to existing issues.** #151 (pkg Scripts truncation) is
**closed/fixed** by PR #154; the Scripts read-back path it fixed is sound in
the cases tested here. #135 (six ZIP central/local view gaps) is **open**;
§6 reports the result of running its six candidates — none reproduced as a
missed member against `unzip`, because NAV's independent local-header walk
reads a superset. The findings below are **new** and were not covered by
either issue: they are in XAR TOC *interpretation* (not the heap read #151
addressed) and in plist key resolution.

---

## 1. Conclusions

1. **The ZIP reader is sound** on the #135 candidates and on malformed
   input: its two-view design (central directory *and* an independent local
   header walk) reads a superset of what `unzip` extracts, so every planted
   member in §6 was inspected, and genuine disagreements are reported as
   gaps. No ZIP finding.
2. **The CPIO reader is sound**: it halts (never silently truncates) on
   malformed headers, zero-length-then-data, and post-trailer bytes, and
   never opens attacker-controlled names. No CPIO finding.
3. **The gzip/bzip2 framing is sound** for the installer `Scripts` path,
   including concatenated gzip members. No decompressor finding.
4. **The XAR TOC reader diverges from libxar in four ways that let a
   crafted `.pkg` hide its install scripts from NAV while Installer still
   runs them** (F-1 … F-4). In each case NAV parses the archive as
   *complete* and scores it *clean* (`no-action`), with no coverage gap
   naming the hidden scripts — the §11.8 "report it, don't pass it" rule is
   violated because NAV does not know it missed anything.
5. **The plist reader resolves duplicate keys first-wins; CoreFoundation /
   launchd resolve last-wins** (F-5), letting a launchd job under-report
   persistence markers to the `launchd-persistence-plist` rule.

Findings F-1…F-4 share one root cause: NAV's hand-written XML scanner
(`xml.rs`) matches **raw qualified element names and treats every text-ish
event as element text**, whereas libxar drives libxml2's reader, which
exposes **local names, decoded `enctype="base64"` values, and distinct
CDATA node types**. They are reported separately because each needs its own
fix and its own regression fixture.

---

## 2. F-1 — XAR heap `<offset>` is parsed strict-decimal; libxar parses it base-0 (octal/hex)

**Parser / code path.** `crates/nav-core/src/xar.rs` — `parse_u64()` (used
for `<offset>`, `<length>`, `<size>` element text in `walk_toc`), feeding
`XarFile.offset` and the heap read in `read_entry`/`entry_span`.

**Expected behaviour (libxar).** `lib/io.c:xar_io_get_file_offset` reads the
offset with `strtoll(opt, NULL, 0)` — **base 0**, so a leading `0` is octal
and a leading `0x` is hex. (Length, by contrast, is `strtoll(..., 10)` —
decimal — so the two fields do not parse the same way.) Installer/`pkgutil`
seek to that byte in the heap and run whatever is there.

**NAV's actual behaviour.** `parse_u64` accumulates decimal digits only. An
offset of `01000` is read as decimal **1000**; libxar reads it as octal
**512**. NAV therefore reads a *different heap location* than Installer, and
because the entry still parses, it reports `Ok(None)` (clean) with no gap.

**Evidence.** Fixture: a one-entry `Scripts` xar whose `<offset>` is `01000`,
with an inert decoy script at decimal 1000 and a marker payload
(`curl … | sh`, inert, TEST-NET-3 address) at octal 512.

| | offset byte NAV reads | result |
|---|---|---|
| `x0_baseline` (offset `0`, payload at 0) | 0 | `notify` — `installer-script-suspicious` w=19 |
| `x1_octal_offset` (offset `01000`) | 1000 (decoy) | **`no-action`** — payload at 512 never read, no gap |

libxar on `x1` reads offset 512 → the marker payload. NAV reads 1000 → the
benign decoy, and scores the package clean.

A `0x…` or `+…` offset is *detected* rather than silently misread: NAV's
`parse_u64` returns `None` → `XarEntryError::NoHeapLocation` →
`installer-script-suspicious` goes not-applicable (a coverage gap), so the
package comes out `Partial`. The **silent** case is specifically a
leading-zero (octal) offset.

**Impact.** Detection evasion for installer scripts, with no incompleteness
signal. Correctness: NAV's heap model disagrees with the one the OS uses to
execute the bytes.

---

## 3. F-2 — XAR `<name enctype="base64">` is not decoded

**Parser / code path.** `xar.rs` — `walk_toc`, the `(Some("file"), "name")`
text arm sets `node.name = xml::decode_entities(raw)`; the `enctype`
attribute on `<name>` is never consulted.

**Expected behaviour (libxar).** `lib/filetree.c:xar_prop_unserialize`
treats `isname && enctype=="base64"` specially: the element text is
base64-decoded (`xar_from_base64`) to produce the real filename. This is a
format feature libxar emits for names it cannot write as safe XML text.

**NAV's actual behaviour.** NAV stores the literal base64 text as the name.
A `Scripts` entry written as
`<name enctype="base64">U2NyaXB0cw==</name>` is named `U2NyaXB0cw==` to NAV,
so `XarFile::is_metadata_entry()` (which matches the exact strings
`PackageInfo`/`Distribution`/`Scripts`) returns **false**, the entry is
never read, and nothing is scored.

**Evidence.** Fixture `x2_b64_name.pkg`: probe reports `path="U2NyaXB0cw=="
meta=false`; `scan` → `no-action`, only `unsigned-installer-package` (w=6),
no installer-script gap. libxar decodes the name to `Scripts` and runs it.

**Impact.** Detection evasion: the entire install-script surface is hidden
with no gap. (Also affects `PackageInfo`/`Distribution` the same way.)

---

## 4. F-3 — XAR namespace-prefixed TOC elements are ignored (qualified vs local name)

**Parser / code path.** `xar.rs` — `walk_toc` matches `name` from
`xml::Event::Open` against the bare strings `"file"`, `"name"`, `"type"`,
`"data"`, `"offset"`, etc. `xml.rs`'s `Scanner` returns the **raw qualified
name** including any `prefix:`.

**Expected behaviour (libxar).** Every element test in `archive.c` /
`filetree.c` uses `xmlTextReaderConstLocalName`, i.e. the **local name** with
the namespace prefix stripped. `<n:file>` and `<n:name>` are processed
identically to `<file>`/`<name>`; libxml2 (hence Installer) accepts the
prefixed form.

**NAV's actual behaviour.** With a declared prefix, NAV sees element names
like `n:file` / `n:name`, matches none of its arms, and drops the data.

**Evidence.**
- `x3_ns_name.pkg` (`<n:name>Scripts</n:name>` inside an unprefixed
  `<file>`): probe reports `path="<unnamed>" meta=false`; `scan` →
  `no-action`.
- `x3b_ns_file.pkg` (the whole `<n:file>…</n:file>` prefixed): probe reports
  **zero** `FILE` entries — the entire file tree is invisible; `scan` →
  `no-action`.

In both, libxar resolves local names → `file`/`name`/`Scripts` and inspects
normally.

**Impact.** Detection evasion ranging from a single hidden entry to a
wholly invisible file tree, with no gap. This is also a general
parsing-consistency defect: NAV cannot read a namespaced-but-valid TOC that
Installer reads fine.

---

## 5. F-4 — CDATA (and child-element) text overwrites a `<file>` child's value; libxar ignores non-TEXT nodes

**Parser / code path.** `xml.rs` — `Scanner::next_event` emits a
`<![CDATA[…]]>` section as an `Event::Text`. `xar.rs` `walk_toc` assigns
`node.name`/`node.kind`/offset/length on **every** text event under the
relevant parent, so the last text wins.

**Expected behaviour (libxar).** `xar_prop_unserialize`'s read loop switches
only on `XML_READER_TYPE_TEXT` (3) for setting a property value;
`XML_READER_TYPE_CDATA` (4) is not handled, so a CDATA section does **not**
change the name. For `<name>Scripts<![CDATA[x]]></name>`, libxar keeps the
last *TEXT* value, `Scripts`.

**NAV's actual behaviour.** NAV treats the CDATA `x` as text and overwrites
the name, yielding `x`.

**Evidence.** `x4_cdata_name.pkg`: probe reports `path="x" meta=false`;
`scan` → `no-action`. libxar name = `Scripts` → inspected and run.

**Impact.** Detection evasion: a `Scripts` entry named
`Scripts<![CDATA[x]]>` is `Scripts` to Installer but `x` to NAV, so it is
not recognised as metadata and not read, with no gap. (A trailing child
element such as `<name>Scripts<x/></name>` perturbs the name similarly; that
variant was not separately confirmed against libxar and is noted, not
claimed.)

---

## 6. F-5 — plist duplicate keys resolve first-wins; CoreFoundation/launchd resolve last-wins

**Parser / code path.** `crates/nav-core/src/plist.rs` —
`PlistValue::get()` does `.iter().find(|(k, _)| k == key)`, returning the
**first** matching key. Both the XML and binary readers preserve duplicate
keys in document order, so `get` is first-wins. Consumed by
`crates/nav-core/src/rules/persistence.rs` (`LaunchdJob::from_plist`).

**Expected behaviour (CoreFoundation).** A `<dict>` with repeated keys
resolves to the **last** occurrence (confirmed with `plistlib`, which
mirrors CFPropertyList here); launchd reads the job through
CoreFoundation, so the last value is the effective one.

**NAV's actual behaviour.** NAV reads the first value. A job with
`<key>RunAtLoad</key><false/> … <key>RunAtLoad</key><true/>` (and the same
for `KeepAlive`) is read by NAV as `false`/`false`, so the
`RunAtLoad + KeepAlive` marker (weight 8) never fires; launchd sees
`true`/`true`.

**Evidence.** `dupkey.plist` under a `LaunchAgents/` path: probe
`parse_launchd` shows both pairs preserved in order; `scan` →
`launchd-persistence-plist` fires at **w=12** (unusual-location only), *not*
the 8 for RunAtLoad+KeepAlive. `plistlib` resolves both to `True`.

**Impact.** Under-counting of persistence evidence (a corroboration-only
signal weakened or dropped). Lower severity than F-1…F-4 because the rule
still fires on other anomalies, but it is a real native-reader divergence
and could matter where RunAtLoad+KeepAlive is the deciding corroboration
(§5.1).

---

## 7. Checked and sound (no finding)

These were exercised and matched the native reader / failed safe; recording
them so the next audit need not re-derive the result.

**ZIP — issue #135's six candidates.** NAV reads the central directory *and*
independently walks local headers from the first `PK\x03\x04`, decoding each
distinct interpretation once. Against `unzip` 6.00:

| #135 candidate | fixture | `unzip` | NAV |
|---|---|---|---|
| 1 streamed-stored vs descriptor | `z6_stored_dd` | `a.sh` | reads `a.sh`, matches |
| 2 stored `csize≠usize` | `z1_stored_csize_ne_usize` | 139 B | reads **both** interpretations + raises `Headers`/`StreamEnd` gaps |
| 3 >1 EOCD record | `z2_two_eocd` | last EOCD → `evil.sh` | reads **both** `good`+`evil` (local walk) |
| 4 non-header bytes between members | `z4_junk_between` | `good.txt` only | `good.txt` only — matches `unzip` |
| 5 Zip64 / 16-bit count 0 | `z5_count_zero` | errors, extracts `evil.sh` | reads `evil.sh` (local walk) |
| 6 CD size vs entry count | `z3_count_lt_records` | errors, lists both | reads **both** (local walk) |

In every case where a member exists, NAV inspected it. Candidate 4 is the
only residual: NAV, like `unzip`, does **not** resync past junk to a later
local header, so a member that is both omitted from the central directory
*and* hidden behind a desync is missed — matching `unzip`. Whether `ditto`
or `bsdtar` resync there is the open half of #135 and was **not** testable
on this host (neither tool present); it should be settled on macOS before
#135 is closed. Recommend leaving #135 open with this result appended.

**CPIO.** odc/newc headers, `TRAILER!!!`, duplicate names, a zero-filesize
header followed by data, bytes after the trailer, and a leading-junk prefix
all behaved correctly: NAV halts with a `CpioHalt` (reported as incomplete)
on malformed/ambiguous input rather than silently truncating, stops cleanly
at the trailer, and keeps traversal names verbatim without opening them
(`../../etc/evil` is returned as data, never a path). No divergence that
hides content.

**gzip / bzip2.** gzip header-flag handling (FEXTRA/FNAME/FCOMMENT/FHCRC),
CRC/ISIZE trailer verification, and concatenated-member decoding
(`decode_later_members`) are correct for the `Scripts` path; bzip2 stops at
the first stream's end-magic as libxar does. Budget stops are kept distinct
from malformation (`DecodeError::BudgetExceeded`), per §10/§11.8.

**Mach-O within an archive (positive control).** A real test Mach-O stored
in a zip is extracted and handed to the Mach-O scan (`zip-member-*`); the
`ByteSource::source_len_is_authoritative` flag correctly marks a
budget-truncated member so offsets past the captured prefix are treated as
"not held" rather than "absent". No finding; included to show the
archive→Mach-O handoff works.

---

## 8. Proposed regression tests and remediation

All fixtures below are synthetic; generators are reproducible from the
snippets in §9. Each fix is small and local to the XML/number handling.

**F-1 (octal offset).** *Test:* a `Scripts` xar with `<offset>010</offset>`
and distinct bytes at decimal-10 vs octal-8; assert NAV reads octal-8, or at
minimum raises a gap. *Remediation:* parse `<offset>` (and, for parity with
libxar, only `<offset>`) with C `strtoll` base-0 semantics — accept a
leading `0` as octal and `0x` as hex — or, more conservatively, treat any
offset whose decimal and base-0 interpretations differ as a
`Disagreement`-style gap so the package degrades to `Partial` instead of
reading one interpretation silently.

**F-2 (base64 name).** *Test:* a `Scripts` entry with
`<name enctype="base64">U2NyaXB0cw==</name>`; assert `path == "Scripts"` and
`is_metadata_entry()`. *Remediation:* in `walk_toc`, when a `<name>` (or any
property) carries `enctype="base64"`, base64-decode its text before storing.
Capture the `enctype` attribute on the `Open` event (the scanner already
exposes the attribute region via `xml::attr`).

**F-3 (namespace prefix).** *Test:* the `x3`/`x3b` TOCs; assert the
`Scripts` entry is found. *Remediation:* strip an optional `prefix:` from
element names in `xml.rs` (expose a local-name helper) and match on the
local name throughout `walk_toc`, as libxar does. This also benefits the
plist and Distribution XML paths.

**F-4 (CDATA in value).** *Test:* `<name>Scripts<![CDATA[x]]></name>`;
assert name `Scripts`. *Remediation:* distinguish CDATA from element text so
`walk_toc`/`xar_prop` semantics match libxar — either emit a separate
`Event::CData` the TOC walker ignores for value assignment, or have
`walk_toc` take the first text child rather than the last. (The Distribution
`<script>` path deliberately keeps CDATA verbatim; keep that — the fix is
scoped to TOC property values.)

**F-5 (duplicate keys).** *Test:* the `dupkey` launchd plist; assert
`RunAtLoad`/`KeepAlive` read as the last occurrence. *Remediation:* make
`PlistValue::get` last-wins (`.rev().find(...)` or de-dup keeping the last on
insert) to match CoreFoundation. Audit other `get` callers for the change in
meaning first.

Because F-1…F-4 are all "a crafted but Installer-valid TOC hides scripts
with no gap", a belt-and-braces mitigation independent of the individual
fixes is worth considering: when a `.pkg` parses complete but NAV recognises
**zero** metadata entries (`PackageInfo`/`Distribution`/`Scripts`), treat
that as a coverage gap rather than a clean read — a real installer package
essentially always has at least `PackageInfo`/`Distribution`.

---

## 9. Reproduction

Probe harness (links `nav-core`, calls the public parser APIs) and fixture
generators are in the audit scratchpad:
`…/scratchpad/probe/` (the `probe` binary),
`…/scratchpad/tools/{fxlib,mk_xar,mk_cpio,zipb,mk_zip}.py`,
fixtures under `…/scratchpad/fx/{xar,cpio,zip,plist}/`.

Essentials, for a self-contained rebuild:

- **XAR fixture** = `xar!` + 28-byte big-endian header
  (`header_size=28, version=1, toc_len_compressed, toc_len_uncompressed,
  checksum_alg=0`) + zlib-compressed TOC + heap. A minimal `Scripts` TOC is
  `<xar><toc><file id="1"><name>Scripts</name><type>file</type><data>
  <offset>0</offset><length>N</length><size>N</size>
  <encoding style="application/octet-stream"/></data></file></toc></xar>`;
  the heap entry at that offset is a gzip of an odc cpio holding one
  `preinstall` member. The five XAR variants change only the `<offset>`
  value (F-1), the `<name>` encoding (F-2), the element prefixes (F-3), or
  insert `<![CDATA[…]]>` in `<name>` (F-4).
- **plist fixture** (F-5) is an XML launchd job dict with `RunAtLoad` and
  `KeepAlive` each listed twice, `false` then `true`.
- All script payloads are inert text (`echo`, or a `curl … | sh` marker
  pointing at a TEST-NET-3 `203.0.113.0/24` address); nothing is executed.

libxar oracle: `apple-oss-distributions/xar`, `xar/lib/io.c`
(`xar_io_get_file_offset`, base-0 offset), `xar/lib/filetree.c`
(`xar_prop_unserialize`: `enctype="base64"` decode, `XML_READER_TYPE_TEXT`
only), `xar/lib/archive.c` (`xar_unserialize`: `ConstLocalName` throughout).
