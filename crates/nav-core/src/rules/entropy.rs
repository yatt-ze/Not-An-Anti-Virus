//! High-entropy content detection — a weak generic signal on its own (§5.1).
//!
//! Structure-aware, not whole-file (§5.2):
//! - **Mach-O**: scores the `__TEXT` code section as a whole, and its 64 KiB
//!   windows for a packed region inside otherwise ordinary code (a window
//!   alone only reaches the elevated tier). Also scores 64 KiB windows of
//!   payload-shaped regions elsewhere in the image (see [`PayloadRegion`]).
//! - **script/text**: scores the whole content first (weight 15), then a
//!   base64-encoded payload's *decoded* bytes (weight 8, corroboration-only
//!   — see [`BASE64_PAYLOAD_WEIGHT`]). Base64 of plain text decodes to low
//!   entropy and is deliberately not this rule's signal (issue #35).
//! - **any other opaque binary**: not scored — expected to be high-entropy.

use std::collections::HashSet;
use std::ops::Range;

use super::{Rule, RuleOutcome};
use crate::base64;
use crate::context::{ScanContext, MAX_STREAM_BYTES};
use crate::macho::{self, ByteSource};
use crate::model::{MatchedSignal, SignalCategory};
use crate::textclass::{classify_text, TextClass, BINARY_MAGICS, MIN_SAMPLE_BYTES};

/// Entry gate (bits/byte, max 8.0) for the script/text and base64 paths and
/// for the elevated `__TEXT` tier; packed `__TEXT` needs
/// [`TEXT_PACKED_THRESHOLD`].
const ENTROPY_THRESHOLD: f64 = 7.0;

/// `__TEXT` entropy at or above this is treated as packed/encrypted code
/// (full weight); see §5.2.
const TEXT_PACKED_THRESHOLD: f64 = 7.5;

/// Weight of a `__TEXT` section from [`ENTROPY_THRESHOLD`] up to
/// [`TEXT_PACKED_THRESHOLD`] (dense SIMD code, partial packing), or with a
/// window at or above it: corroboration-only (§5.2).
const TEXT_ELEVATED_WEIGHT: i32 = 4;

/// Weight of a whole `__TEXT` section at or above [`TEXT_PACKED_THRESHOLD`].
const TEXT_PACKED_WEIGHT: i32 = 15;

/// Smallest file range a payload region may have, and so the window size
/// it is scored on (§5.2, #67).
const PAYLOAD_MIN_BYTES: u64 = 64 * 1024;

/// A payload region's window entropy needs at least this to fire.
const PAYLOAD_WINDOW_THRESHOLD: f64 = TEXT_PACKED_THRESHOLD;

/// Weight of a payload region in a writable+executable segment, or in a
/// non-standard segment beside a much smaller `__text` (§5.2, #67).
const PAYLOAD_STRUCTURAL_WEIGHT: i32 = 15;

/// Weight of a payload region with only one of the three shape qualifiers:
/// corroboration-only (§5.2, #67).
const PAYLOAD_CORROBORATING_WEIGHT: i32 = 4;

/// A region is "small text" shaped when `__text` is under 1/N of its size.
const PAYLOAD_TEXT_RATIO: u64 = 4;

/// Non-executable segments with these names are never measured as payload;
/// an executable one is not exempt (§5.2, #67).
const PAYLOAD_EXCLUDED_SEGMENTS: &[&[u8]] = &[b"__PAGEZERO", b"__LINKEDIT", b"__DWARF", b"__LLVM"];

/// Segment names a toolchain emits; any other name is "non-standard".
const STANDARD_SEGMENTS: &[&[u8]] = &[
    b"__PAGEZERO",
    b"__TEXT",
    b"__DATA",
    b"__DATA_CONST",
    b"__DATA_DIRTY",
    b"__AUTH",
    b"__AUTH_CONST",
    b"__OBJC",
    b"__IMPORT",
    b"__LINKEDIT",
    b"__DWARF",
    b"__LLVM",
    b"__CTF",
    b"__RESTRICT",
];

/// Block size for window scoring: a window is two consecutive blocks (64 KiB,
/// stride one block), aligned to the start of the scored range.
const WINDOW_BLOCK_BYTES: usize = 32 * 1024;

/// A base64 run shorter than this (alphabet characters, `=` and line breaks
/// not counted) is too small to be a meaningful embedded payload rather than
/// an incidental alnum-only token.
const MIN_BASE64_RUN: usize = 1024;

/// A decoded run shorter than this is too small to trust an entropy figure
/// from, mirroring [`MIN_SAMPLE_BYTES`]'s role for the whole-content case.
const MIN_DECODED_BYTES: usize = 768;

/// Consecutive lines sharing this width or more merge into one block if the
/// width is exact and uniform across all of them (e.g. `base64 -b 32`).
/// Below it, a shared width is more likely coincidental (e.g. a dictionary's
/// short one-word-per-line entries).
const MIN_WRAPPED_LINE_LEN: usize = 16;

/// Consecutive lines merge into one block if every one of them is at least
/// this wide, even at uneven widths (e.g. wrapping that varies by a column
/// or two) — real wrapping uses 64 or 76-column lines; a wordlist's entries
/// don't reliably reach this width at all, uniform or not.
const MIN_FREEFORM_LINE_LEN: usize = 48;

/// Corroboration-only (§5.1): a script embedding a compressed/encoded
/// payload as base64 is common in benign software (installers, bundlers),
/// so this alone must not reach Notify — it needs a second signal. Lower
/// than [`EMBEDDED_BLOB_WEIGHT`] and [`TEXT_PACKED_WEIGHT`], which are narrow
/// enough (raw binary in a script, packed Mach-O code) to carry more alone.
const BASE64_PAYLOAD_WEIGHT: i32 = 8;

/// Whole-content entropy in a fallback-classified file whose prefix shows
/// binary-container evidence (§5.2). Corroboration-only: media and PDFs
/// look like this, and a spoofed header must only lower a dropper's score.
const CONTAINER_BLOB_WEIGHT: i32 = 5;

/// Weight of a raw high-entropy blob in a script/text file (§5.1).
const EMBEDDED_BLOB_WEIGHT: i32 = 15;

pub struct HighEntropyRule;

impl Rule for HighEntropyRule {
    fn id(&self) -> &'static str {
        "high-entropy-content"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::StaticSuspicion
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        self.evaluate_with(ctx, || super::codesign::verifies_apple_anchor(ctx))
    }

    /// Covered when every slice's `__TEXT` and payload regions were scored:
    /// no slice was skipped or has an incomplete segment list walking the
    /// Mach-O itself, no slice's declared range needs bytes past
    /// a non-authoritative capture (§10/§11.8), the combined EOF-clipped
    /// ranges fit `MAX_STREAM_BYTES` with none left out by that cap, ranged
    /// reads actually work here when streaming was needed (§5.2, #45), and
    /// no slice's stream failed partway; a script/text file whose content is
    /// itself unread stays uncovered.
    fn covers_truncation(&self, ctx: &ScanContext) -> bool {
        let scan = ctx.macho();
        if !scan.images.is_empty() {
            if ctx.stream_failed(self.id())
                || scan.skipped_slices > 0
                || scan.images.iter().any(|image| !image.segments_complete)
            {
                return false;
            }
            if declares_range_past_a_non_authoritative_capture(ctx, &scan.images) {
                return false;
            }
            let (included, all_scored) = budgeted_ranges(ctx, &scan.images);
            if !all_scored {
                return false;
            }
            let total: u64 = included
                .iter()
                .map(|(_, range)| range.end - range.start)
                .sum();
            return total == 0 || ctx.supports_ranged_reads();
        }
        if scan.is_macho {
            return false;
        }
        ctx.content
            .as_ref()
            .is_some_and(|content| classify_text(content, &ctx.path) == TextClass::NotText)
    }
}

/// True if any image's declared, *unclipped* `__text` or payload-region
/// range reaches past `ctx.file_len` on a source whose length isn't
/// authoritative (a truncated embedded/container capture, §10/§11.8): real
/// bytes past what this capture holds could still hold it, so
/// [`clip_to_file_len`] shrinking or emptying the range must not be read as
/// "nothing to score."
fn declares_range_past_a_non_authoritative_capture(
    ctx: &ScanContext,
    images: &[macho::MachOImage],
) -> bool {
    if ctx.source_len_is_authoritative() {
        return false;
    }
    let file_len = ctx.file_len.unwrap_or(0);
    images.iter().any(|image| {
        image.text_range.as_ref().is_some_and(|r| r.end > file_len)
            || payload_regions(ctx, image)
                .iter()
                .any(|r| r.range.end > file_len)
    })
}

/// A non-`__text` region measured for a packed payload (§5.2, #67).
#[derive(Clone, Debug)]
struct PayloadRegion {
    /// Absolute file range, unclipped; at least [`PAYLOAD_MIN_BYTES`].
    range: Range<u64>,
    /// The segment's `initprot` has both write and execute.
    writable_executable: bool,
    /// The segment name is not a standard one.
    non_standard: bool,
    /// `__text` is under 1/[`PAYLOAD_TEXT_RATIO`] of the region.
    small_text: bool,
    /// Escaped `__SEG` or `__SEG,__sect`, safe to embed in a description.
    label: String,
    /// Length of the image's clipped `__text` outside this region.
    text_len: u64,
}

impl PayloadRegion {
    /// Whether this region's qualifiers can reach
    /// [`PAYLOAD_STRUCTURAL_WEIGHT`].
    fn is_structural(&self) -> bool {
        self.writable_executable || (self.non_standard && self.small_text)
    }

    fn weight(&self) -> i32 {
        if self.is_structural() {
            PAYLOAD_STRUCTURAL_WEIGHT
        } else {
            PAYLOAD_CORROBORATING_WEIGHT
        }
    }

    fn describe(&self, window: f64) -> String {
        let len = self.range.end - self.range.start;
        let kib = PAYLOAD_MIN_BYTES / 1024;
        let measured = format!("window entropy: {window:.2} bits/byte over {kib} KiB");
        let label = &self.label;
        if self.writable_executable {
            format!("high-entropy payload in writable+executable segment {label} ({measured}; segment {len} bytes)")
        } else if self.non_standard {
            format!("high-entropy payload in non-standard segment {label} ({measured}; segment {len} bytes)")
        } else if let Some(ratio) = len.checked_div(self.text_len) {
            format!(
                "high-entropy section {label} {ratio}x the size of __text — consistent with an unpacking stub and payload ({measured}; section {len} bytes)"
            )
        } else {
            format!("high-entropy section {label} with no __text — consistent with an unpacking stub and payload ({measured}; section {len} bytes)")
        }
    }
}

/// Render a raw NUL-padded 16-byte name: stops at the first NUL, and
/// escapes anything but printable ASCII (names are attacker-controlled).
fn escaped_name(raw: &[u8; 16]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let mut out = String::new();
    for c in String::from_utf8_lossy(&raw[..end]).chars() {
        if (c.is_ascii_graphic() || c == ' ') && c != '"' && c != '\\' {
            out.push(c);
        } else {
            out.extend(c.escape_default());
        }
    }
    out
}

/// The image's regions worth measuring for a packed payload: each of at
/// least [`PAYLOAD_MIN_BYTES`] with at least one shape qualifier — a
/// writable+executable segment, a non-standard segment name, or a `__text`
/// much smaller than the region (§5.2, #67).
fn payload_regions(ctx: &ScanContext, image: &macho::MachOImage) -> Vec<PayloadRegion> {
    // An object file is never loaded; its single unnamed rwx segment is normal.
    if image.filetype == macho::MH_OBJECT {
        return Vec::new();
    }
    // EOF-clipped, and per region minus its overlap with the region: a
    // declared-huge `__text` header must not hide a small stub.
    let text = image
        .text_range
        .clone()
        .map(|r| clip_to_file_len(ctx, r))
        .unwrap_or(0..0);
    let mut out = Vec::new();
    let mut push =
        |range: &Range<u64>, writable_executable: bool, non_standard: bool, label: String| {
            let len = range.end - range.start;
            let overlap = text
                .end
                .min(range.end)
                .saturating_sub(text.start.max(range.start));
            let text_len = text.end - text.start - overlap;
            let small_text = text_len.saturating_mul(PAYLOAD_TEXT_RATIO) < len;
            if len >= PAYLOAD_MIN_BYTES && (writable_executable || non_standard || small_text) {
                out.push(PayloadRegion {
                    range: range.clone(),
                    writable_executable,
                    non_standard,
                    small_text,
                    label,
                    text_len,
                });
            }
        };
    for seg in &image.segments {
        if seg.initprot & macho::VM_PROT_EXECUTE == 0
            && PAYLOAD_EXCLUDED_SEGMENTS.iter().any(|n| seg.is_named(n))
        {
            continue;
        }
        let seg_label = escaped_name(&seg.name);
        let non_standard = !STANDARD_SEGMENTS.iter().any(|n| seg.is_named(n));
        let wx = seg.initprot & (macho::VM_PROT_WRITE | macho::VM_PROT_EXECUTE)
            == (macho::VM_PROT_WRITE | macho::VM_PROT_EXECUTE);
        if wx || non_standard {
            if let Some(range) = &seg.file_range {
                push(range, wx, non_standard, seg_label);
            }
        } else if seg.sections.is_empty() {
            // A section-less segment that is itself the `__text` fallback.
            if let Some(range) = seg
                .file_range
                .as_ref()
                .filter(|r| image.text_range.as_ref() != Some(*r))
            {
                push(range, false, false, seg_label);
            }
        } else {
            for sect in &seg.sections {
                let Some(range) = &sect.file_range else {
                    continue;
                };
                if image.text_range.as_ref() == Some(range) {
                    continue;
                }
                let label = format!("{seg_label},{}", escaped_name(&sect.name));
                push(range, false, false, label);
            }
        }
    }
    out
}

/// One range to score: a `__text` range (`None`) or a payload region.
type Candidate = (Option<PayloadRegion>, Range<u64>);

/// Decide which ranges get scored under one `MAX_STREAM_BYTES` budget for
/// the whole file (§5.2): every image's `__text`, then payload regions that
/// could reach [`PAYLOAD_STRUCTURAL_WEIGHT`], then the other payload
/// regions; each group resident-first and deduped by EOF-clipped absolute
/// range. A range that fits the remaining budget is included whole, else
/// only its resident part (inside `ctx`'s held content) if that fits, else
/// it is skipped. Returns the included candidates (with the clipped or
/// resident range) and whether every non-empty range was included whole.
/// Shared by evaluate and `covers_truncation` so they can't disagree.
fn budgeted_ranges(ctx: &ScanContext, images: &[macho::MachOImage]) -> (Vec<Candidate>, bool) {
    let held = ctx.content.as_ref().map_or(0, |c| c.len() as u64);
    let mut seen = HashSet::new();
    let mut texts: Vec<Candidate> = Vec::new();
    // Payload regions deduped by clipped range, keeping the heaviest.
    let mut payloads: Vec<Candidate> = Vec::new();
    for image in images {
        if let Some(range) = image.text_range.clone() {
            let range = clip_to_file_len(ctx, range);
            if !range.is_empty() && seen.insert((false, range.start, range.end)) {
                texts.push((None, range));
            }
        }
        for region in payload_regions(ctx, image) {
            let range = clip_to_file_len(ctx, region.range.clone());
            if range.is_empty() {
                continue;
            }
            let same = payloads.iter_mut().find(|(_, r)| *r == range);
            match same {
                Some((existing, _)) => {
                    if existing
                        .as_ref()
                        .is_some_and(|e| region.weight() > e.weight())
                    {
                        *existing = Some(region);
                    }
                }
                None => payloads.push((Some(region), range)),
            }
        }
    }
    // Fully resident ranges first, so a decoy that spends the whole budget
    // on streamed bytes can't crowd them out.
    texts.sort_by_key(|(_, range)| range.end > held);
    payloads.sort_by_key(|(region, range)| {
        (
            !region.as_ref().is_some_and(PayloadRegion::is_structural),
            range.end > held,
        )
    });
    for (_, range) in &payloads {
        seen.insert((true, range.start, range.end));
    }
    let mut included = Vec::new();
    let mut total = 0u64;
    let mut all_scored = true;
    for (region, range) in texts.into_iter().chain(payloads) {
        let is_payload = region.is_some();
        let remaining = MAX_STREAM_BYTES - total;
        let mut chosen = range.clone();
        if chosen.end - chosen.start > remaining {
            all_scored = false;
            chosen = range.start.min(held)..range.end.min(held);
            if chosen.is_empty()
                || chosen.end - chosen.start > remaining
                || (chosen != range && !seen.insert((is_payload, chosen.start, chosen.end)))
            {
                continue;
            }
        }
        total += chosen.end - chosen.start;
        included.push((region, chosen));
    }
    (included, all_scored)
}

impl HighEntropyRule {
    /// `evaluate` with the Apple-anchor check injected; `anchored` runs at
    /// most once, and only when it could change the result (see
    /// [`Self::eval_macho_images_with`]).
    fn evaluate_with(
        &self,
        ctx: &ScanContext,
        anchored: impl FnOnce() -> bool,
    ) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;
        if content.is_empty() {
            return Ok(None);
        }

        // `images` empty (whether or not `is_macho`) falls through exactly as
        // a `macho::parse` miss did — a non-Mach-O or unwalkable file.
        let images = &ctx.macho().images;
        if !images.is_empty() {
            return self.eval_macho_images_with(ctx, content, images, anchored);
        }

        if let TextClass::Text { container_evidence } = classify_text(content, &ctx.path) {
            return Ok(self.eval_embedded_payload(content, container_evidence));
        }

        // Opaque non-Mach-O binary: high entropy is expected, so no suspicion.
        Ok(None)
    }

    /// Score every image's `__TEXT` code and payload regions (a fat binary
    /// can hide a packed slice behind a clean one, §5.2) and report the
    /// single strongest — highest weight, then highest entropy. Returns
    /// `NotApplicable` when a range was left unscored (budget), scored
    /// prefix-only (failed stream) or an image's segment list is incomplete,
    /// and there is no weight-15 match (§10/§11.8).
    #[cfg(test)]
    fn eval_macho_images(
        &self,
        ctx: &ScanContext,
        content: &[u8],
        images: &[macho::MachOImage],
    ) -> Result<Option<MatchedSignal>, RuleOutcome> {
        self.eval_macho_images_with(ctx, content, images, || false)
    }

    /// [`Self::eval_macho_images`] with the Apple-anchor check injected. A
    /// payload region that reaches weight 15 only by non-standard name plus
    /// small `__text` (not writable+executable) is demoted to corroboration
    /// when the file verifies to an Apple anchor (§5.2). `anchored` runs at
    /// most once, and only if the best match is such a region.
    fn eval_macho_images_with(
        &self,
        ctx: &ScanContext,
        content: &[u8],
        images: &[macho::MachOImage],
        anchored: impl FnOnce() -> bool,
    ) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let (included, all_scored) = budgeted_ranges(ctx, images);
        let mut whole = all_scored && images.iter().all(|image| image.segments_complete);
        // (entropy, signal, reaches 15 only via name + small text)
        let mut scored_all: Vec<(f64, MatchedSignal, bool)> = Vec::new();
        for (region, range) in included {
            let (scored, complete) = self.eval_macho_range(ctx, content, range, region.as_ref());
            whole &= complete;
            if let Some((entropy, signal)) = scored {
                let name_and_text_only = region
                    .as_ref()
                    .is_some_and(|r| r.is_structural() && !r.writable_executable);
                scored_all.push((entropy, signal, name_and_text_only));
            }
        }
        let pick = |all: &[(f64, MatchedSignal, bool)]| {
            all.iter()
                .enumerate()
                .fold(None::<usize>, |best, (i, (e, s, _))| match best {
                    Some(b) if (all[b].1.weight, all[b].0) >= (s.weight, *e) => Some(b),
                    _ => Some(i),
                })
        };
        let mut best = pick(&scored_all);
        if best.is_some_and(|b| scored_all[b].2) && anchored() {
            for (_, signal, name_and_text_only) in &mut scored_all {
                if *name_and_text_only {
                    signal.weight = PAYLOAD_CORROBORATING_WEIGHT;
                    signal
                        .description
                        .push_str("; signature verifies to an Apple anchor, so corroboration-only");
                }
            }
            best = pick(&scored_all);
        }
        let best = best.map(|b| scored_all.swap_remove(b).1);
        match best {
            None if !whole => Err(RuleOutcome::NotApplicable),
            // A lesser match is corroboration-only, and an unscored or
            // prefix-only range could still hold packed code (§10/§11.8).
            Some(signal) if !whole && signal.weight < TEXT_PACKED_WEIGHT => {
                Err(RuleOutcome::NotApplicable)
            }
            best => Ok(best),
        }
    }

    /// Score one range from [`budgeted_ranges`] (EOF-clipped, at most
    /// `MAX_STREAM_BYTES`) as `__text` (`region` `None`) or as that payload
    /// region: read from `content` when resident, else streamed; if the
    /// stream fails, only the part inside `content` is scored and the
    /// failure is recorded. Returns the signal with its entropy (whole-section,
    /// or the window's for the windowed tiers) for comparing slices, and
    /// whether the whole range was scored (`false` after a failed stream).
    fn eval_macho_range(
        &self,
        ctx: &ScanContext,
        content: &[u8],
        range: Range<u64>,
        region: Option<&PayloadRegion>,
    ) -> (Option<(f64, MatchedSignal)>, bool) {
        // Whole range already resident in `content`: score it directly on
        // the slice, no streaming/windowing needed (§5.2).
        if range.end <= content.len() as u64 {
            return (self.macho_signal_from_content(content, range, region), true);
        }

        let mut acc = TextEntropy::new();
        let delivered = ctx.for_each_window(range.clone(), 0, |window, _is_last| {
            acc.feed(window);
        });
        if delivered {
            return (self.macho_signal(acc, region), true);
        }
        // The stream failed (or ranged reads are unavailable) — fall back to
        // what the captured prefix can still show rather than discarding a
        // score it would have found there (§10/§11.8).
        ctx.mark_stream_failed(self.id());

        (
            self.macho_signal_from_content(content, range, region),
            false,
        )
    }

    /// Score the part of `range` that lies inside `content`, clamped — used
    /// both when the whole range is already held and as the fallback after a
    /// failed stream.
    fn macho_signal_from_content(
        &self,
        content: &[u8],
        range: Range<u64>,
        region: Option<&PayloadRegion>,
    ) -> Option<(f64, MatchedSignal)> {
        let start = usize::try_from(range.start)
            .ok()
            .map(|s| s.min(content.len()));
        let end = usize::try_from(range.end)
            .ok()
            .map(|e| e.min(content.len()));
        let text = start.zip(end).and_then(|(s, e)| content.get(s..e))?;
        let mut acc = TextEntropy::new();
        acc.feed(text);
        self.macho_signal(acc, region)
    }

    /// Build the tiered `__TEXT` signal and the entropy it was decided on
    /// from a fully fed accumulator. Needs [`MIN_SAMPLE_BYTES`]; tiers use
    /// bias-corrected entropy (§5.2): whole section at or above
    /// [`TEXT_PACKED_THRESHOLD`] is packed, at or above [`ENTROPY_THRESHOLD`]
    /// is elevated, else a window at or above the packed threshold is
    /// elevated. A payload `region` instead fires on its best window alone
    /// ([`PAYLOAD_WINDOW_THRESHOLD`]), at the region's weight. Shared by the
    /// streamed and resident paths.
    fn macho_signal(
        &self,
        acc: TextEntropy,
        region: Option<&PayloadRegion>,
    ) -> Option<(f64, MatchedSignal)> {
        let (counts, len, max_window) = acc.finish();
        if let Some(region) = region {
            let window = max_window.filter(|&w| w >= PAYLOAD_WINDOW_THRESHOLD)?;
            return Some((
                window,
                MatchedSignal {
                    id: self.id().to_string(),
                    weight: region.weight(),
                    description: region.describe(window),
                    category: self.category(),
                },
            ));
        }
        if len < MIN_SAMPLE_BYTES as u64 {
            return None;
        }
        let entropy = miller_madow_entropy(&counts, len);
        let (weight, shown, description) = if entropy >= TEXT_PACKED_THRESHOLD {
            (
                TEXT_PACKED_WEIGHT,
                entropy,
                format!(
                    "high-entropy __TEXT section — consistent with packed/obfuscated code (entropy: {entropy:.2} bits/byte, bias-corrected, over {len} bytes)"
                ),
            )
        } else if entropy >= ENTROPY_THRESHOLD {
            (
                TEXT_ELEVATED_WEIGHT,
                entropy,
                format!(
                    "elevated __TEXT entropy — dense/SIMD code or partial packing (entropy: {entropy:.2} bits/byte, bias-corrected, over {len} bytes)"
                ),
            )
        } else {
            let window = max_window.filter(|&w| w >= TEXT_PACKED_THRESHOLD)?;
            (
                TEXT_ELEVATED_WEIGHT,
                window,
                format!(
                    "high-entropy region inside __TEXT section — packed payload or embedded data (window entropy: {window:.2} bits/byte over {} KiB; section {entropy:.2} over {len} bytes)",
                    2 * WINDOW_BLOCK_BYTES / 1024
                ),
            )
        };
        Some((
            shown,
            MatchedSignal {
                id: self.id().to_string(),
                weight,
                description,
                category: self.category(),
            },
        ))
    }

    /// Score a script/text file for an embedded high-entropy payload: first
    /// the whole content (raw binary spliced in), then a qualifying
    /// base64-encoded run's *decoded* bytes (module docs above). Neither
    /// path fires on base64 of ordinary text — decoding that yields low
    /// entropy, which is the point.
    fn eval_embedded_payload(
        &self,
        content: &[u8],
        container_evidence: bool,
    ) -> Option<MatchedSignal> {
        if content.len() >= MIN_SAMPLE_BYTES {
            let entropy = shannon_entropy(content);
            if entropy >= ENTROPY_THRESHOLD {
                let (weight, what) = if container_evidence {
                    (
                        CONTAINER_BLOB_WEIGHT,
                        "high-entropy data in a text-headed binary container",
                    )
                } else {
                    (
                        EMBEDDED_BLOB_WEIGHT,
                        "binary data embedded in a script/text file",
                    )
                };
                return Some(MatchedSignal {
                    id: self.id().to_string(),
                    weight,
                    description: format!(
                        "{what} (entropy: {:.1} bits/byte over {} bytes)",
                        entropy,
                        content.len()
                    ),
                    category: self.category(),
                });
            }
        }
        self.eval_base64_payload(content)
    }

    /// Scan for a base64-encoded high-entropy payload: find maximal runs,
    /// split each into candidate blocks/lines, skip a run confirmed as an
    /// ordinary carrier, and score the first remaining candidate whose
    /// entropy clears the threshold. Every candidate is examined — no work
    /// cap (§5.2).
    fn eval_base64_payload(&self, content: &[u8]) -> Option<MatchedSignal> {
        let mut pos = 0;
        while let Some((run_start, run_end, resume)) = next_base64_run(content, pos) {
            let mut carrier_confirmed = None;
            let mut seg_start = run_start;
            while seg_start < run_end {
                let (seg_end, next_start) = next_base64_segment(content, seg_start, run_end);
                if let Some(signal) = self.try_base64_candidate(
                    content,
                    seg_start,
                    seg_end,
                    run_start,
                    &mut carrier_confirmed,
                ) {
                    return Some(signal);
                }
                seg_start = next_start;
            }
            pos = resume;
        }
        None
    }

    /// Evaluate one candidate byte range as a possible base64 payload.
    /// `carrier_confirmed` is settled by the first candidate long enough to
    /// decode meaningfully — the only point [`Carrier::detect`] runs, on the
    /// text before `run_start` — then applied to the rest of the run (§5.2).
    fn try_base64_candidate(
        &self,
        content: &[u8],
        start: usize,
        end: usize,
        run_start: usize,
        carrier_confirmed: &mut Option<bool>,
    ) -> Option<MatchedSignal> {
        let run = &content[start..end];
        let (decoded, alphabet_len) =
            base64::decode_bounded(run, run.len(), base64::OnInvalid::Stop);
        if alphabet_len < MIN_BASE64_RUN {
            return None;
        }

        let confirmed = *carrier_confirmed.get_or_insert_with(|| {
            let carrier = Carrier::detect(content, run_start);
            !matches!(carrier, Carrier::None)
                && carrier.matches(&decoded[..decoded.len().min(CARRIER_MAGIC_PREFIX_BYTES)])
        });
        if confirmed {
            return None;
        }
        if decoded.len() < MIN_DECODED_BYTES {
            return None;
        }
        let entropy = shannon_entropy(&decoded);
        if entropy < ENTROPY_THRESHOLD {
            return None;
        }
        Some(MatchedSignal {
            id: self.id().to_string(),
            weight: BASE64_PAYLOAD_WEIGHT,
            description: format!(
                "base64-encoded high-entropy payload in a script/text file \
                 (entropy: {:.1} bits/byte over {} decoded bytes) — \
                 possible packed/encrypted stage",
                entropy,
                decoded.len()
            ),
            category: self.category(),
        })
    }
}

/// Find the next base64 candidate segment starting at `seg_start` within
/// `content[..run_end]`: its (exclusive) end, and where to resume scanning.
/// A segment is a single line under both [`MIN_WRAPPED_LINE_LEN`] and
/// [`MIN_FREEFORM_LINE_LEN`], or a maximal block of consecutive lines
/// matching one of those two width rules, optionally with one shorter
/// trailing line (§5.2).
fn next_base64_segment(content: &[u8], seg_start: usize, run_end: usize) -> (usize, usize) {
    let (first_end, first_next) = next_base64_line(content, seg_start, run_end);
    let first_width = first_end - seg_start;
    let mut uniform_ok = first_width >= MIN_WRAPPED_LINE_LEN;
    let mut freeform_ok = first_width >= MIN_FREEFORM_LINE_LEN;
    if !uniform_ok && !freeform_ok {
        return (first_end, first_next);
    }

    let mut block_end = first_end;
    let mut next = first_next;
    let mut last_width = first_width;
    while next < run_end {
        let (line_end, line_next) = next_base64_line(content, next, run_end);
        let width = line_end - next;
        let still_uniform = uniform_ok && width == first_width;
        let still_freeform = freeform_ok && width >= MIN_FREEFORM_LINE_LEN;
        if !still_uniform && !still_freeform {
            break;
        }
        uniform_ok = still_uniform;
        freeform_ok = still_freeform;
        block_end = line_end;
        next = line_next;
        last_width = width;
    }
    // One optional shorter (or equal) trailing line: the wrap remainder.
    if next < run_end {
        let (line_end, line_next) = next_base64_line(content, next, run_end);
        if line_end - next <= last_width {
            block_end = line_end;
            next = line_next;
        }
    }
    (block_end, next)
}

/// The next line starting at `start` within `content[..run_end]`: its end,
/// with a trailing `\r` (CRLF wrapping) excluded so line width is measured
/// consistently, and where scanning resumes — past the `\n`, or at `run_end`
/// if the line ran to the end of the run with no terminator.
fn next_base64_line(content: &[u8], start: usize, run_end: usize) -> (usize, usize) {
    let mut raw_end = start;
    while raw_end < run_end && content[raw_end] != b'\n' {
        raw_end += 1;
    }
    let next = if raw_end < run_end {
        raw_end + 1
    } else {
        raw_end
    };
    let end = if raw_end > start && content[raw_end - 1] == b'\r' {
        raw_end - 1
    } else {
        raw_end
    };
    (end, next)
}

/// Whether `b` can appear inside a base64 run: alphabet, padding, or a line
/// break (line-wrapped base64 is common and carries no information).
fn is_base64_run_byte(b: u8) -> bool {
    base64::char_value(b).is_some() || b == b'=' || b == b'\r' || b == b'\n'
}

/// Whether `b` continues a run's payload — alphabet or a line break, but not
/// `=`: padding only belongs to a run when it's genuinely trailing (see
/// [`next_base64_run`]).
fn is_base64_payload_byte(b: u8) -> bool {
    base64::char_value(b).is_some() || b == b'\r' || b == b'\n'
}

/// Find the next maximal base64 run at or after `from`: alphabet/line-break
/// bytes, plus a trailing `=` padding block — but only when that padding
/// isn't itself followed by more alphabet bytes (§5.2: an unquoted `P=<b64>`
/// assignment must not fuse the `=` into the payload as false padding).
/// Returns `(run_start, run_end, resume_from)`.
fn next_base64_run(content: &[u8], from: usize) -> Option<(usize, usize, usize)> {
    let len = content.len();
    let mut i = from;
    while i < len && !is_base64_run_byte(content[i]) {
        i += 1;
    }
    if i >= len {
        return None;
    }
    let run_start = i;
    loop {
        while i < len && is_base64_payload_byte(content[i]) {
            i += 1;
        }
        if i < len && content[i] == b'=' {
            let eq_start = i;
            while i < len && content[i] == b'=' {
                i += 1;
            }
            let mut lookahead = i;
            while lookahead < len && (content[lookahead] == b'\r' || content[lookahead] == b'\n') {
                lookahead += 1;
            }
            if lookahead < len && base64::char_value(content[lookahead]).is_some() {
                // Padding followed by more payload: not trailing padding —
                // exclude it, and let the next run start fresh right after it.
                return Some((run_start, eq_start, i));
            }
            // Genuine trailing padding: keep it in the run and keep looking
            // for more payload bytes (there normally are none).
            continue;
        }
        return Some((run_start, i, i));
    }
}

/// How many preceding lines [`find_pem_carrier`] will look back through
/// (header lines and a blank separator) to find a `-----BEGIN ` line.
const PEM_LOOKBACK_LINES: usize = 8;

/// Longest line [`find_pem_carrier`] will consider: PEM armor and header
/// lines are short, so a longer one is neither.
const MAX_PEM_LINE_BYTES: usize = 1024;

/// Bytes to search backward from a `;base64,` suffix for a `data:` prefix —
/// mime types are short, so this is generous.
const MAX_MIME_LOOKBACK: usize = 64;

/// What a base64 run is claimed to carry, read once from the text before it:
/// `;base64,` (a data URI) or a nearby `-----BEGIN ` line (PEM armor). Only
/// a claim confirmed by the candidate's *decoded* bytes ([`Carrier::matches`])
/// is actually skipped (§5.2) — a spoofed prefix matches nothing.
enum Carrier {
    None,
    /// The mime type's expected magic bytes, or `None` for an unrecognized
    /// mime (never matches — scored normally).
    DataUri(Option<&'static [u8]>),
    Pem(PemArmor),
}

/// A `-----BEGIN `-armored carrier's shape, as read from its label and
/// header lines.
struct PemArmor {
    /// The label contains `PGP` — an OpenPGP packet, not DER.
    is_pgp: bool,
    /// A `Proc-Type: 4,ENCRYPTED` header — a legacy OpenSSL encrypted key.
    /// Its body is ciphertext with no magic to check.
    is_legacy_encrypted: bool,
}

impl Carrier {
    fn detect(content: &[u8], run_start: usize) -> Carrier {
        if let Some(pem) = find_pem_carrier(content, run_start) {
            return Carrier::Pem(pem);
        }
        if let Some(mime) = find_data_uri_mime(content, run_start) {
            return Carrier::DataUri(data_uri_magic(mime));
        }
        Carrier::None
    }

    /// Whether `decoded` (the run's own decoded start) matches what this
    /// carrier claims to hold.
    fn matches(&self, decoded: &[u8]) -> bool {
        match self {
            Carrier::None => false,
            Carrier::DataUri(magic) => magic.is_some_and(|m| decoded.starts_with(m)),
            Carrier::Pem(pem) => pem.matches(decoded),
        }
    }
}

/// Bytes of decoded prefix needed to check any carrier's magic (the longest
/// is 4 bytes) — enough regardless of which candidate settles the check.
const CARRIER_MAGIC_PREFIX_BYTES: usize = 8;

impl PemArmor {
    fn matches(&self, decoded: &[u8]) -> bool {
        if self.is_legacy_encrypted {
            return true; // ciphertext — no magic to check
        }
        let Some(&first) = decoded.first() else {
            return false;
        };
        if first == 0x30 {
            return true; // DER SEQUENCE
        }
        self.is_pgp && first & 0x80 != 0 // OpenPGP packet tag
    }
}

/// Find a PEM carrier for the run starting at `run_start`: walk backward
/// through the text lines ending there (independent of run boundaries — a
/// run can start mid-line, since a header value's last word is itself a run
/// byte). Up to [`PEM_LOOKBACK_LINES`] blank/`Key: value`-header lines are
/// tolerated before a `-----BEGIN ` line; anything else, including a line
/// longer than [`MAX_PEM_LINE_BYTES`], means no carrier.
fn find_pem_carrier(content: &[u8], run_start: usize) -> Option<PemArmor> {
    let mut end = run_start;
    let mut is_legacy_encrypted = false;

    for _ in 0..PEM_LOOKBACK_LINES {
        if end == 0 {
            return None;
        }
        let floor = end.saturating_sub(MAX_PEM_LINE_BYTES + 1); // +1: the '\n' before a line of exactly the cap
        let start = match content[floor..end].iter().rposition(|&b| b == b'\n') {
            Some(p) => floor + p + 1,
            None if floor == 0 => 0,
            None => return None, // line longer than the cap
        };
        let line_end = if end > start && content[end - 1] == b'\r' {
            end - 1
        } else {
            end
        };
        let line = &content[start..line_end];

        if line.starts_with(b"-----BEGIN ") {
            return Some(PemArmor {
                is_pgp: contains_bytes(line, b"PGP"),
                is_legacy_encrypted,
            });
        }
        if is_blank_line(line) {
            end = start.saturating_sub(1);
            continue;
        }
        if is_header_line(line) {
            if line.starts_with(b"Proc-Type:") && contains_bytes(line, b"ENCRYPTED") {
                is_legacy_encrypted = true;
            }
            end = start.saturating_sub(1);
            continue;
        }
        return None;
    }
    None
}

fn is_blank_line(line: &[u8]) -> bool {
    line.iter().all(|b| b.is_ascii_whitespace())
}

/// Whether `line` looks like a `Key: value` header — a run of alphanumeric/
/// `-` characters, followed by `:`.
fn is_header_line(line: &[u8]) -> bool {
    match line.iter().position(|&b| b == b':') {
        Some(0) => false,
        Some(i) => line[..i]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-'),
        None => false,
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Find the mime type of a data URI whose base64 body starts at `run_start`:
/// the bytes immediately before it must end `;base64,`, with a `data:`
/// prefix within [`MAX_MIME_LOOKBACK`] bytes before that.
fn find_data_uri_mime(content: &[u8], run_start: usize) -> Option<&[u8]> {
    let before = &content[..run_start];
    if !before.ends_with(b";base64,") {
        return None;
    }
    let mime_end = before.len() - b";base64,".len();
    let search_start = mime_end.saturating_sub(MAX_MIME_LOOKBACK);
    let window = &content[search_start..mime_end];
    let data_pos = window.windows(5).rposition(|w| w == b"data:")?;
    Some(&content[search_start + data_pos + 5..mime_end])
}

/// Expected magic bytes for a known mime type carried as a data URI, or
/// `None` for one this rule doesn't recognize.
fn data_uri_magic(mime: &[u8]) -> Option<&'static [u8]> {
    BINARY_MAGICS
        .iter()
        .find(|(mimes, _)| mimes.contains(&mime))
        .map(|&(_, magic)| magic)
}

/// Clip `range`'s end to `ctx`'s real length — tolerates a section size
/// claiming bytes past EOF. Never returns a range with `end < start`.
fn clip_to_file_len(ctx: &ScanContext, range: Range<u64>) -> Range<u64> {
    let file_len = ctx.file_len.unwrap_or(0);
    let end = range.end.min(file_len).max(range.start);
    range.start..end
}

/// Accumulates a `__TEXT` range's whole-range histogram and the highest
/// Miller–Madow entropy over its 64 KiB windows ([`WINDOW_BLOCK_BYTES`]).
/// Results do not depend on how the bytes are split across `feed` calls.
struct TextEntropy {
    counts: [u64; 256],
    len: u64,
    block: [u64; 256],
    block_len: usize,
    prev: Option<[u64; 256]>,
    max_window: Option<f64>,
}

impl TextEntropy {
    fn new() -> Self {
        Self {
            counts: [0; 256],
            len: 0,
            block: [0; 256],
            block_len: 0,
            prev: None,
            max_window: None,
        }
    }

    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let take = bytes.len().min(WINDOW_BLOCK_BYTES - self.block_len);
            let (head, rest) = bytes.split_at(take);
            for &b in head {
                self.block[b as usize] += 1;
            }
            self.block_len += take;
            self.len += take as u64;
            bytes = rest;
            if self.block_len == WINDOW_BLOCK_BYTES {
                self.score_window();
                for (c, b) in self.counts.iter_mut().zip(self.block.iter()) {
                    *c += *b;
                }
                self.prev = Some(self.block);
                self.block = [0; 256];
                self.block_len = 0;
            }
        }
    }

    /// Score the previous block plus the current (possibly partial) one.
    fn score_window(&mut self) {
        let Some(prev) = &self.prev else { return };
        let mut window = *prev;
        for (w, b) in window.iter_mut().zip(self.block.iter()) {
            *w += *b;
        }
        let total = WINDOW_BLOCK_BYTES as u64 + self.block_len as u64;
        let e = miller_madow_entropy(&window, total);
        self.max_window = Some(self.max_window.map_or(e, |m| m.max(e)));
    }

    /// Returns the whole-range histogram, its length, and the best window
    /// entropy (`None` under two blocks).
    fn finish(mut self) -> ([u64; 256], u64, Option<f64>) {
        if self.block_len > 0 {
            if self.len >= 2 * WINDOW_BLOCK_BYTES as u64 {
                self.score_window();
            }
            for (c, b) in self.counts.iter_mut().zip(self.block.iter()) {
                *c += *b;
            }
        }
        let max_window = if self.len >= 2 * WINDOW_BLOCK_BYTES as u64 {
            self.max_window
        } else {
            None
        };
        (self.counts, self.len, max_window)
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    entropy_from_histogram(&counts, data.len() as u64)
}

/// Shannon entropy (bits/byte) of a byte distribution given as a 256-bucket
/// histogram plus its total count — the shared core [`shannon_entropy`] and
/// the streamed Mach-O path both use, so they can't disagree.
fn entropy_from_histogram(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let len = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// [`entropy_from_histogram`] plus the Miller-Madow bias correction
/// `(K - 1) / (2 N ln 2)` (K distinct values seen, N samples): plug-in
/// entropy reads low on small samples, so a short packed `__text` would
/// otherwise miss the packed tier.
fn miller_madow_entropy(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let distinct = counts.iter().filter(|&&c| c > 0).count() as f64;
    entropy_from_histogram(counts, total)
        + (distinct - 1.0) / (2.0 * total as f64 * std::f64::consts::LN_2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::MAX_CONTENT_BYTES;
    use crate::test_support::write_temp_file;
    use std::path::{Path, PathBuf};

    /// `total_len` high-entropy bytes, starting with `magic` — for building
    /// a payload that a content-validated carrier check should recognize.
    fn magic_prefixed_blob(magic: &[u8], total_len: usize) -> Vec<u8> {
        let mut out = magic.to_vec();
        out.extend(high_entropy_blob(total_len - magic.len()));
        out
    }

    fn high_entropy_blob(len: usize) -> Vec<u8> {
        crate::test_support::xorshift_bytes(len)
    }

    #[test]
    fn zero_bytes_all_same_is_low_entropy() {
        let data = vec![0u8; 4096];
        assert!(shannon_entropy(&data) < 1.0);
    }

    #[test]
    fn uniform_random_bytes_are_high_entropy() {
        assert!(shannon_entropy(&high_entropy_blob(65536)) > 7.5);
    }

    /// The histogram helper backing the streamed path must agree exactly
    /// with the whole-buffer helper it now shares its core with.
    #[test]
    fn histogram_entropy_matches_shannon_entropy() {
        let cycled_256: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        for data in [
            vec![0u8; 4096],
            cycled_256,
            high_entropy_blob(65536),
            Vec::new(),
        ] {
            let mut counts = [0u64; 256];
            for &b in &data {
                counts[b as usize] += 1;
            }
            assert_eq!(
                entropy_from_histogram(&counts, data.len() as u64),
                shannon_entropy(&data)
            );
        }
    }

    /// Uniform over the first `symbols` byte values: entropy is exactly
    /// `log2(symbols)` bits/byte.
    fn uniform_over(symbols: usize, len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % symbols) as u8).collect()
    }

    fn text_weight(text: &[u8]) -> Option<i32> {
        let (image, _) = crate::macho::tests_support::synth_macho_64(text);
        let path = write_temp_file("entropy-tier", &image);
        let ctx = ScanContext::load(&path);
        let weight = HighEntropyRule.evaluate(&ctx).unwrap().map(|s| s.weight);
        let _ = std::fs::remove_file(&path);
        weight
    }

    /// Small samples read low under plug-in entropy (256 random bytes
    /// ~7.18); the tier is decided on the bias-corrected value.
    #[test]
    fn small_packed_text_reaches_the_packed_tier() {
        assert_eq!(
            text_weight(&high_entropy_blob(256)),
            Some(TEXT_PACKED_WEIGHT)
        );
        assert_eq!(
            text_weight(&high_entropy_blob(384)),
            Some(TEXT_PACKED_WEIGHT)
        );
        assert_eq!(
            text_weight(&uniform_over(147, 4096 / 147 * 147)),
            Some(TEXT_ELEVATED_WEIGHT)
        );
    }

    #[test]
    fn macho_text_entropy_tiers() {
        // log2(147) = 7.20, log2(100) = 6.64.
        assert_eq!(text_weight(&uniform_over(100, 6000)), None);
        assert_eq!(
            text_weight(&uniform_over(147, 147 * 40)),
            Some(TEXT_ELEVATED_WEIGHT)
        );
        assert_eq!(
            text_weight(&high_entropy_blob(65536)),
            Some(TEXT_PACKED_WEIGHT)
        );
    }

    #[test]
    fn fat_binary_best_slice_decides_the_text_tier() {
        let (elevated, _) =
            crate::macho::tests_support::synth_macho_64(&uniform_over(147, 147 * 40));
        let (packed, _) = crate::macho::tests_support::synth_macho_64(&high_entropy_blob(65536));
        for (tag, slices) in [
            ("elevated-first", [&elevated[..], &packed[..]]),
            ("packed-first", [&packed[..], &elevated[..]]),
        ] {
            let fat = crate::macho::tests_support::synth_fat(&slices);
            let path = write_temp_file(&format!("entropy-tier-fat-{tag}"), &fat);
            let ctx = ScanContext::load(&path);
            let signal = HighEntropyRule.evaluate(&ctx).unwrap().unwrap();
            assert_eq!(signal.weight, TEXT_PACKED_WEIGHT, "{tag}");
            let _ = std::fs::remove_file(&path);
        }
    }

    fn text_signal(text: &[u8]) -> Option<MatchedSignal> {
        let (image, _) = crate::macho::tests_support::synth_macho_64(text);
        let path = write_temp_file("entropy-signal", &image);
        let ctx = ScanContext::load(&path);
        let signal = HighEntropyRule.evaluate(&ctx).unwrap();
        let _ = std::fs::remove_file(&path);
        signal
    }

    /// `low_len` code-like bytes (about 5.6 bits/byte) then `random_len`
    /// random bytes: the whole section stays under the elevated gate while
    /// a window over the random tail reaches about 8.0.
    fn code_then_random(low_len: usize, random_len: usize) -> Vec<u8> {
        let mut text = uniform_over(50, low_len);
        text.extend(high_entropy_blob(random_len));
        text
    }

    const KIB: usize = 1024;

    #[test]
    fn packed_region_inside_low_entropy_text_is_elevated() {
        let text = code_then_random(448 * KIB, 96 * KIB);
        assert!(shannon_entropy(&text) < ENTROPY_THRESHOLD);
        let signal = text_signal(&text).expect("the random window should be found");
        assert_eq!(signal.weight, TEXT_ELEVATED_WEIGHT);
        assert!(
            signal.description.contains("window entropy: 8.0"),
            "{}",
            signal.description
        );
    }

    /// #67: 87% random then 13% zeros reads just under the packed gate
    /// whole-section; it must not reach the packed weight.
    #[test]
    fn padded_packed_payload_is_elevated_not_packed() {
        let total = 512 * KIB;
        let random = total * 87 / 100;
        let mut text = high_entropy_blob(random);
        text.resize(total, 0);
        assert_eq!(text_weight(&text), Some(TEXT_ELEVATED_WEIGHT));
    }

    #[test]
    fn uniform_low_entropy_text_has_no_window_signal() {
        assert_eq!(text_weight(&uniform_over(100, 512 * KIB)), None);
    }

    #[test]
    fn text_under_64kib_gets_no_window_score() {
        let text = code_then_random(56 * KIB, 4 * KIB);
        assert!(shannon_entropy(&text) < ENTROPY_THRESHOLD);
        let mut acc = TextEntropy::new();
        acc.feed(&text);
        assert_eq!(acc.finish().2, None);
        assert_eq!(text_weight(&text), None);
        // Whole-section rules still apply to a short, wholly random section.
        assert_eq!(
            text_weight(&high_entropy_blob(60 * KIB)),
            Some(TEXT_PACKED_WEIGHT)
        );
    }

    #[test]
    fn streamed_windowed_text_matches_the_resident_score() {
        let payload = code_then_random(MAX_CONTENT_BYTES + 512 * KIB, 96 * KIB);
        let (image, range) = crate::macho::tests_support::synth_macho_64(&payload);
        let path = write_temp_file("entropy-window-streamed", &image);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let streamed = HighEntropyRule
            .evaluate(&ctx)
            .unwrap()
            .expect("the window past the 8 MiB capture should be found");
        let (_, resident) = HighEntropyRule
            .macho_signal_from_content(&image, range, None)
            .expect("resident score");
        assert_eq!(streamed.weight, TEXT_ELEVATED_WEIGHT);
        assert_eq!(streamed.weight, resident.weight);
        assert_eq!(streamed.description, resident.description);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn text_entropy_is_independent_of_chunking() {
        let text = code_then_random(300 * KIB, 100 * KIB);
        let finish = |chunks: &mut dyn FnMut(&mut TextEntropy)| {
            let mut acc = TextEntropy::new();
            chunks(&mut acc);
            acc.finish()
        };
        let one = finish(&mut |a| a.feed(&text));
        let odd = finish(&mut |a| text.chunks(7001).for_each(|c| a.feed(c)));
        let path = write_temp_file("entropy-chunking", &text);
        let ctx = ScanContext::load(&path);
        let streamed = finish(&mut |a| {
            assert!(ctx.for_each_window(0..text.len() as u64, 0, |w, _| a.feed(w)));
        });
        let _ = std::fs::remove_file(&path);
        assert!(one.2.is_some());
        assert_eq!(one, odd);
        assert_eq!(one, streamed);
    }

    #[test]
    fn fat_binary_windowed_slice_beats_a_weaker_whole_tier() {
        let (elevated, _) =
            crate::macho::tests_support::synth_macho_64(&uniform_over(147, 147 * 40));
        let (windowed, _) =
            crate::macho::tests_support::synth_macho_64(&code_then_random(448 * KIB, 96 * KIB));
        for (tag, slices) in [
            ("elevated-first", [&elevated[..], &windowed[..]]),
            ("windowed-first", [&windowed[..], &elevated[..]]),
        ] {
            let fat = crate::macho::tests_support::synth_fat(&slices);
            let path = write_temp_file(&format!("entropy-fat-window-{tag}"), &fat);
            let ctx = ScanContext::load(&path);
            let signal = HighEntropyRule.evaluate(&ctx).unwrap().unwrap();
            assert_eq!(signal.weight, TEXT_ELEVATED_WEIGHT, "{tag}");
            assert!(signal.description.contains("window entropy"), "{tag}");
            let _ = std::fs::remove_file(&path);
        }
    }

    #[test]
    fn fat_binary_whole_packed_slice_beats_a_windowed_slice() {
        let (packed, _) = crate::macho::tests_support::synth_macho_64(&high_entropy_blob(65536));
        let (windowed, _) =
            crate::macho::tests_support::synth_macho_64(&code_then_random(448 * KIB, 96 * KIB));
        for (tag, slices) in [
            ("packed-first", [&packed[..], &windowed[..]]),
            ("windowed-first", [&windowed[..], &packed[..]]),
        ] {
            let fat = crate::macho::tests_support::synth_fat(&slices);
            let path = write_temp_file(&format!("entropy-fat-packed-{tag}"), &fat);
            let ctx = ScanContext::load(&path);
            let signal = HighEntropyRule.evaluate(&ctx).unwrap().unwrap();
            assert_eq!(signal.weight, TEXT_PACKED_WEIGHT, "{tag}");
            let _ = std::fs::remove_file(&path);
        }
    }

    /// A `__TEXT` section whose 8 MiB-clipped prefix is pure low-entropy but
    /// whose full range (low prefix + a high-entropy tail past 8 MiB) reaches
    /// the elevated tier overall: streaming the whole section, not just the
    /// captured prefix, is what makes this fire (§5.2, #45).
    #[test]
    fn macho_text_past_8mib_is_scored_on_the_whole_section() {
        // LOW_LEN fills the entire captured prefix with zero bytes; HIGH_LEN
        // (divisible by 256) cycles every byte value equally past it, giving
        // an exact combined histogram: 7.293 bits/byte overall (elevated tier)
        // while the zero-only clipped prefix reads as 0.0.
        const LOW_LEN: usize = MAX_CONTENT_BYTES;
        const HIGH_LEN: usize = 40 * 1024 * 1024;
        let mut payload = vec![0u8; LOW_LEN];
        payload.extend((0..HIGH_LEN as u32).map(|i| (i % 256) as u8));
        let full_len = payload.len() as u64;

        let (image_bytes, range) = crate::macho::tests_support::synth_macho_64(&payload);
        let path = write_temp_file("macho-past-8mib", &image_bytes);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated, "fixture must exceed the 8 MiB capture");

        // Confirm the premise: the clipped-to-content prefix alone is below
        // the threshold, so only streaming past it can find the signal.
        let content = ctx.content.as_ref().unwrap();
        let prefix_start = usize::try_from(range.start).unwrap();
        assert!(shannon_entropy(&content[prefix_start..]) < ENTROPY_THRESHOLD);
        assert!(shannon_entropy(&payload) >= ENTROPY_THRESHOLD);

        let signal = HighEntropyRule
            .evaluate(&ctx)
            .unwrap()
            .expect("the whole __TEXT section should clear the threshold");
        assert_eq!(signal.weight, TEXT_ELEVATED_WEIGHT);
        assert!(signal
            .description
            .contains(&format!("over {full_len} bytes")));
        assert!(HighEntropyRule.covers_truncation(&ctx));

        let _ = std::fs::remove_file(&path);
    }

    /// A stream failure partway through `__TEXT` (the file shrinks after
    /// `ScanContext::load`, so reads past the captured prefix start failing)
    /// must not discard the score the content-only path would have found in
    /// that prefix, and must not claim `covers_truncation` (§10/§11.8).
    #[test]
    fn stream_failure_falls_back_to_the_content_only_score() {
        const TOTAL_LEN: usize = MAX_CONTENT_BYTES + 1024 * 1024;
        let payload = high_entropy_blob(TOTAL_LEN);
        let (image_bytes, range) = crate::macho::tests_support::synth_macho_64(&payload);
        assert!(
            (range.end - range.start) as usize > MAX_CONTENT_BYTES,
            "the __TEXT range must extend past the prefix to exercise streaming"
        );

        let path = write_temp_file("entropy-stream-failure", &image_bytes);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);

        // Confirm the premise: the in-content portion alone clears the
        // threshold, so the fallback (not the streamed read) is what finds it.
        let content = ctx.content.as_ref().unwrap();
        let start = usize::try_from(range.start).unwrap();
        assert!(shannon_entropy(&content[start..]) >= ENTROPY_THRESHOLD);

        // Shrink the file out from under the already-loaded context: reads
        // past the captured prefix now fail.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(8)
            .unwrap();

        let signal = HighEntropyRule
            .evaluate(&ctx)
            .unwrap()
            .expect("the in-prefix portion should still score");
        assert!(signal.description.contains("__TEXT"));
        assert!(!HighEntropyRule.covers_truncation(&ctx));

        let _ = std::fs::remove_file(&path);
    }

    /// A failed stream leaves only the resident prefix scored: an elevated
    /// result there is `NotApplicable`, since the whole section may be
    /// packed (§10/§11.8).
    #[test]
    fn stream_failure_with_an_elevated_prefix_is_not_applicable() {
        const TOTAL_LEN: usize = MAX_CONTENT_BYTES + 1024 * 1024;
        let payload = uniform_over(147, TOTAL_LEN);
        let (image_bytes, _) = crate::macho::tests_support::synth_macho_64(&payload);
        let path = write_temp_file("entropy-stream-failure-elevated", &image_bytes);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(8)
            .unwrap();
        assert!(matches!(
            HighEntropyRule.evaluate(&ctx),
            Err(RuleOutcome::NotApplicable)
        ));
        let _ = std::fs::remove_file(&path);
    }

    /// A fat binary's first slice is small and low-entropy, entirely inside
    /// the 8 MiB prefix; its second slice's `__TEXT` is high-entropy and
    /// starts past it. Scoring only `images.first()` would miss the second
    /// slice entirely (§5.2, #45).
    #[test]
    fn a_fat_slices_high_entropy_text_past_8mib_is_scored() {
        let (mut first, _) = crate::macho::tests_support::synth_macho_64(&[0u8; 64]);
        // Padding appended past the slice's own declared structure — pushes
        // where the second slice starts in the fat file without touching the
        // first slice's own (small, low-entropy) __TEXT range.
        first.resize(first.len() + MAX_CONTENT_BYTES + 4096, 0);
        let (second, _) = crate::macho::tests_support::synth_macho_64(&high_entropy_blob(4096));
        let fat = crate::macho::tests_support::synth_fat(&[&first, &second]);

        let path = write_temp_file("fat-second-text-past-8mib", &fat);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);

        let signal = HighEntropyRule
            .evaluate(&ctx)
            .unwrap()
            .expect("the second slice's high-entropy __TEXT should be found");
        assert!(signal.description.contains("__TEXT"));
        assert!(HighEntropyRule.covers_truncation(&ctx));

        let _ = std::fs::remove_file(&path);
    }

    /// Same fixture, but the second slice's `__TEXT` stream fails partway
    /// (the file shrinks after load): `covers_truncation` must not claim a
    /// slice was examined that couldn't be (§10/§11.8).
    #[test]
    fn a_fat_slices_second_text_stream_failure_does_not_cover_truncation() {
        let (mut first, _) = crate::macho::tests_support::synth_macho_64(&[0u8; 64]);
        first.resize(first.len() + MAX_CONTENT_BYTES + 4096, 0);
        let (second, _) = crate::macho::tests_support::synth_macho_64(&high_entropy_blob(4096));
        let fat = crate::macho::tests_support::synth_fat(&[&first, &second]);

        let path = write_temp_file("fat-second-text-stream-failure", &fat);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);

        // Shrink the file out from under the already-loaded context: reads
        // past the captured prefix (the second slice's __TEXT) now fail.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(8)
            .unwrap();

        let _ = HighEntropyRule.evaluate(&ctx).unwrap();
        assert!(!HighEntropyRule.covers_truncation(&ctx));

        let _ = std::fs::remove_file(&path);
    }

    /// Images cloned from one synthetic Mach-O with `count` distinct-offset
    /// `__TEXT` ranges, each `len` bytes long, plus a context whose declared
    /// file length is `file_len`.
    fn many_images_ctx(
        count: u64,
        len: u64,
        file_len: u64,
    ) -> (ScanContext, Vec<macho::MachOImage>) {
        let (bytes, _) = crate::macho::tests_support::synth_macho_64(&[0u8; 64]);
        let mut ctx = make_ctx("fat", bytes);
        let base = ctx.macho().images[0].clone();
        ctx.file_len = Some(file_len);
        let images = (0..count)
            .map(|i| {
                let mut image = base.clone();
                image.text_range = Some(i * 4096..i * 4096 + len);
                image
            })
            .collect();
        (ctx, images)
    }

    /// Hostile fat file: 1024 distinct-offset slices each declaring a huge
    /// `__TEXT` clipped to EOF. The scored set stays within the total
    /// budget and the rest are reported as left out.
    #[test]
    fn many_overlapping_slice_texts_are_bounded_by_the_total_budget() {
        let file_len = MAX_STREAM_BYTES / 4;
        let (ctx, images) = many_images_ctx(1024, u64::MAX / 2, file_len);
        let (included, all_scored) = budgeted_ranges(&ctx, &images);
        let total: u64 = included.iter().map(|(_, r)| r.end - r.start).sum();
        assert!(total <= MAX_STREAM_BYTES);
        assert!(included.len() < images.len());
        assert!(!all_scored);
    }

    /// Context holding `content` (high-entropy) with a declared file length
    /// of `file_len`, plus a base image to clone `__TEXT` ranges onto.
    fn packed_ctx(file_len: u64) -> (ScanContext, macho::MachOImage) {
        let (bytes, _) = crate::macho::tests_support::synth_macho_64(&[0u8; 64]);
        let base = make_ctx("m", bytes).macho().images[0].clone();
        let mut ctx = make_ctx("fat", high_entropy_blob(4096));
        ctx.file_len = Some(file_len);
        (ctx, base)
    }

    /// One `__TEXT` declared larger than the whole budget: its resident
    /// packed prefix is still scored, and coverage is not claimed.
    #[test]
    fn oversized_text_still_scores_its_resident_prefix() {
        let (ctx, base) = packed_ctx(MAX_STREAM_BYTES + 4096);
        let mut image = base;
        image.text_range = Some(0..MAX_STREAM_BYTES + 4096);
        let images = [image];
        let rule = HighEntropyRule;
        let content = ctx.content.as_ref().unwrap();
        assert!(rule
            .eval_macho_images(&ctx, content, &images)
            .unwrap()
            .is_some());
        assert!(!budgeted_ranges(&ctx, &images).1);
    }

    /// A decoy first slice declaring a huge `__TEXT` doesn't hide a later,
    /// fully resident packed slice.
    #[test]
    fn decoy_huge_first_slice_does_not_hide_a_resident_packed_slice() {
        let (ctx, base) = packed_ctx(MAX_STREAM_BYTES + 4096);
        let mut decoy = base.clone();
        decoy.text_range = Some(4096..MAX_STREAM_BYTES + 4096);
        let mut packed = base;
        packed.text_range = Some(0..4096);
        let images = [decoy, packed];
        let content = ctx.content.as_ref().unwrap();
        let signal = HighEntropyRule.eval_macho_images(&ctx, content, &images);
        assert!(signal.unwrap().is_some());
    }

    /// Non-truncated ctx with `content` held, a decoy range that nearly
    /// exhausts the budget, and a second range the budget leaves out.
    /// `with_resident` adds a resident range scored before the decoy.
    fn left_out_range_images(
        content: Vec<u8>,
        with_resident: bool,
    ) -> (ScanContext, Vec<macho::MachOImage>) {
        let held = content.len() as u64;
        let (mut ctx, base) = packed_ctx(held + MAX_STREAM_BYTES);
        ctx.content = Some(content);
        let resident = if with_resident { held } else { 0 };
        let mut decoy = base.clone();
        decoy.text_range = Some(held..held + MAX_STREAM_BYTES - resident - 100);
        let mut left_out = base.clone();
        left_out.text_range = Some(1..held + MAX_STREAM_BYTES - 50);
        let mut images = vec![decoy, left_out];
        if with_resident {
            let mut first = base;
            first.text_range = Some(0..held);
            images.push(first);
        }
        (ctx, images)
    }

    /// Non-truncated file whose decoys exhaust the budget and leave a range
    /// out: no finding means `NotApplicable`, not clean.
    #[test]
    fn budget_left_out_range_without_a_match_is_not_applicable() {
        let (ctx, images) = left_out_range_images(vec![0u8; 4096], false);
        assert!(!budgeted_ranges(&ctx, &images).1);
        let content = ctx.content.as_ref().unwrap();
        assert!(matches!(
            HighEntropyRule.eval_macho_images(&ctx, content, &images),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// A finding in an included range stands even when another range was
    /// left out by the budget.
    #[test]
    fn budget_left_out_range_does_not_suppress_a_match() {
        let (ctx, images) = left_out_range_images(high_entropy_blob(4096), true);
        assert!(!budgeted_ranges(&ctx, &images).1);
        let content = ctx.content.as_ref().unwrap();
        let signal = HighEntropyRule.eval_macho_images(&ctx, content, &images);
        assert!(signal.unwrap().is_some());
    }

    /// An elevated-tier match does not stand over a range the budget left
    /// out, but a packed-tier one does (§10/§11.8).
    #[test]
    fn elevated_match_does_not_stand_over_a_left_out_range() {
        let (ctx, images) = left_out_range_images(uniform_over(147, 4116), true);
        assert!(!budgeted_ranges(&ctx, &images).1);
        let content = ctx.content.as_ref().unwrap();
        assert!(matches!(
            HighEntropyRule.eval_macho_images(&ctx, content, &images),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// Slices clipping to the same absolute range are scored once.
    #[test]
    fn identical_clipped_ranges_are_deduped() {
        let (ctx, mut images) = many_images_ctx(3, 100, 4096 * 4);
        for image in &mut images {
            image.text_range = Some(0..100);
        }
        let (included, all_scored) = budgeted_ranges(&ctx, &images);
        assert_eq!(included.len(), 1);
        assert!(all_scored);
    }

    /// A truncated embedded member whose `__TEXT` lies past the capture
    /// can't be claimed as covered, even though the clipped range is empty.
    #[test]
    fn truncated_embedded_text_past_the_capture_does_not_cover_truncation() {
        let (bytes, range) = crate::macho::tests_support::synth_macho_64(&high_entropy_blob(4096));
        let cut = bytes[..range.start as usize].to_vec();
        let ctx = ScanContext::from_embedded_bytes("x.pkg!member", cut, true);
        assert!(!ctx.macho().images.is_empty());
        assert!(!HighEntropyRule.covers_truncation(&ctx));
    }

    /// A truncated file with no Mach-O magic and no text-like structure is
    /// opaque-binary territory: never scored, and unread bytes past 8 MiB
    /// can't change that, so the rule covers the truncation.
    #[test]
    fn truncated_opaque_binary_is_not_scored_and_covers_truncation() {
        let path = write_temp_file(
            "opaque-past-8mib",
            &high_entropy_blob(MAX_CONTENT_BYTES + 1024 * 1024),
        );
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);

        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
        assert!(HighEntropyRule.covers_truncation(&ctx));

        let _ = std::fs::remove_file(&path);
    }

    /// A truncated script/text file stays `Partial` by design: the
    /// whole-content and base64 checks only see the captured prefix, so
    /// bytes past it could still hide a payload.
    #[test]
    fn truncated_script_does_not_cover_truncation() {
        let mut content = b"#!/bin/sh\n".to_vec();
        while content.len() <= MAX_CONTENT_BYTES {
            content.extend_from_slice(b"# padding line to keep this script large.\n");
        }
        let path = write_temp_file("script-past-8mib", &content);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);

        assert!(!HighEntropyRule.covers_truncation(&ctx));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn opaque_high_entropy_binary_is_not_scored() {
        // The false positive the old whole-file rule had.
        let ctx = ScanContext {
            path: PathBuf::from("archive.bin"),
            content: Some(high_entropy_blob(4096)),
            truncated: false,
            file_len: Some(4096),
            identity: None,
            source: crate::context::ContentSource::File,
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
            stream_failures: std::sync::Mutex::new(Vec::new()),
        };
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
    }

    #[test]
    fn high_entropy_payload_in_a_script_is_scored() {
        let mut content = b"#!/bin/sh\n# stage two:\n".to_vec();
        content.extend_from_slice(&high_entropy_blob(4096));
        let file_len = Some(content.len() as u64);
        let ctx = ScanContext {
            path: PathBuf::from("dropper.sh"),
            content: Some(content),
            truncated: false,
            file_len,
            identity: None,
            source: crate::context::ContentSource::File,
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
            stream_failures: std::sync::Mutex::new(Vec::new()),
        };
        let signal = HighEntropyRule.evaluate(&ctx).unwrap();
        assert!(signal.is_some(), "script with embedded blob should score");
    }

    /// PNG whose first 512 bytes are mostly a text chunk but include the
    /// header's NULs, then a high-entropy body.
    fn png_with_text_and_noise() -> Vec<u8> {
        let mut c = b"\x89PNG\r\n\x1a\n".to_vec();
        c.extend_from_slice(&[0, 0, 0, 13]);
        c.extend_from_slice(b"IHDR");
        c.extend_from_slice(&[0, 0, 1, 0, 0, 0, 1, 0, 8, 2, 0, 0, 0]);
        c.extend_from_slice(b"tEXtComment\0");
        c.extend_from_slice(
            "generated by a friendly image editor "
                .repeat(14)
                .as_bytes(),
        );
        c.extend_from_slice(&high_entropy_blob(4096));
        c
    }

    fn text_with_blob() -> Vec<u8> {
        let mut c = "plain notes about nothing in particular\n"
            .repeat(20)
            .into_bytes();
        c.extend_from_slice(&high_entropy_blob(4096));
        c
    }

    fn weight_of(path: &str, content: Vec<u8>) -> Option<i32> {
        let ctx = make_ctx(path, content);
        HighEntropyRule.evaluate(&ctx).unwrap().map(|s| s.weight)
    }

    #[test]
    fn png_with_text_metadata_is_demoted() {
        let content = png_with_text_and_noise();
        assert_eq!(
            classify_text(&content, Path::new("a.png")),
            TextClass::Text {
                container_evidence: true
            }
        );
        assert_eq!(weight_of("a.png", content), Some(CONTAINER_BLOB_WEIGHT));
    }

    #[test]
    fn pdf_with_binary_stream_is_demoted() {
        let mut content = b"%PDF-1.7\n".to_vec();
        content.extend_from_slice(
            "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
                .repeat(12)
                .as_bytes(),
        );
        content.extend_from_slice(b"stream\n");
        content.extend_from_slice(&high_entropy_blob(4096));
        content.extend_from_slice(b"\nendstream\n");
        assert_eq!(weight_of("a.pdf", content), Some(CONTAINER_BLOB_WEIGHT));
    }

    #[test]
    fn extensionless_text_with_blob_keeps_full_weight() {
        assert_eq!(
            weight_of("notes", text_with_blob()),
            Some(EMBEDDED_BLOB_WEIGHT)
        );
    }

    #[test]
    fn txt_with_blob_keeps_full_weight() {
        assert_eq!(
            weight_of("notes.txt", text_with_blob()),
            Some(EMBEDDED_BLOB_WEIGHT)
        );
    }

    #[test]
    fn shebang_script_with_nul_is_never_demoted() {
        let mut content = b"#!/bin/sh\n\0".to_vec();
        content.extend_from_slice(&high_entropy_blob(4096));
        assert_eq!(weight_of("x", content), Some(EMBEDDED_BLOB_WEIGHT));
    }

    #[test]
    fn script_extension_with_nul_is_never_demoted() {
        let mut content = b"echo hi\n\0".to_vec();
        content.extend_from_slice(&high_entropy_blob(4096));
        assert_eq!(weight_of("x.sh", content), Some(EMBEDDED_BLOB_WEIGHT));
    }

    #[test]
    fn nul_past_the_prefix_is_not_evidence() {
        let mut content = "plain notes about nothing in particular\n"
            .repeat(20)
            .into_bytes();
        assert!(content.len() > 512);
        content.push(0);
        content.extend_from_slice(&high_entropy_blob(4096));
        assert_eq!(weight_of("notes", content), Some(EMBEDDED_BLOB_WEIGHT));
    }

    #[test]
    fn truncated_text_headed_file_with_nul_does_not_cover_truncation() {
        let mut content = b"header\0 of a text-looking file\n".to_vec();
        while content.len() <= MAX_CONTENT_BYTES {
            content.extend_from_slice(b"padding line to keep this file large.\n");
        }
        let path = write_temp_file("nul-text-past-8mib", &content);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        assert!(!HighEntropyRule.covers_truncation(&ctx));
        let _ = std::fs::remove_file(&path);
    }

    fn scan_default(path: &str, content: Vec<u8>) -> crate::model::ScanResult {
        let ctx = make_ctx(path, content);
        crate::scan::scan_context(&ctx, &crate::rules::default_ruleset())
    }

    fn polyglot(first: &[u8], second: &[u8]) -> Vec<u8> {
        let mut c = first.to_vec();
        c.extend_from_slice(b"tail -c +600 \"$0\" | base64 -D | sh; exit\n");
        c.extend_from_slice(second);
        c.extend_from_slice(b"\n");
        c.extend_from_slice(
            "# padding so the header stays mostly text\n"
                .repeat(14)
                .as_bytes(),
        );
        c.extend_from_slice(&high_entropy_blob(4096));
        c
    }

    #[test]
    fn polyglot_dropper_with_nul_on_line_two_still_notifies() {
        let r = scan_default("dropper", polyglot(b"", b"\0"));
        let hec = r.signals.iter().find(|s| s.id == "high-entropy-content");
        assert_eq!(hec.map(|s| s.weight), Some(CONTAINER_BLOB_WEIGHT));
        assert!(r.signals.iter().any(|s| s.id == "suspicious-strings"));
        assert!(matches!(
            r.recommendation,
            crate::model::Recommendation::Notify
                | crate::model::Recommendation::NotifyAndSuggestQuarantine
        ));
    }

    #[test]
    fn polyglot_dropper_with_png_header_line_still_notifies() {
        let r = scan_default("dropper", polyglot(b"\x89PNG\r\n\x1a\n", b"# x"));
        let hec = r.signals.iter().find(|s| s.id == "high-entropy-content");
        assert_eq!(hec.map(|s| s.weight), Some(CONTAINER_BLOB_WEIGHT));
        assert!(matches!(
            r.recommendation,
            crate::model::Recommendation::Notify
                | crate::model::Recommendation::NotifyAndSuggestQuarantine
        ));
    }

    #[test]
    fn high_entropy_macho_text_is_scored() {
        let (image_bytes, _range) =
            crate::macho::tests_support::synth_macho_64(&high_entropy_blob(4096));
        let file_len = Some(image_bytes.len() as u64);
        let ctx = ScanContext {
            path: PathBuf::from("packed"),
            content: Some(image_bytes),
            truncated: false,
            file_len,
            identity: None,
            source: crate::context::ContentSource::File,
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
            stream_failures: std::sync::Mutex::new(Vec::new()),
        };
        let signal = HighEntropyRule.evaluate(&ctx).unwrap();
        assert!(
            signal.is_some(),
            "Mach-O with packed __TEXT should score high entropy"
        );
        assert!(signal.unwrap().description.contains("__TEXT"));
    }

    fn make_ctx(path: &str, content: Vec<u8>) -> ScanContext {
        let file_len = Some(content.len() as u64);
        ScanContext {
            path: PathBuf::from(path),
            content: Some(content),
            truncated: false,
            file_len,
            identity: None,
            source: crate::context::ContentSource::File,
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
            stream_failures: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Minimal standard base64 encoder (RFC 4648 §4), test-only — mirrors
    /// [`base64::decode_bounded`] so the round trip pins both directions.
    fn base64_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[((n >> 6) & 0x3f) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(n & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    fn wrap(s: &str, width: usize) -> String {
        let mut out = String::new();
        for (i, c) in s.chars().enumerate() {
            if i > 0 && i % width == 0 {
                out.push('\n');
            }
            out.push(c);
        }
        out
    }

    // Decoder-level tests (RFC vectors, invalid/padding handling, output cap)
    // live in `crate::base64`'s own test module now that it owns the decoder.

    // --- rule ---

    #[test]
    fn base64_payload_in_a_script_is_scored() {
        let payload = high_entropy_blob(2048);
        let encoded = wrap(&base64_encode(&payload), 76);
        let content = format!(
            "#!/bin/sh\n# stage two, base64-encoded:\nP=\"{encoded}\"\n\
             echo \"$P\" | base64 -d | sh\n"
        );
        let ctx = make_ctx("dropper.sh", content.into_bytes());
        let signal = HighEntropyRule.evaluate(&ctx).unwrap();
        assert!(signal.is_some(), "base64 payload in a script should score");
        let signal = signal.unwrap();
        assert!(signal.description.contains("decoded bytes"));
        assert_eq!(
            signal.weight, BASE64_PAYLOAD_WEIGHT,
            "base64 path is corroboration-only, unlike the whole-content/__TEXT paths"
        );
    }

    #[test]
    fn base64_payload_in_a_data_uri_is_not_scored() {
        // Decoded bytes carry the real PNG signature — a genuine carrier.
        let payload = magic_prefixed_blob(b"\x89PNG\r\n\x1a\n", 1536);
        let encoded = base64_encode(&payload);
        let content = format!("export const icon = \"data:image/png;base64,{encoded}\";\n");
        let ctx = make_ctx("icon.js", content.into_bytes());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
    }

    #[test]
    fn png_data_uri_wrapped_across_multiple_segments_is_not_scored() {
        // Two different wrap widths mid-stream force the run to split into
        // more than one segment; the carrier decision is made once for the
        // whole run, so both segments stay skipped.
        let payload = magic_prefixed_blob(b"\x89PNG\r\n\x1a\n", 4096);
        let encoded = base64_encode(&payload);
        let mid = (encoded.len() / 2 / 4) * 4; // keep the split on a 4-char boundary
        let (first_half, second_half) = encoded.split_at(mid);
        let wrapped = format!("{}\n{}", wrap(first_half, 76), wrap(second_half, 50));
        let content = format!("export const icon = \"data:image/png;base64,{wrapped}\";\n");
        let ctx = make_ctx("icon.js", content.into_bytes());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
    }

    #[test]
    fn spoofed_data_uri_prefix_is_scored() {
        // Claims image/png but the decoded bytes are a gzip stream — the
        // carrier claim doesn't match, so it's scored like any other payload.
        let payload = magic_prefixed_blob(b"\x1f\x8b", 2048);
        let encoded = wrap(&base64_encode(&payload), 76);
        let content =
            format!("P=\";base64,{encoded}\"\necho \"${{P#*,}}\" | base64 -d | gunzip | sh\n");
        let ctx = make_ctx("dropper.sh", content.into_bytes());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_some());
    }

    #[test]
    fn base64_payload_in_pem_armor_is_not_scored() {
        // Decoded bytes carry a DER SEQUENCE header — a genuine carrier.
        let payload = magic_prefixed_blob(&[0x30, 0x82, 0x00, 0x00], 1536);
        let encoded = wrap(&base64_encode(&payload), 64);
        let content = format!(
            "#!/bin/sh\ncat > ca.pem <<'EOF'\n-----BEGIN CERTIFICATE-----\n\
             {encoded}\n-----END CERTIFICATE-----\nEOF\n"
        );
        let ctx = make_ctx("pem_bundle.sh", content.into_bytes());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
    }

    #[test]
    fn spoofed_pem_begin_is_scored() {
        // A `-----BEGIN FOO-----` label in front of a gzip payload: found as
        // a candidate PEM carrier, but the decoded bytes match neither DER
        // nor PGP, so it's scored normally.
        let payload = magic_prefixed_blob(b"\x1f\x8b", 2048);
        let encoded = wrap(&base64_encode(&payload), 64);
        let content = format!(
            "#!/bin/sh\ncat > payload.bin <<'EOF'\n-----BEGIN FOO-----\n\
             {encoded}\n-----END FOO-----\nEOF\n"
        );
        let ctx = make_ctx("spoofed.sh", content.into_bytes());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_some());
    }

    #[test]
    fn pgp_public_key_block_is_not_scored() {
        // Decoded first byte 0x99: an OpenPGP old-format packet tag (high
        // bit set) — headers and a blank line separate BEGIN from the body.
        let payload = magic_prefixed_blob(&[0x99], 1536);
        let encoded = wrap(&base64_encode(&payload), 64);
        let content = format!(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n\
             Comment: exported\n\n{encoded}\n-----END PGP PUBLIC KEY BLOCK-----\n"
        );
        let ctx = make_ctx("key.asc", content.into_bytes());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
    }

    #[test]
    fn legacy_encrypted_pem_is_not_scored() {
        // `Proc-Type: 4,ENCRYPTED` marks ciphertext with no magic to expect.
        let payload = high_entropy_blob(1536);
        let encoded = wrap(&base64_encode(&payload), 64);
        let content = format!(
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
             DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n\
             {encoded}\n-----END RSA PRIVATE KEY-----\n"
        );
        let ctx = make_ctx("key.pem", content.into_bytes());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
    }

    /// A long single line holding many qualifying base64-alphabet runs must
    /// not make carrier detection quadratic (#59): every run reaches
    /// `Carrier::detect`, which used to search back to the line start.
    #[test]
    fn long_single_line_of_many_qualifying_runs_evaluates_quickly() {
        let content = format!("{};", "A".repeat(1100)).repeat(3800).into_bytes();
        assert!(content.len() > 4_000_000 && !content.contains(&b'\n'));
        let ctx = make_ctx("bundle.min.js", content);
        let start = std::time::Instant::now();
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "took {:?}",
            start.elapsed()
        );
    }

    /// A PEM header line of exactly the cap is armor (the block behind it is
    /// a carrier); one byte longer is not (the block is scored).
    #[test]
    fn a_pem_header_line_at_and_over_the_cap() {
        let payload = magic_prefixed_blob(&[0x30, 0x82, 0x00, 0x00], 1536);
        let encoded = wrap(&base64_encode(&payload), 64);
        let mk = |header_len: usize| {
            let header = format!("Comment:{}", " ".repeat(header_len - "Comment:".len()));
            let content = format!(
                "#!/bin/sh\n-----BEGIN CERTIFICATE-----\n{header}\n\n{encoded}\n\
                 -----END CERTIFICATE-----\n"
            );
            make_ctx("x.sh", content.into_bytes())
        };
        let rule = HighEntropyRule;
        assert!(rule.evaluate(&mk(20)).unwrap().is_none());
        assert!(rule.evaluate(&mk(MAX_PEM_LINE_BYTES)).unwrap().is_none());
        assert!(rule
            .evaluate(&mk(MAX_PEM_LINE_BYTES + 1))
            .unwrap()
            .is_some());
    }

    #[test]
    fn base64_of_plain_text_is_not_scored() {
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(60);
        assert!(text.len() >= 2048);
        let encoded = wrap(&base64_encode(text.as_bytes()), 76);
        let content = format!("#!/bin/sh\nP=\"{encoded}\"\necho \"$P\" | base64 -d\n");
        let ctx = make_ctx("encoded_text.sh", content.into_bytes());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
    }

    #[test]
    fn base64_run_shorter_than_minimum_is_not_scored() {
        let payload = high_entropy_blob(512); // encodes to well under 1024 chars
        let encoded = base64_encode(&payload);
        let content = format!(
            "#!/bin/sh\n# padding to keep whole-content entropy low:\n\
             # {}\nP=\"{encoded}\"\n",
            "the quick brown fox jumps over the lazy dog ".repeat(20)
        );
        let ctx = make_ctx("short_run.sh", content.into_bytes());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
    }

    // --- base64 segmentation (§5.1 wordlist false-run fix, and the
    // adjacent-short-line fix on top of it) ---

    #[test]
    fn single_unwrapped_line_is_one_segment() {
        let line = "A".repeat(3000);
        let (seg_end, next) = next_base64_segment(line.as_bytes(), 0, line.len());
        assert_eq!(seg_end, line.len());
        assert_eq!(next, line.len());
    }

    #[test]
    fn wrapped_76_col_base64_is_one_segment() {
        let payload = high_entropy_blob(2048);
        let wrapped = wrap(&base64_encode(&payload), 76);
        let (seg_end, next) = next_base64_segment(wrapped.as_bytes(), 0, wrapped.len());
        assert_eq!(
            seg_end,
            wrapped.len(),
            "the whole wrapped payload, remainder line included, is one block"
        );
        assert_eq!(next, wrapped.len());
    }

    #[test]
    fn wrapped_32_col_base64_is_one_segment() {
        // `base64 -b 32`: narrower than the old 40-char threshold, but still
        // real uniform wrapping.
        let payload = high_entropy_blob(2048);
        let wrapped = wrap(&base64_encode(&payload), 32);
        let (seg_end, next) = next_base64_segment(wrapped.as_bytes(), 0, wrapped.len());
        assert_eq!(
            seg_end,
            wrapped.len(),
            "a narrow but uniform wrap width still forms one block"
        );
        assert_eq!(next, wrapped.len());
    }

    #[test]
    fn alternating_width_wrap_is_one_segment() {
        // Uneven wrapping (e.g. a client that varies line length by a
        // column): no two consecutive lines need share an exact width, only
        // each be wide enough on its own.
        let payload = high_entropy_blob(2048);
        let encoded = base64_encode(&payload);
        let mut wrapped = String::new();
        let mut rest = encoded.as_str();
        let mut toggle = 60;
        while !rest.is_empty() {
            let take = toggle.min(rest.len());
            wrapped.push_str(&rest[..take]);
            rest = &rest[take..];
            if !rest.is_empty() {
                wrapped.push('\n');
            }
            toggle = if toggle == 60 { 61 } else { 60 };
        }
        let (seg_end, next) = next_base64_segment(wrapped.as_bytes(), 0, wrapped.len());
        assert_eq!(
            seg_end,
            wrapped.len(),
            "alternating 60/61-column lines still form one block"
        );
        assert_eq!(next, wrapped.len());
    }

    #[test]
    fn wordlist_first_word_is_its_own_segment() {
        // Mimics a one-word-per-line dictionary/password list: every
        // character is in the base64 alphabet, but each line is far under a
        // real wrap width, so it must stand as its own tiny segment rather
        // than fusing with the rest of the list.
        let block = "password\nletmein\nhunter2\n";
        let (seg_end, next) = next_base64_segment(block.as_bytes(), 0, block.len());
        assert_eq!(seg_end, "password".len());
        assert_eq!(next, "password".len() + 1);
    }

    #[test]
    fn base64_payload_after_a_blank_line_is_scored() {
        // Mimics a MIME part: a blank separator line directly precedes the
        // real wrapped base64 body, joined into the same run since a bare
        // `\n` doesn't break one. The blank line must not blind detection of
        // the payload that follows it.
        let payload = high_entropy_blob(2048);
        let wrapped = wrap(&base64_encode(&payload), 76);
        let content = format!("Content-Transfer-Encoding: base64\n\n{wrapped}\n");
        let ctx = make_ctx("email.txt", content.into_bytes());
        let signal = HighEntropyRule.evaluate(&ctx).unwrap();
        assert!(
            signal.is_some(),
            "a payload right after a blank line should still be detected"
        );
    }

    #[test]
    fn base64_payload_adjacent_to_a_terminator_word_is_scored() {
        // Mimics a Perl-style heredoc: a short all-letters terminator word
        // sits on its own line directly after the wrapped payload, joined
        // into the same run. The terminator must not blind detection of the
        // payload that precedes it.
        let payload = high_entropy_blob(2048);
        let wrapped = wrap(&base64_encode(&payload), 76);
        let content = format!("my $data = << 'ICON';\n{wrapped}\nICON\n");
        let ctx = make_ctx("icon.pl", content.into_bytes());
        let signal = HighEntropyRule.evaluate(&ctx).unwrap();
        assert!(
            signal.is_some(),
            "a payload right before a terminator word should still be detected"
        );
    }

    #[test]
    fn wordlist_like_block_does_not_form_a_base64_candidate() {
        // Lengths vary, mostly under MIN_WRAPPED_LINE_LEN (16) with a couple
        // reaching up to ~20 — enough to probe the lowered threshold without
        // any two adjacent entries coincidentally sharing a width >= 16.
        let words = [
            "password",
            "letmein",
            "hunter2",
            "qwerty123",
            "dragon",
            "monkey12",
            "abcdefghijklmnop",
            "abcdefghijklmnopqrst",
        ];
        let mut block = String::new();
        for i in 0..300 {
            block.push_str(words[i % words.len()]);
            block.push('\n');
        }
        assert!(
            block.len() > MIN_BASE64_RUN,
            "block must exceed the run threshold to be meaningful"
        );
        let ctx = make_ctx("wordlist.txt", block.into_bytes());
        assert!(
            HighEntropyRule.evaluate(&ctx).unwrap().is_none(),
            "a joined wordlist run must not be treated as one base64 candidate"
        );
    }

    #[test]
    fn equal_length_short_wordlist_lines_do_not_form_a_base64_candidate() {
        // A dictionary sorted by length produces long runs of consecutive
        // *equal*-length lines — exactly the uniform-width shape the block
        // rule looks for — but at 8-12 chars, well under MIN_WRAPPED_LINE_LEN
        // (16), so it must not qualify just because the width matches.
        let words_8 = [
            "password", "dragon12", "letmein1", "baseball", "sunshine", "qwerty12",
        ];
        let words_12 = [
            "correcthorse",
            "trustno12345",
            "monkeybarsxx",
            "footballerxx",
        ];
        assert!(words_8.iter().all(|w| w.len() == 8));
        assert!(words_12.iter().all(|w| w.len() == 12));
        let mut block = String::new();
        for i in 0..100 {
            block.push_str(words_8[i % words_8.len()]);
            block.push('\n');
        }
        for i in 0..100 {
            block.push_str(words_12[i % words_12.len()]);
            block.push('\n');
        }
        assert!(
            block.len() > MIN_BASE64_RUN,
            "block must exceed the run threshold to be meaningful"
        );
        let ctx = make_ctx("wordlist_sorted.txt", block.into_bytes());
        assert!(
            HighEntropyRule.evaluate(&ctx).unwrap().is_none(),
            "consecutive equal-length short lines must not be treated as one base64 candidate"
        );
    }

    // --- work caps and the `=`-splitting fix (§5.1 review round on #36) ---

    #[test]
    fn unquoted_assignment_is_not_swallowed_by_its_own_equals_sign() {
        // "P=<payload>" with no quotes: the `=` sits directly against the
        // payload, with nothing to separate them into different runs except
        // the run-finding fix itself.
        let payload = high_entropy_blob(2048);
        let encoded = base64_encode(&payload);
        let content = format!("#!/bin/sh\nP={encoded}\necho $P | base64 -d | gunzip | sh\n");
        let ctx = make_ctx("dropper.sh", content.into_bytes());
        let signal = HighEntropyRule.evaluate(&ctx).unwrap();
        assert!(
            signal.is_some(),
            "an unquoted P=<payload> assignment must still be detected"
        );
    }

    #[test]
    fn base64_payload_survives_many_low_entropy_decoys() {
        // Regression: MAX_BASE64_CANDIDATES used to stop scanning after 64
        // qualifying candidates, so enough low-entropy decoys ahead of the
        // real payload would hide it entirely.
        let decoy_text = "the quick brown fox jumps over the lazy dog. ".repeat(40);
        let decoy_encoded = base64_encode(decoy_text.as_bytes());
        assert!(
            decoy_encoded.len() >= MIN_BASE64_RUN,
            "each decoy must itself qualify as a candidate"
        );
        let mut content = String::from("#!/bin/sh\n");
        for i in 0..70 {
            content.push_str(&format!("D{i}=\"{decoy_encoded}\"\n"));
        }
        let payload = high_entropy_blob(2048);
        let encoded_payload = wrap(&base64_encode(&payload), 76);
        content.push_str(&format!(
            "P=\"{encoded_payload}\"\necho \"$P\" | base64 -d | gunzip | sh\n"
        ));
        let ctx = make_ctx("many_decoys.sh", content.into_bytes());
        let signal = HighEntropyRule.evaluate(&ctx).unwrap();
        assert!(
            signal.is_some(),
            "a real payload after 70 low-entropy decoys must still be found"
        );
    }

    #[test]
    fn base64_payload_survives_many_data_uri_decoys() {
        // Same regression, via the other capped resource: 70 skipped
        // data-URI candidates ahead of the real payload used to exhaust
        // MAX_BASE64_CANDIDATES before it was ever reached.
        let icon = high_entropy_blob(900);
        let icon_encoded = base64_encode(&icon);
        assert!(
            icon_encoded.len() >= MIN_BASE64_RUN,
            "each decoy must itself qualify as a candidate"
        );
        let mut content = String::from("#!/bin/sh\n");
        for i in 0..70 {
            content.push_str(&format!(
                "ICON{i}=\"data:image/png;base64,{icon_encoded}\"\n"
            ));
        }
        let payload = high_entropy_blob(2048);
        let encoded_payload = wrap(&base64_encode(&payload), 76);
        content.push_str(&format!(
            "P=\"{encoded_payload}\"\necho \"$P\" | base64 -d | gunzip | sh\n"
        ));
        let ctx = make_ctx("many_icons.sh", content.into_bytes());
        let signal = HighEntropyRule.evaluate(&ctx).unwrap();
        assert!(
            signal.is_some(),
            "a real payload after 70 skipped data-URI decoys must still be found"
        );
    }

    // --- payload regions (§5.2, #67) ---

    use crate::macho::tests_support::{build_segments, seg, SegSpec};

    const TEXT_OFF: u64 = 0x1000;
    /// Default payload offset, past any `__text` of up to 0x1F000 bytes.
    const PAYLOAD_AT: u64 = 0x20000;

    /// A payload placed in an extra segment: `sect` `None` declares no
    /// sections (a whole-segment region), else one section spanning it.
    struct Extra {
        name: &'static [u8],
        initprot: u32,
        sect: Option<&'static [u8]>,
        payload: Vec<u8>,
        at: u64,
    }

    fn extra(
        name: &'static [u8],
        initprot: u32,
        sect: Option<&'static [u8]>,
        payload: Vec<u8>,
    ) -> Extra {
        Extra {
            name,
            initprot,
            sect,
            payload,
            at: PAYLOAD_AT,
        }
    }

    /// A thin arm64-less 64-bit Mach-O: `__TEXT,__text` holding `text`, then
    /// each extra segment with its payload at its offset.
    fn image_with(text: &[u8], extras: &[Extra]) -> Vec<u8> {
        let mut text_seg = seg(
            b"__TEXT",
            TEXT_OFF,
            text.len() as u64,
            vec![(b"__text", text.len() as u64, TEXT_OFF as u32, 0x8000_0400)],
        );
        text_seg.initprot = 5;
        let mut specs = vec![text_seg];
        let mut total = TEXT_OFF as usize + text.len();
        for e in extras {
            let size = e.payload.len() as u64;
            let sects = e.sect.map_or(vec![], |n| vec![(n, size, e.at as u32, 0)]);
            let mut sg: SegSpec = seg(e.name, e.at, size, sects);
            sg.initprot = e.initprot;
            specs.push(sg);
            total = total.max((e.at + size) as usize);
        }
        let mut bytes = build_segments(true, &specs, &[], total);
        bytes[TEXT_OFF as usize..TEXT_OFF as usize + text.len()].copy_from_slice(text);
        for e in extras {
            let at = e.at as usize;
            bytes[at..at + e.payload.len()].copy_from_slice(&e.payload);
        }
        bytes
    }

    fn eval_bytes(tag: &str, bytes: &[u8]) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let path = write_temp_file(tag, bytes);
        let ctx = ScanContext::load(&path);
        let result = HighEntropyRule.evaluate(&ctx);
        let _ = std::fs::remove_file(&path);
        result
    }

    fn payload_weight(tag: &str, text: &[u8], extras: &[Extra]) -> Option<i32> {
        eval_bytes(tag, &image_with(text, extras))
            .unwrap()
            .map(|s| s.weight)
    }

    #[test]
    fn wx_segment_payload_with_a_tiny_text_is_structural() {
        let bytes = image_with(
            &[0u8; 64],
            &[extra(b"__PACK", 7, None, high_entropy_blob(80 * KIB))],
        );
        let signal = eval_bytes("payload-wx", &bytes).unwrap().unwrap();
        assert_eq!(signal.weight, PAYLOAD_STRUCTURAL_WEIGHT);
        assert!(
            signal
                .description
                .starts_with("high-entropy payload in writable+executable segment __PACK ("),
            "{}",
            signal.description
        );
        assert!(signal.description.contains("segment 81920 bytes"));
    }

    #[test]
    fn custom_segment_payload_with_a_tiny_text_is_structural() {
        let payload = high_entropy_blob(80 * KIB);
        assert_eq!(
            payload_weight(
                "payload-custom",
                &[0u8; 64],
                &[extra(b"__PACK", 5, None, payload)]
            ),
            Some(PAYLOAD_STRUCTURAL_WEIGHT)
        );
    }

    #[test]
    fn custom_segment_payload_beside_a_big_text_is_corroborating() {
        let text = uniform_over(100, 400 * KIB);
        let mut e = extra(b"__FOO", 5, None, high_entropy_blob(80 * KIB));
        e.at = TEXT_OFF + 400 * KIB as u64;
        let bytes = image_with(&text, &[e]);
        let signal = eval_bytes("payload-custom-big-text", &bytes)
            .unwrap()
            .unwrap();
        assert_eq!(signal.weight, PAYLOAD_CORROBORATING_WEIGHT);
        assert!(signal
            .description
            .starts_with("high-entropy payload in non-standard segment __FOO ("));
    }

    #[test]
    fn standard_segment_payload_beside_a_tiny_text_is_corroborating() {
        let bytes = image_with(
            &[0u8; 64],
            &[extra(
                b"__DATA",
                3,
                Some(b"__data"),
                high_entropy_blob(80 * KIB),
            )],
        );
        let signal = eval_bytes("payload-data", &bytes).unwrap().unwrap();
        assert_eq!(signal.weight, PAYLOAD_CORROBORATING_WEIGHT);
        assert!(
            signal
                .description
                .starts_with("high-entropy section __DATA,__data 1280x the size of __text"),
            "{}",
            signal.description
        );
    }

    #[test]
    fn standard_section_beside_a_big_text_is_not_measured() {
        let text = uniform_over(100, 600 * KIB);
        let mut e = extra(b"__TEXT", 5, Some(b"__const"), high_entropy_blob(128 * KIB));
        e.at = TEXT_OFF + 600 * KIB as u64;
        let bytes = image_with(&text, &[e]);
        let path = write_temp_file("payload-const-unmeasured", &bytes);
        let ctx = ScanContext::load(&path);
        let (included, all_scored) = budgeted_ranges(&ctx, &ctx.macho().images);
        assert!(all_scored);
        assert_eq!(included.len(), 1, "only __text is read");
        assert!(included[0].0.is_none());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
        assert!(HighEntropyRule.covers_truncation(&ctx));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn excluded_segments_are_never_measured() {
        for name in [&b"__LINKEDIT"[..], b"__DWARF", b"__LLVM", b"__PAGEZERO"] {
            let name: &'static [u8] = Box::leak(name.to_vec().into_boxed_slice());
            let payload = high_entropy_blob(128 * KIB);
            assert_eq!(
                payload_weight(
                    "payload-excluded",
                    &[0u8; 64],
                    &[extra(name, 3, None, payload)]
                ),
                None,
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn executable_segment_with_an_excluded_name_is_measured() {
        for name in [&b"__LLVM"[..], b"__DWARF"] {
            let name: &'static [u8] = Box::leak(name.to_vec().into_boxed_slice());
            let payload = high_entropy_blob(80 * KIB);
            assert_eq!(
                payload_weight(
                    "payload-excluded-wx",
                    &[0u8; 64],
                    &[extra(name, 7, None, payload)]
                ),
                Some(PAYLOAD_STRUCTURAL_WEIGHT),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn inflated_text_size_does_not_hide_a_small_stub() {
        let payload = high_entropy_blob(80 * KIB);
        let total = PAYLOAD_AT as usize + payload.len();
        let mut text_seg = seg(
            b"__TEXT",
            TEXT_OFF,
            64,
            vec![(b"__text", 1u64 << 40, total as u32 - 16, 0x8000_0400)],
        );
        text_seg.initprot = 5;
        let mut pack = seg(b"__PACK", PAYLOAD_AT, payload.len() as u64, vec![]);
        pack.initprot = 5;
        let mut bytes = build_segments(true, &[text_seg, pack], &[], total);
        bytes[PAYLOAD_AT as usize..].copy_from_slice(&payload);
        let signal = eval_bytes("payload-inflated-text", &bytes)
            .unwrap()
            .unwrap();
        assert_eq!(signal.weight, PAYLOAD_STRUCTURAL_WEIGHT);
    }

    #[test]
    fn text_header_spanning_the_payload_does_not_hide_a_small_stub() {
        let payload = high_entropy_blob(80 * KIB);
        // Payload right after the real stub, so little of the span is non-payload.
        let at = 0x2000u64;
        let total = at as usize + payload.len();
        let mut text_seg = seg(
            b"__TEXT",
            TEXT_OFF,
            64,
            vec![(b"__text", 1u64 << 40, TEXT_OFF as u32, 0x8000_0400)],
        );
        text_seg.initprot = 5;
        let mut pack = seg(b"__PACK", at, payload.len() as u64, vec![]);
        pack.initprot = 5;
        let mut bytes = build_segments(true, &[text_seg, pack], &[], total);
        bytes[at as usize..].copy_from_slice(&payload);
        let signal = eval_bytes("payload-spanning-text", &bytes)
            .unwrap()
            .unwrap();
        assert_eq!(signal.weight, PAYLOAD_STRUCTURAL_WEIGHT);
    }

    #[test]
    fn qualifying_region_under_64kib_is_not_measured() {
        let payload = high_entropy_blob(64 * KIB - 1);
        assert_eq!(
            payload_weight(
                "payload-small",
                &[0u8; 64],
                &[extra(b"__PACK", 7, None, payload)]
            ),
            None
        );
    }

    #[test]
    fn low_entropy_qualifying_region_is_clean() {
        let payload = uniform_over(100, 128 * KIB);
        assert_eq!(
            payload_weight(
                "payload-low",
                &[0u8; 64],
                &[extra(b"__PACK", 7, None, payload)]
            ),
            None
        );
    }

    #[test]
    fn fat_binary_payload_slice_beats_a_clean_slice() {
        let clean = image_with(&uniform_over(100, 4096), &[]);
        let packed = image_with(
            &[0u8; 64],
            &[extra(b"__PACK", 7, None, high_entropy_blob(80 * KIB))],
        );
        for (tag, slices) in [
            ("clean-first", [&clean[..], &packed[..]]),
            ("packed-first", [&packed[..], &clean[..]]),
        ] {
            let fat = crate::macho::tests_support::synth_fat(&slices);
            let signal = eval_bytes(&format!("payload-fat-{tag}"), &fat)
                .unwrap()
                .unwrap();
            assert_eq!(signal.weight, PAYLOAD_STRUCTURAL_WEIGHT, "{tag}");
        }
    }

    #[test]
    fn incomplete_segment_list_without_a_match_is_not_applicable() {
        let mut text_seg = seg(
            b"__TEXT",
            TEXT_OFF,
            64,
            vec![(b"__text", 64, TEXT_OFF as u32, 0x8000_0400)],
        );
        text_seg.nsects = Some(0xFFFF); // lies: headers don't fit the command
        let bytes = build_segments(true, &[text_seg], &[], 0x2000);
        let path = write_temp_file("payload-incomplete", &bytes);
        let ctx = ScanContext::load(&path);
        assert!(!ctx.macho().images[0].segments_complete);
        assert!(matches!(
            HighEntropyRule.evaluate(&ctx),
            Err(RuleOutcome::NotApplicable)
        ));
        assert!(!HighEntropyRule.covers_truncation(&ctx));
        let _ = std::fs::remove_file(&path);
    }

    /// A custom-segment image whose payload range is `range`.
    fn payload_image(base: &macho::MachOImage, range: Range<u64>) -> macho::MachOImage {
        let mut image = base.clone();
        image.text_range = None;
        image.segments = vec![macho::Segment {
            name: *b"__PACK\0\0\0\0\0\0\0\0\0\0",
            file_range: Some(range),
            maxprot: 7,
            initprot: 5,
            sections: vec![],
        }];
        image.segments_complete = true;
        image
    }

    /// Resident `content` plus a text decoy that nearly exhausts the budget
    /// and a payload region at the file's end that the budget leaves out.
    fn left_out_payload_images(content: Vec<u8>) -> (ScanContext, Vec<macho::MachOImage>) {
        let held = content.len() as u64;
        let file_len = held + MAX_STREAM_BYTES + 256 * KIB as u64;
        let (mut ctx, base) = packed_ctx(file_len);
        ctx.content = Some(content);
        let mut decoy = base.clone();
        decoy.text_range = Some(held..MAX_STREAM_BYTES - 100);
        let mut first = base.clone();
        first.text_range = Some(0..held);
        let payload = payload_image(&base, file_len - 128 * KIB as u64..file_len);
        (ctx, vec![first, decoy, payload])
    }

    #[test]
    fn budget_left_out_payload_region_without_a_match_is_not_applicable() {
        let (ctx, images) = left_out_payload_images(vec![0u8; 4096]);
        let (included, all_scored) = budgeted_ranges(&ctx, &images);
        assert!(!all_scored);
        assert!(included.iter().all(|(region, _)| region.is_none()));
        let content = ctx.content.as_ref().unwrap();
        assert!(matches!(
            HighEntropyRule.eval_macho_images(&ctx, content, &images),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    #[test]
    fn budget_left_out_payload_region_does_not_suppress_a_packed_text_match() {
        let (ctx, images) = left_out_payload_images(high_entropy_blob(4096));
        let (included, all_scored) = budgeted_ranges(&ctx, &images);
        assert!(!all_scored);
        assert!(included.iter().all(|(region, _)| region.is_none()));
        let content = ctx.content.as_ref().unwrap();
        let signal = HighEntropyRule
            .eval_macho_images(&ctx, content, &images)
            .unwrap()
            .unwrap();
        assert_eq!(signal.weight, TEXT_PACKED_WEIGHT);
    }

    #[test]
    fn structural_payload_regions_are_budgeted_before_corroborating_ones() {
        let (ctx, base) = packed_ctx(1024 * KIB as u64);
        let mut image = base;
        let section = |name: &[u8], range: Range<u64>| {
            let mut n = [0u8; 16];
            n[..name.len()].copy_from_slice(name);
            macho::Section {
                name: n,
                file_range: Some(range),
                flags: 0,
            }
        };
        image.text_range = Some(0..64);
        image.segments = vec![
            macho::Segment {
                name: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
                file_range: Some(0..128 * KIB as u64),
                maxprot: 3,
                initprot: 3,
                sections: vec![section(b"__data", 0..128 * KIB as u64)],
            },
            macho::Segment {
                name: *b"__PACK\0\0\0\0\0\0\0\0\0\0",
                file_range: Some(256 * KIB as u64..384 * KIB as u64),
                maxprot: 7,
                initprot: 7,
                sections: vec![],
            },
        ];
        let (included, all_scored) = budgeted_ranges(&ctx, &[image]);
        assert!(all_scored);
        let weights: Vec<Option<i32>> = included
            .iter()
            .map(|(r, _)| r.as_ref().map(PayloadRegion::weight))
            .collect();
        assert_eq!(
            weights,
            [
                None,
                Some(PAYLOAD_STRUCTURAL_WEIGHT),
                Some(PAYLOAD_CORROBORATING_WEIGHT)
            ]
        );
    }

    #[test]
    fn streamed_payload_region_matches_the_resident_score() {
        let mut e = extra(b"__PACK", 7, None, high_entropy_blob(80 * KIB));
        e.at = MAX_CONTENT_BYTES as u64 + 4096;
        let bytes = image_with(&[0u8; 64], &[e]);
        let path = write_temp_file("payload-streamed", &bytes);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let streamed = HighEntropyRule.evaluate(&ctx).unwrap().unwrap();
        assert!(HighEntropyRule.covers_truncation(&ctx));

        let regions = payload_regions(&ctx, &ctx.macho().images[0]);
        let (_, resident) = HighEntropyRule
            .macho_signal_from_content(&bytes, regions[0].range.clone(), Some(&regions[0]))
            .unwrap();
        assert_eq!(streamed.weight, PAYLOAD_STRUCTURAL_WEIGHT);
        assert_eq!(streamed.weight, resident.weight);
        assert_eq!(streamed.description, resident.description);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn object_file_unnamed_rwx_segment_is_not_a_payload() {
        let mut text_seg = seg(
            b"__TEXT",
            TEXT_OFF,
            64,
            vec![(b"__text", 64, TEXT_OFF as u32, 0x8000_0400)],
        );
        text_seg.initprot = 7;
        let mut unnamed = seg(b"", PAYLOAD_AT, 80 * KIB as u64, vec![]);
        unnamed.initprot = 7;
        let total = PAYLOAD_AT as usize + 80 * KIB;
        let mut bytes = crate::macho::tests_support::build_segments_typed(
            true,
            macho::MH_OBJECT,
            &[text_seg, unnamed],
            &[],
            total,
        );
        bytes[PAYLOAD_AT as usize..].copy_from_slice(&high_entropy_blob(80 * KIB));
        let path = write_temp_file("payload-object", &bytes);
        let ctx = ScanContext::load(&path);
        let image = &ctx.macho().images[0];
        assert_eq!(image.filetype, macho::MH_OBJECT);
        assert!(payload_regions(&ctx, image).is_empty());
        assert!(HighEntropyRule.evaluate(&ctx).unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hostile_segment_names_cannot_break_the_description() {
        let raw = b"__A\"B\\C\n\x1b[0m\xe2\x80\xae\xff";
        let mut name = [0u8; 16];
        name[..raw.len()].copy_from_slice(raw);
        let escaped = escaped_name(&name);
        assert_eq!(escaped, "__A\\\"B\\\\C\\n\\u{1b}[0m\\u{202e}\\u{fffd}");
        assert!(escaped.chars().all(|c| c.is_ascii_graphic()));

        // Bytes after the first NUL are not part of the name.
        let mut name = [0u8; 16];
        name[..3].copy_from_slice(b"__X");
        name[4..8].copy_from_slice(b"evil");
        assert_eq!(escaped_name(&name), "__X");

        // End to end: the name flows into the description escaped.
        let hostile: &'static [u8] = b"__P\"\n\x07K";
        let bytes = image_with(
            &[0u8; 64],
            &[extra(hostile, 7, None, high_entropy_blob(80 * KIB))],
        );
        let signal = eval_bytes("payload-hostile", &bytes).unwrap().unwrap();
        assert!(
            signal.description.contains("segment __P\\\"\\n\\u{7}K ("),
            "{}",
            signal.description
        );
        assert!(!signal.description.contains('\n'));
    }

    // --- Apple-anchored demotion of name + small-text payloads (§5.2, #67) ---

    fn eval_anchored(
        tag: &str,
        bytes: &[u8],
        anchored: bool,
    ) -> (Result<Option<MatchedSignal>, RuleOutcome>, u32) {
        let path = write_temp_file(tag, bytes);
        let ctx = ScanContext::load(&path);
        let calls = std::cell::Cell::new(0u32);
        let result = HighEntropyRule.evaluate_with(&ctx, || {
            calls.set(calls.get() + 1);
            anchored
        });
        let _ = std::fs::remove_file(&path);
        (result, calls.get())
    }

    fn custom_payload_image() -> Vec<u8> {
        image_with(
            &[0u8; 64],
            &[extra(b"__IMAGES", 5, None, high_entropy_blob(128 * KIB))],
        )
    }

    #[test]
    fn name_and_small_text_payload_is_demoted_when_apple_anchored() {
        let bytes = custom_payload_image();
        let (unanchored, calls) = eval_anchored("anchor-no", &bytes, false);
        assert_eq!(
            unanchored.unwrap().unwrap().weight,
            PAYLOAD_STRUCTURAL_WEIGHT
        );
        assert_eq!(calls, 1);
        let (anchored, calls) = eval_anchored("anchor-yes", &bytes, true);
        let signal = anchored.unwrap().unwrap();
        assert_eq!(signal.weight, PAYLOAD_CORROBORATING_WEIGHT);
        assert!(signal
            .description
            .ends_with("; signature verifies to an Apple anchor, so corroboration-only"));
        assert_eq!(calls, 1);
    }

    #[test]
    fn anchor_check_is_skipped_unless_a_name_and_text_payload_is_best() {
        let wx = image_with(
            &[0u8; 64],
            &[extra(b"__PACK", 7, None, high_entropy_blob(80 * KIB))],
        );
        let (result, calls) = eval_anchored("anchor-wx", &wx, true);
        assert_eq!(result.unwrap().unwrap().weight, PAYLOAD_STRUCTURAL_WEIGHT);
        assert_eq!(calls, 0);

        let packed_text = image_with(&high_entropy_blob(4096), &[]);
        let (result, calls) = eval_anchored("anchor-packed-text", &packed_text, true);
        assert_eq!(result.unwrap().unwrap().weight, TEXT_PACKED_WEIGHT);
        assert_eq!(calls, 0);

        let clean = image_with(&[0u8; 64], &[]);
        let (result, calls) = eval_anchored("anchor-clean", &clean, true);
        assert!(result.unwrap().is_none());
        assert_eq!(calls, 0);
    }

    #[test]
    fn anchored_demotion_keeps_a_result_when_everything_was_scored() {
        let a = custom_payload_image();
        let b = image_with(
            &[0u8; 64],
            &[extra(
                b"__DATA",
                3,
                Some(b"__data"),
                high_entropy_blob(80 * KIB),
            )],
        );
        let fat = crate::macho::tests_support::synth_fat(&[&a, &b]);
        let (result, calls) = eval_anchored("anchor-fat", &fat, true);
        assert_eq!(
            result.unwrap().unwrap().weight,
            PAYLOAD_CORROBORATING_WEIGHT
        );
        assert_eq!(calls, 1);
    }
}
