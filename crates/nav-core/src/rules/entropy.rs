//! High-entropy content detection — a weak generic signal on its own (§5.1).
//!
//! Structure-aware, not whole-file:
//! - **Mach-O**: scores the `__TEXT` code section (§5.2) — packed/obfuscated
//!   code is well above the ceiling, normal machine code well below.
//! - **script/text**: scores the whole content first (raw binary spliced
//!   into a script, weight 15), then looks for a base64-encoded high-entropy
//!   payload (§5.2, weight 8 — corroboration-only, see
//!   [`BASE64_PAYLOAD_WEIGHT`]). Base64's 64-symbol alphabet caps
//!   whole-content entropy at 6.0 bits/byte, so an encoded payload can never
//!   trip the whole-content check — only *decoding* a qualifying run
//!   recovers its real entropy. A data-URI (`;base64,`) or PEM-armored
//!   (`-----BEGIN ...-----`) run is skipped, since both are ordinary
//!   carriers for high-entropy bytes. A multi-line run is split into
//!   candidate *blocks* — maximal stretches of consecutive same-width lines
//!   (a possible shorter final line allowed, real base64 wrapping's
//!   remainder) — rather than judged as a single all-or-nothing candidate,
//!   so a wordlist/dictionary's one-token-per-line text can't fuse into a
//!   fake giant run just because every character sits in the base64
//!   alphabet, and, the other direction, a blank separator line or a short
//!   heredoc terminator word sitting right next to a genuinely wrapped
//!   payload can't blind detection of it either — each block stands on its
//!   own. Base64 of plain text (e.g. an encoded shell script) decodes
//!   to *low* entropy and is deliberately not this rule's signal — that
//!   encode-then-hand-to-an-interpreter shape is a string-marker concern
//!   (issue #35).
//! - **any other opaque binary** (archive, image, encrypted data): high
//!   entropy is expected, so it is *not* scored — whole-file scoring was a
//!   real false-positive source (a plain `.tar.gz` alerted) (§1).

use std::path::Path;

use super::{Rule, RuleOutcome};
use crate::base64;
use crate::context::ScanContext;
use crate::macho;
use crate::model::{MatchedSignal, SignalCategory};

/// Above this (out of 8.0 bits/byte, the max for byte-oriented Shannon
/// entropy) content reads as packed/encrypted/compressed rather than typical
/// machine code or text.
const ENTROPY_THRESHOLD: f64 = 7.0;

/// Below this many bytes an entropy figure is too noisy to act on.
const MIN_SAMPLE_BYTES: usize = 256;

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
/// than the whole-content/`__TEXT` weight, which stays narrowly scoped
/// enough (raw binary spliced into a script, or packed Mach-O code) to
/// carry more weight alone.
const BASE64_PAYLOAD_WEIGHT: i32 = 8;

pub struct HighEntropyRule {
    threshold: f64,
}

impl Default for HighEntropyRule {
    fn default() -> Self {
        HighEntropyRule {
            threshold: ENTROPY_THRESHOLD,
        }
    }
}

impl Rule for HighEntropyRule {
    fn id(&self) -> &'static str {
        "high-entropy-content"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::StaticSuspicion
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;
        if content.is_empty() {
            return Ok(None);
        }

        if let Some(image) = macho::parse(content) {
            return Ok(self.eval_macho_text(content, &image));
        }

        if looks_like_script_or_text(content, &ctx.path) {
            return Ok(self.eval_embedded_payload(content));
        }

        // Opaque non-Mach-O binary: high entropy is expected, so no suspicion.
        Ok(None)
    }
}

impl HighEntropyRule {
    /// Score the entropy of a Mach-O's `__TEXT` code, clipped to the bytes we
    /// actually captured (a bounded scan may not hold the whole section).
    fn eval_macho_text(&self, content: &[u8], image: &macho::MachOImage) -> Option<MatchedSignal> {
        let range = image.text_range.clone()?;
        let start = usize::try_from(range.start).ok()?.min(content.len());
        let end = usize::try_from(range.end).ok()?.min(content.len());
        let text = content.get(start..end)?;
        if text.len() < MIN_SAMPLE_BYTES {
            return None;
        }

        let entropy = shannon_entropy(text);
        if entropy < self.threshold {
            return None;
        }
        Some(MatchedSignal {
            id: self.id().to_string(),
            weight: 15,
            description: format!(
                "high-entropy __TEXT section (entropy: {:.1} bits/byte over {} bytes) — \
                 consistent with packed/obfuscated code",
                entropy,
                text.len()
            ),
            category: self.category(),
        })
    }

    /// Score a script/text file for an embedded high-entropy payload: first
    /// the whole content (raw binary spliced in), then a qualifying
    /// base64-encoded run's *decoded* bytes (module docs above). Neither
    /// path fires on base64 of ordinary text — decoding that yields low
    /// entropy, which is the point.
    fn eval_embedded_payload(&self, content: &[u8]) -> Option<MatchedSignal> {
        if content.len() >= MIN_SAMPLE_BYTES {
            let entropy = shannon_entropy(content);
            if entropy >= self.threshold {
                return Some(MatchedSignal {
                    id: self.id().to_string(),
                    weight: 15,
                    description: format!(
                        "high-entropy content embedded in a script/text file \
                         (entropy: {:.1} bits/byte over {} bytes) — possible obfuscated/base64 payload",
                        entropy,
                        content.len()
                    ),
                    category: self.category(),
                });
            }
        }
        self.eval_base64_payload(content)
    }

    /// Scan for a base64-encoded high-entropy payload: find maximal runs of
    /// the base64 alphabet, walk each run as a sequence of wrapped-base64
    /// *blocks* and single-line boundaries (§ module docs — a block is a
    /// candidate on its own, so an unrelated short line — blank, a wordlist
    /// entry, a heredoc terminator — can't fuse an adjacent real payload into
    /// a run it fails to qualify as, nor smuggle itself in as part of one),
    /// skip candidates that are ordinary data-URI or PEM carriers, decode the
    /// rest, and score the first decoded candidate whose entropy clears the
    /// threshold. Every candidate is examined — content is already capped at
    /// 8 MiB (§3) and each candidate's decode is bounded by its own length,
    /// so there's no separate work cap for a payload to hide behind many
    /// decoys.
    fn eval_base64_payload(&self, content: &[u8]) -> Option<MatchedSignal> {
        let mut pos = 0;
        while let Some((run_start, run_end, resume)) = next_base64_run(content, pos) {
            let mut seg_start = run_start;
            while seg_start < run_end {
                let (seg_end, next_start) = next_base64_segment(content, seg_start, run_end);
                if let Some(signal) = self.try_base64_candidate(content, seg_start, seg_end) {
                    return Some(signal);
                }
                seg_start = next_start;
            }
            pos = resume;
        }
        None
    }

    /// Evaluate one candidate byte range as a possible base64 payload.
    fn try_base64_candidate(
        &self,
        content: &[u8],
        start: usize,
        end: usize,
    ) -> Option<MatchedSignal> {
        let run = &content[start..end];
        let alphabet_len = run
            .iter()
            .filter(|&&b| base64::char_value(b).is_some())
            .count();
        if alphabet_len < MIN_BASE64_RUN {
            return None;
        }

        // Ordinary carrier for high-entropy bytes, not an obfuscation attempt.
        if preceded_by_data_uri(content, start) {
            return None;
        }
        // Same: a certificate/key bundle, not a payload.
        if preceded_by_pem_begin(content, start) {
            return None;
        }

        let decoded = base64::decode_bounded(run, run.len(), base64::OnInvalid::Stop);
        if decoded.len() < MIN_DECODED_BYTES {
            return None;
        }
        let entropy = shannon_entropy(&decoded);
        if entropy < self.threshold {
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
/// `content[..run_end]`, returning its (exclusive) end and where to resume
/// scanning for the next one. A segment is either: a single line under both
/// [`MIN_WRAPPED_LINE_LEN`] and [`MIN_FREEFORM_LINE_LEN`] (too narrow to be
/// real wrapping — a blank line, a wordlist entry, a short terminator word —
/// judged only on its own bytes); or a maximal *block* of consecutive lines
/// that either all share one exact width >= `MIN_WRAPPED_LINE_LEN` (uniform
/// wrapping, e.g. `base64 -b 32`) or are all individually >=
/// `MIN_FREEFORM_LINE_LEN` regardless of exact width (uneven wrapping),
/// optionally followed by one trailing line no wider than the block's last
/// line (real base64 wrapping's final, partial line). Splitting into blocks
/// this way means a block is unaffected by what lies just before or after it
/// in the run — a blank separator line or a heredoc terminator word can't
/// blind detection of a genuinely wrapped payload next to it, nor can it
/// borrow the payload's length to pass as one itself.
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
/// isn't itself followed by more alphabet bytes. Without this, an unquoted
/// shell assignment (`P=H4sI...`) fuses the variable name and `=` into one
/// run, so the decoder reads `=` as the start of padding and stops at the
/// `H` that follows, silently decoding to nothing. Here that `=` ends the
/// run instead, and scanning resumes right after it, starting a fresh run at
/// the payload. Returns `(run_start, run_end, resume_from)`.
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

/// Whether the run starting at `start` is a data-URI payload — the bytes
/// immediately before it end `;base64,`.
fn preceded_by_data_uri(content: &[u8], start: usize) -> bool {
    let lookback = &content[start.saturating_sub(128)..start];
    lookback.ends_with(b";base64,")
}

/// Whether the run starting at `start` is PEM armor — ignoring trailing
/// whitespace, the preceding line starts `-----BEGIN `.
fn preceded_by_pem_begin(content: &[u8], start: usize) -> bool {
    let lookback = &content[start.saturating_sub(256)..start];
    let mut end = lookback.len();
    while end > 0 && lookback[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let trimmed = &lookback[..end];
    let line_start = trimmed
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|p| p + 1)
        .unwrap_or(0);
    trimmed[line_start..].starts_with(b"-----BEGIN ")
}

/// Whether `content`/`path` looks like a script or text file (which could
/// carry an obfuscated payload), vs. an opaque binary blob.
fn looks_like_script_or_text(content: &[u8], path: &Path) -> bool {
    if content.starts_with(b"#!") {
        return true;
    }

    const SCRIPT_EXTS: &[&str] = &[
        "sh",
        "bash",
        "zsh",
        "command",
        "scpt",
        "applescript",
        "js",
        "jxa",
        "py",
        "rb",
        "pl",
        "php",
        "ps1",
    ];
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if SCRIPT_EXTS.iter().any(|e| e.eq_ignore_ascii_case(ext)) {
            return true;
        }
    }

    // Extensionless but overwhelmingly printable leading bytes: a text file
    // with a binary blob spliced in.
    let prefix = &content[..content.len().min(512)];
    if prefix.len() < MIN_SAMPLE_BYTES {
        return false;
    }
    let printable = prefix
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\t' || b == b'\r' || (0x20..=0x7e).contains(&b))
        .count();
    printable * 100 / prefix.len() >= 85
}

fn shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn high_entropy_blob(len: usize) -> Vec<u8> {
        // Deterministic pseudo-random fill, no external RNG dependency.
        let mut state: u32 = 0x1234_5678;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state & 0xff) as u8
            })
            .collect()
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
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
        };
        assert!(HighEntropyRule::default().evaluate(&ctx).unwrap().is_none());
    }

    #[test]
    fn high_entropy_payload_in_a_script_is_scored() {
        let mut content = b"#!/bin/sh\n# stage two:\n".to_vec();
        content.extend_from_slice(&high_entropy_blob(4096));
        let ctx = ScanContext {
            path: PathBuf::from("dropper.sh"),
            content: Some(content),
            truncated: false,
            file_len: None,
            identity: None,
            source: crate::context::ContentSource::File,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
        };
        let signal = HighEntropyRule::default().evaluate(&ctx).unwrap();
        assert!(signal.is_some(), "script with embedded blob should score");
    }

    #[test]
    fn high_entropy_macho_text_is_scored() {
        let (image_bytes, _range) =
            crate::macho::tests_support::synth_macho_64(&high_entropy_blob(4096));
        let ctx = ScanContext {
            path: PathBuf::from("packed"),
            content: Some(image_bytes),
            truncated: false,
            file_len: None,
            identity: None,
            source: crate::context::ContentSource::File,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
        };
        let signal = HighEntropyRule::default().evaluate(&ctx).unwrap();
        assert!(
            signal.is_some(),
            "Mach-O with packed __TEXT should score high entropy"
        );
        assert!(signal.unwrap().description.contains("__TEXT"));
    }

    fn make_ctx(path: &str, content: Vec<u8>) -> ScanContext {
        ScanContext {
            path: PathBuf::from(path),
            content: Some(content),
            truncated: false,
            file_len: None,
            identity: None,
            source: crate::context::ContentSource::File,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
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
        let signal = HighEntropyRule::default().evaluate(&ctx).unwrap();
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
        let payload = high_entropy_blob(1536);
        let encoded = base64_encode(&payload);
        let content = format!("export const icon = \"data:image/png;base64,{encoded}\";\n");
        let ctx = make_ctx("icon.js", content.into_bytes());
        assert!(HighEntropyRule::default().evaluate(&ctx).unwrap().is_none());
    }

    #[test]
    fn base64_payload_in_pem_armor_is_not_scored() {
        let payload = high_entropy_blob(1536);
        let encoded = wrap(&base64_encode(&payload), 64);
        let content = format!(
            "#!/bin/sh\ncat > ca.pem <<'EOF'\n-----BEGIN CERTIFICATE-----\n\
             {encoded}\n-----END CERTIFICATE-----\nEOF\n"
        );
        let ctx = make_ctx("pem_bundle.sh", content.into_bytes());
        assert!(HighEntropyRule::default().evaluate(&ctx).unwrap().is_none());
    }

    #[test]
    fn base64_of_plain_text_is_not_scored() {
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(60);
        assert!(text.len() >= 2048);
        let encoded = wrap(&base64_encode(text.as_bytes()), 76);
        let content = format!("#!/bin/sh\nP=\"{encoded}\"\necho \"$P\" | base64 -d\n");
        let ctx = make_ctx("encoded_text.sh", content.into_bytes());
        assert!(HighEntropyRule::default().evaluate(&ctx).unwrap().is_none());
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
        assert!(HighEntropyRule::default().evaluate(&ctx).unwrap().is_none());
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
        let signal = HighEntropyRule::default().evaluate(&ctx).unwrap();
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
        let signal = HighEntropyRule::default().evaluate(&ctx).unwrap();
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
            HighEntropyRule::default().evaluate(&ctx).unwrap().is_none(),
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
            HighEntropyRule::default().evaluate(&ctx).unwrap().is_none(),
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
        let signal = HighEntropyRule::default().evaluate(&ctx).unwrap();
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
        let signal = HighEntropyRule::default().evaluate(&ctx).unwrap();
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
        let signal = HighEntropyRule::default().evaluate(&ctx).unwrap();
        assert!(
            signal.is_some(),
            "a real payload after 70 skipped data-URI decoys must still be found"
        );
    }
}
