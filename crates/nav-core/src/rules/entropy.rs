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

/// Total decoded bytes this rule will produce across all candidate runs in
/// one file. Content is already bounded to 8 MiB (§3), so this is generous
/// enough that hitting it without an earlier finding is not expected in
/// practice; it exists to bound worst-case decode work, not to trim normal
/// scanning.
const MAX_BASE64_DECODED_BYTES: usize = 1024 * 1024;

/// Stop considering further base64 runs after this many have cleared
/// [`MIN_BASE64_RUN`] — bounds worst-case work on a file built from many
/// qualifying runs.
const MAX_BASE64_CANDIDATES: usize = 64;

/// A multi-line run's non-final lines must all be at least this wide to be
/// treated as one wrapped-base64 candidate — real wrapping uses 64 or
/// 76-column lines. Below it, a uniform width is more likely coincidental
/// (e.g. a dictionary's short one-word-per-line entries).
const MIN_WRAPPED_LINE_LEN: usize = 40;

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
    /// threshold. Bounded by [`MAX_BASE64_CANDIDATES`] qualifying candidates
    /// and [`MAX_BASE64_DECODED_BYTES`] total decoded bytes.
    fn eval_base64_payload(&self, content: &[u8]) -> Option<MatchedSignal> {
        let mut remaining_budget = MAX_BASE64_DECODED_BYTES;
        let mut candidates = 0usize;
        let len = content.len();
        let mut i = 0;
        while i < len {
            if !is_base64_run_byte(content[i]) {
                i += 1;
                continue;
            }
            let run_start = i;
            while i < len && is_base64_run_byte(content[i]) {
                i += 1;
            }
            let run_end = i;

            let mut seg_start = run_start;
            while seg_start < run_end {
                let (seg_end, next_start) = next_base64_segment(content, seg_start, run_end);
                match self.try_base64_candidate(
                    content,
                    seg_start,
                    seg_end,
                    &mut remaining_budget,
                    &mut candidates,
                ) {
                    Base64Step::Match(signal) => return Some(signal),
                    Base64Step::Stop => return None,
                    Base64Step::Continue => {}
                }
                seg_start = next_start;
            }
        }
        None
    }

    /// Evaluate one candidate byte range as a possible base64 payload,
    /// consuming from `remaining_budget`/`candidates` as it goes.
    fn try_base64_candidate(
        &self,
        content: &[u8],
        start: usize,
        end: usize,
        remaining_budget: &mut usize,
        candidates: &mut usize,
    ) -> Base64Step {
        let run = &content[start..end];
        let alphabet_len = run
            .iter()
            .filter(|&&b| base64::char_value(b).is_some())
            .count();
        if alphabet_len < MIN_BASE64_RUN {
            return Base64Step::Continue;
        }
        if *candidates >= MAX_BASE64_CANDIDATES || *remaining_budget == 0 {
            return Base64Step::Stop;
        }
        *candidates += 1;

        // Ordinary carrier for high-entropy bytes, not an obfuscation attempt.
        if preceded_by_data_uri(content, start) {
            return Base64Step::Continue;
        }
        // Same: a certificate/key bundle, not a payload.
        if preceded_by_pem_begin(content, start) {
            return Base64Step::Continue;
        }

        let decoded = base64::decode_bounded(run, *remaining_budget, base64::OnInvalid::Stop);
        *remaining_budget = remaining_budget.saturating_sub(decoded.len());
        if decoded.len() < MIN_DECODED_BYTES {
            return Base64Step::Continue;
        }
        let entropy = shannon_entropy(&decoded);
        if entropy < self.threshold {
            return Base64Step::Continue;
        }
        Base64Step::Match(MatchedSignal {
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

/// Outcome of evaluating one base64 candidate range.
enum Base64Step {
    /// No match; keep scanning.
    Continue,
    /// The candidate/budget cap was hit; stop scanning entirely.
    Stop,
    /// A qualifying payload was found.
    Match(MatchedSignal),
}

/// Find the next base64 candidate segment starting at `seg_start` within
/// `content[..run_end]`, returning its (exclusive) end and where to resume
/// scanning for the next one. A segment is either: a single line shorter
/// than [`MIN_WRAPPED_LINE_LEN`] (too narrow to be real wrapping — a blank
/// line, a wordlist entry, a short terminator word — judged only on its own
/// bytes); or a maximal *block* of consecutive lines that all share one
/// width >= [`MIN_WRAPPED_LINE_LEN`], optionally followed by one shorter
/// trailing line (real base64 wrapping's final, partial line). Splitting
/// into blocks this way means a block is unaffected by what lies just before
/// or after it in the run — a blank separator line or a heredoc terminator
/// word can't blind detection of a genuinely wrapped payload next to it, nor
/// can it borrow the payload's length to pass as one itself.
fn next_base64_segment(content: &[u8], seg_start: usize, run_end: usize) -> (usize, usize) {
    let (first_end, first_next) = next_base64_line(content, seg_start, run_end);
    let width = first_end - seg_start;
    if width < MIN_WRAPPED_LINE_LEN {
        return (first_end, first_next);
    }

    let mut block_end = first_end;
    let mut next = first_next;
    while next < run_end {
        let (line_end, line_next) = next_base64_line(content, next, run_end);
        if line_end - next != width {
            break;
        }
        block_end = line_end;
        next = line_next;
    }
    // One optional shorter (or equal) trailing line: the wrap remainder.
    if next < run_end {
        let (line_end, line_next) = next_base64_line(content, next, run_end);
        if line_end - next <= width {
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
        let words = [
            "password",
            "letmein",
            "hunter2",
            "qwerty123",
            "dragon",
            "monkey12",
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
}
