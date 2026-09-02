//! High-entropy content detection — a weak generic signal on its own (§5.1).
//!
//! Structure-aware, not whole-file:
//! - **Mach-O**: scores the `__TEXT` code section (§5.2) — packed/obfuscated
//!   code is well above the ceiling, normal machine code well below.
//! - **script/text**: flags an embedded obfuscated or base64/packed payload.
//! - **any other opaque binary** (archive, image, encrypted data): high
//!   entropy is expected, so it is *not* scored — whole-file scoring was a
//!   real false-positive source (a plain `.tar.gz` alerted) (§1).

use std::path::Path;

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::macho;
use crate::model::{MatchedSignal, SignalCategory};

/// Above this (out of 8.0 bits/byte, the max for byte-oriented Shannon
/// entropy) content reads as packed/encrypted/compressed rather than typical
/// machine code or text.
const ENTROPY_THRESHOLD: f64 = 7.0;

/// Below this many bytes an entropy figure is too noisy to act on.
const MIN_SAMPLE_BYTES: usize = 256;

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

    /// Score a high-entropy region inside a script/text file — an embedded
    /// obfuscated or base64/packed payload.
    fn eval_embedded_payload(&self, content: &[u8]) -> Option<MatchedSignal> {
        if content.len() < MIN_SAMPLE_BYTES {
            return None;
        }
        let entropy = shannon_entropy(content);
        if entropy < self.threshold {
            return None;
        }
        Some(MatchedSignal {
            id: self.id().to_string(),
            weight: 15,
            description: format!(
                "high-entropy content embedded in a script/text file \
                 (entropy: {:.1} bits/byte over {} bytes) — possible obfuscated/base64 payload",
                entropy,
                content.len()
            ),
            category: self.category(),
        })
    }
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
}
