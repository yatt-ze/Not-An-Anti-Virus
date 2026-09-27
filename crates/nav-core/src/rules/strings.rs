//! Suspicious string/import scanning (§5.2): `dlopen`, `NSAppleScript`/
//! `osascript`, TCC database paths, Keychain APIs, curl-pipe-to-shell. A cheap
//! cross-platform substring scan, streamed past the 8 MiB prefix through the
//! scan's own file handle when truncation and file size allow it.

use super::{Rule, RuleOutcome};
use crate::context::{ScanContext, MAX_STREAM_BYTES};
use crate::model::{MatchedSignal, SignalCategory};

struct Marker {
    needle: &'static str,
    weight: i32,
    note: &'static str,
    /// Require a non-word byte (or end of input) after the needle — see
    /// `contains_token`. Used for markers that would otherwise match as a
    /// prefix of an unrelated word (`| sh` inside `| shasum`).
    bounded: bool,
}

const MARKERS: &[Marker] = &[
    Marker {
        needle: "NSAppleScript",
        weight: 6,
        note: "references NSAppleScript (AppleScript execution API)",
        bounded: false,
    },
    Marker {
        needle: "osascript",
        weight: 6,
        note: "references osascript (AppleScript/JXA interpreter)",
        bounded: false,
    },
    Marker {
        needle: "dlopen",
        weight: 4,
        note: "references dlopen (dynamic library loading)",
        bounded: false,
    },
    Marker {
        needle: "TCC.db",
        weight: 10,
        note: "references the TCC permissions database directly",
        bounded: false,
    },
    Marker {
        needle: "SecKeychain",
        weight: 8,
        note: "references Keychain Services APIs",
        bounded: false,
    },
    Marker {
        needle: "curl ",
        weight: 3,
        note: "references curl invocation",
        bounded: false,
    },
    Marker {
        needle: "| sh",
        weight: 10,
        note: "curl/download-pipe-to-shell pattern",
        bounded: true,
    },
    Marker {
        needle: "| bash",
        weight: 10,
        note: "curl/download-pipe-to-shell pattern",
        bounded: true,
    },
];

/// Whether `needle` occurs in `haystack` as a token, not as a prefix of a
/// longer word (`| sh` in `| shasum`). A match counts when the byte after it
/// is not ASCII alphanumeric/`_`/`-`/`.` — a negative class, since content is
/// lossy-decoded binary too (bplist/Mach-O bytes). A match running off the
/// end of `haystack` counts only when `is_last`: when scanning one window of
/// a larger stream, that match's tail is still ahead in the next window's
/// overlap and gets judged again once the following byte is available.
fn contains_token(haystack: &str, needle: &str, is_last: bool) -> bool {
    haystack.match_indices(needle).any(|(start, _)| {
        match haystack.as_bytes().get(start + needle.len()) {
            None => is_last,
            Some(b) => !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')),
        }
    })
}

/// Longest `MARKERS` needle, in bytes — the overlap `for_each_window` needs
/// so no needle can be split across a window boundary without landing whole
/// in some window.
const fn max_marker_len() -> usize {
    let mut max = 0usize;
    let mut i = 0usize;
    while i < MARKERS.len() {
        let len = MARKERS[i].needle.len();
        if len > max {
            max = len;
        }
        i += 1;
    }
    max
}

const MAX_MARKER_LEN: usize = max_marker_len();

/// Scans one window's lossy-decoded text for `MARKERS`, setting `hits[i]`
/// when marker `i` matches and isn't already set. `is_last` is forwarded to
/// [`contains_token`] for bounded markers — see its doc.
fn scan_window(text: &str, is_last: bool, hits: &mut [bool]) {
    for (i, marker) in MARKERS.iter().enumerate() {
        if hits[i] {
            continue;
        }
        let matched = if marker.bounded {
            contains_token(text, marker.needle, is_last)
        } else {
            text.contains(marker.needle)
        };
        if matched {
            hits[i] = true;
        }
    }
}

pub struct SuspiciousStringsRule;

impl Default for SuspiciousStringsRule {
    fn default() -> Self {
        SuspiciousStringsRule
    }
}

impl Rule for SuspiciousStringsRule {
    fn id(&self) -> &'static str {
        "suspicious-strings"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::StaticSuspicion
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let mut hits = vec![false; MARKERS.len()];

        if ctx.truncated && self.covers_truncation(ctx) {
            let file_len = ctx.file_len.ok_or(RuleOutcome::NotApplicable)?;
            let ok = ctx.for_each_window(0..file_len, MAX_MARKER_LEN, |window, is_last| {
                // Lossy-decoded: ASCII markers still match, no panic on non-UTF-8.
                scan_window(&String::from_utf8_lossy(window), is_last, &mut hits);
            });
            if !ok {
                return Err(RuleOutcome::NotApplicable);
            }
        } else {
            let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;
            scan_window(&String::from_utf8_lossy(content), true, &mut hits);
        }

        let matched: Vec<&Marker> = MARKERS
            .iter()
            .zip(hits.iter())
            .filter_map(|(m, &hit)| hit.then_some(m))
            .collect();
        if matched.is_empty() {
            return Ok(None);
        }

        let weight = matched.iter().map(|m| m.weight).sum();
        let description = format!(
            "matched {} marker(s): {}",
            matched.len(),
            matched
                .iter()
                .map(|m| m.note)
                .collect::<Vec<_>>()
                .join("; ")
        );

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight,
            description,
            category: self.category(),
        }))
    }

    /// Streams the whole file through the scan's own handle (§11.7) when it's
    /// within the streaming cap — otherwise the unread bytes past the 8 MiB
    /// prefix may hide a marker.
    fn covers_truncation(&self, ctx: &ScanContext) -> bool {
        ctx.is_file_backed() && ctx.file_len.is_some_and(|len| len <= MAX_STREAM_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{MAX_CONTENT_BYTES, STREAM_CHUNK};
    use std::io::{Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};

    #[test]
    fn rejects_word_extensions() {
        assert!(!contains_token("cat f | shasum -a 256", "| sh", true));
        assert!(!contains_token("cat f | sha256sum", "| sh", true));
        assert!(!contains_token("shuf -n1 list.txt | shuf", "| sh", true));
        assert!(!contains_token(
            "eval \"$(bashcompinit)\" | bashcompinit",
            "| bash",
            true
        ));
    }

    #[test]
    fn accepts_token_boundaries() {
        assert!(contains_token("curl x | sh", "| sh", true));
        assert!(contains_token("curl x | sh -s", "| sh", true));
        assert!(contains_token("curl x | sh\n", "| sh", true));
        assert!(contains_token("curl x | sh;", "| sh", true));
        assert!(contains_token("curl x | sh)", "| sh", true));
        assert!(contains_token("curl x | sh\"", "| sh", true));
        assert!(contains_token("curl x | sh\0", "| sh", true));
        assert!(contains_token("curl x | sh\t", "| sh", true));
        assert!(contains_token("curl x | bash", "| bash", true));
    }

    /// A match running off the end of a non-final window is inconclusive —
    /// the following byte lives in the next window's overlap — so it isn't
    /// counted until `is_last` says there's truly nothing more.
    #[test]
    fn a_match_at_the_end_of_a_non_final_window_is_not_counted() {
        assert!(!contains_token("curl x | sh", "| sh", false));
    }

    /// A zero-filled (sparse) temp file of exactly `total_len` bytes, for
    /// tests that need a file bigger than `MAX_CONTENT_BYTES` (or
    /// `MAX_STREAM_BYTES`) without writing that many bytes. Mirrors
    /// `context.rs`'s private test helper of the same name.
    fn sparse_temp_file(tag: &str, total_len: u64) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "nav-strings-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let f = std::fs::File::create(&p).unwrap();
        f.set_len(total_len).unwrap();
        p
    }

    fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
        let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.seek(SeekFrom::Start(offset)).unwrap();
        f.write_all(bytes).unwrap();
    }

    /// A marker past the 8 MiB prefix is invisible to a prefix-only scan, but
    /// `covers_truncation` opts this rule into streaming the whole file, so
    /// `evaluate` finds it.
    #[test]
    fn marker_past_the_prefix_is_found_when_covered() {
        let total_len = MAX_CONTENT_BYTES as u64 + 64 * 1024;
        let path = sparse_temp_file("past-prefix", total_len);
        write_at(&path, MAX_CONTENT_BYTES as u64 + 100, b"TCC.db");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rule = SuspiciousStringsRule;
        assert!(rule.covers_truncation(&ctx));
        rule.evaluate(&ctx)
            .expect("rule should be applicable")
            .expect("marker past the 8 MiB prefix should be found");

        let _ = std::fs::remove_file(&path);
    }

    /// A marker split across a `STREAM_CHUNK` boundary must still land whole
    /// in some window's overlap and be found.
    #[test]
    fn marker_straddling_a_stream_chunk_boundary_is_found() {
        let total_len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("chunk-straddle", total_len);
        write_at(&path, STREAM_CHUNK as u64 - 3, b"TCC.db");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rule = SuspiciousStringsRule;
        assert!(rule.covers_truncation(&ctx));
        rule.evaluate(&ctx)
            .expect("rule should be applicable")
            .expect("marker straddling a chunk boundary should be found");

        let _ = std::fs::remove_file(&path);
    }

    /// `| sh` ending exactly at a non-final window's boundary, immediately
    /// followed by `asum`, must not match — the same bytes reappear whole in
    /// the next window with `asum` right after them.
    #[test]
    fn bounded_marker_ending_at_a_window_boundary_is_not_matched() {
        let total_len = 10 * STREAM_CHUNK as u64;
        let path = sparse_temp_file("boundary-not-matched", total_len);
        let boundary = 9 * STREAM_CHUNK as u64; // past the 8 MiB prefix
        write_at(&path, boundary - 4, b"| shasum");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rule = SuspiciousStringsRule;
        assert!(rule.covers_truncation(&ctx));
        assert!(
            rule.evaluate(&ctx)
                .expect("rule should be applicable")
                .is_none(),
            "| sh ending exactly at a window boundary, followed by asum, must not match"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The same `| sh` at the true end of the file (nothing following at
    /// all) does match — that's a real end-of-input boundary, not a window
    /// artifact.
    #[test]
    fn bounded_marker_at_the_true_end_of_the_file_is_matched() {
        let total_len = 10 * STREAM_CHUNK as u64;
        let path = sparse_temp_file("end-of-file-matched", total_len);
        write_at(&path, total_len - 4, b"| sh");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rule = SuspiciousStringsRule;
        assert!(rule.covers_truncation(&ctx));
        rule.evaluate(&ctx)
            .expect("rule should be applicable")
            .expect("| sh at the true end of the file should match");

        let _ = std::fs::remove_file(&path);
    }

    /// Past `MAX_STREAM_BYTES`, `covers_truncation` declines and `evaluate`
    /// falls back to the 8 MiB prefix — a marker further in is missed, not
    /// discovered at the cost of streaming a huge file.
    #[cfg(unix)]
    #[test]
    fn file_beyond_the_stream_cap_falls_back_to_prefix_only_scan() {
        let total_len = MAX_STREAM_BYTES + 1;
        let path = sparse_temp_file("beyond-stream-cap", total_len);
        write_at(&path, MAX_CONTENT_BYTES as u64 + 100, b"TCC.db");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rule = SuspiciousStringsRule;
        assert!(!rule.covers_truncation(&ctx));
        assert!(
            rule.evaluate(&ctx)
                .expect("rule should be applicable")
                .is_none(),
            "a marker past the 8 MiB prefix must not be found when the file exceeds the stream cap"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Embedded content has no file behind it, so it can never be streamed.
    #[test]
    fn embedded_truncated_content_does_not_cover_truncation() {
        let ctx = ScanContext::from_embedded_bytes("x.pkg!Scripts/preinstall", vec![1, 2, 3], true);
        assert!(!SuspiciousStringsRule.covers_truncation(&ctx));
    }
}
