//! Containers the engine cannot look inside (§10, §11.8).

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::model::{MatchedSignal, SignalCategory};

/// UDIF trailer size; its first four bytes are the `koly` signature.
const UDIF_TRAILER_LEN: u64 = 512;
const UDIF_SIGNATURE: &[u8; 4] = b"koly";

/// Flags a macOS disk image (UDIF) as not inspected. Weight 0: it only marks
/// the scan incomplete so the file never reads as clean (§10, §11.8).
#[derive(Debug, Default, Clone, Copy)]
pub struct UninspectedContainerRule;

/// Whether `ctx` ends in a UDIF trailer. `None` if the length is unknown or
/// the tail cannot be read. Matches the 4-byte signature only, so a tweaked
/// header still counts.
fn is_udif_disk_image(ctx: &ScanContext) -> Option<bool> {
    let len = ctx.file_len?;
    if len < UDIF_TRAILER_LEN {
        return Some(false);
    }
    let sig = ctx.read_at(len - UDIF_TRAILER_LEN, UDIF_SIGNATURE.len())?;
    Some(sig == UDIF_SIGNATURE)
}

impl Rule for UninspectedContainerRule {
    fn id(&self) -> &'static str {
        "uninspected-container"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::Informational
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        if ctx.content.is_none() {
            return Err(RuleOutcome::NotApplicable);
        }
        match is_udif_disk_image(ctx) {
            None => Err(RuleOutcome::NotApplicable),
            Some(false) => Ok(None),
            Some(true) => {
                ctx.mark_incomplete(self.id());
                Ok(Some(MatchedSignal {
                    id: self.id().to_string(),
                    weight: 0,
                    description:
                        "disk image (UDIF) not inspected — mount it read-only and scan the volume"
                            .into(),
                    category: self.category(),
                }))
            }
        }
    }

    /// Reads the file's tail itself, so a truncated prefix does not matter.
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::MAX_CONTENT_BYTES;
    use crate::model::{Recommendation, ScanCompleteness};
    use crate::scan::scan_context;
    use crate::test_support::{sparse_temp_file, write_at};

    fn embedded(buf: Vec<u8>) -> ScanContext {
        ScanContext::from_embedded_bytes("x.dmg", buf, false)
    }

    fn with_koly_at(len: usize, at: usize) -> ScanContext {
        let mut buf = vec![0u8; len];
        buf[at..at + 4].copy_from_slice(b"koly");
        embedded(buf)
    }

    fn fires(ctx: &ScanContext) -> bool {
        UninspectedContainerRule.evaluate(ctx).unwrap().is_some()
    }

    #[test]
    fn trailer_signature_fires() {
        let ctx = with_koly_at(1024, 1024 - 512);
        assert!(fires(&ctx));
        assert!(ctx.marked_incomplete("uninspected-container"));
    }

    #[test]
    fn signature_elsewhere_does_not_fire() {
        for at in [0, 1024 - 511, 1024 - 4] {
            assert!(!fires(&with_koly_at(1024, at)), "koly at {at}");
        }
    }

    #[test]
    fn short_and_plain_inputs_do_not_fire() {
        assert!(!fires(&with_koly_at(511, 0)));
        assert!(!fires(&embedded(b"#!/bin/sh\necho hi\n".repeat(100))));
        assert!(!fires(&embedded(Vec::new())));
    }

    #[test]
    fn tail_past_the_content_cap_is_read() {
        let len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("udif-tail", len);
        write_at(&path, len - 512, b"koly");
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(UninspectedContainerRule)];
        let result = scan_context(&ctx, &rules);
        let _ = std::fs::remove_file(&path);
        assert_eq!(result.signals.len(), 1);
        assert_eq!(result.completeness, ScanCompleteness::Partial);
    }

    #[test]
    fn fixture_disk_image_scans_partial_and_indeterminate() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/suspicious/dropper_in_disk_image.dmg");
        let result = crate::scan::scan_file(&path);
        assert!(result
            .signals
            .iter()
            .any(|s| s.id == "uninspected-container"));
        assert_eq!(result.completeness, ScanCompleteness::Partial);
        assert_eq!(result.recommendation, Recommendation::NoAction);
        assert_eq!(result.score, 0);
        assert_eq!(
            crate::presentation::for_result(&result),
            crate::presentation::INDETERMINATE
        );
    }
}
