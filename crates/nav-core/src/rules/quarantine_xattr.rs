//! `com.apple.quarantine` extended-attribute detection (§4.1, §5.2).
//! Informational only — the flag just means "downloaded from the internet",
//! and most quarantined files are benign. Exists so other rules can use
//! "arrived via download" as context.

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::model::{MatchedSignal, SignalCategory};

pub struct QuarantineXattrRule;

impl Default for QuarantineXattrRule {
    fn default() -> Self {
        QuarantineXattrRule
    }
}

impl Rule for QuarantineXattrRule {
    fn id(&self) -> &'static str {
        "quarantine-xattr-present"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::Informational
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        // An xattr belongs to a file; container-extracted bytes have none.
        if !ctx.is_file_backed() {
            return Err(RuleOutcome::NotApplicable);
        }
        has_quarantine_xattr(&ctx.path)
    }

    /// Reads an xattr, never `ctx.content` — the content cap is irrelevant.
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        true
    }
}

#[cfg(target_os = "macos")]
fn has_quarantine_xattr(path: &std::path::Path) -> Result<Option<MatchedSignal>, RuleOutcome> {
    match xattr::get(path, "com.apple.quarantine") {
        Ok(Some(_)) => Ok(Some(MatchedSignal {
            id: "quarantine-xattr-present".to_string(),
            weight: 0,
            description: "file carries com.apple.quarantine (downloaded from the internet)"
                .to_string(),
            category: SignalCategory::Informational,
        })),
        Ok(None) => Ok(None),
        Err(_) => Err(RuleOutcome::NotApplicable),
    }
}

#[cfg(not(target_os = "macos"))]
fn has_quarantine_xattr(_path: &std::path::Path) -> Result<Option<MatchedSignal>, RuleOutcome> {
    Err(RuleOutcome::NotApplicable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ContentSource;
    use std::path::PathBuf;

    /// Reads an xattr, so a truncated content prefix has nothing to miss.
    #[test]
    fn covers_truncation_is_true() {
        let c = ScanContext {
            path: PathBuf::from("app"),
            content: Some(b"anything".to_vec()),
            truncated: true,
            file_len: Some(8),
            identity: None,
            source: ContentSource::File,
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
        };
        assert!(QuarantineXattrRule.covers_truncation(&c));
    }
}
