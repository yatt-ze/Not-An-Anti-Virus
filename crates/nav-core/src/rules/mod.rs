//! The rule trait and the built-in ruleset.
//!
//! Every rule reports one of three outcomes, never a bare bool — "didn't fire"
//! and "couldn't be evaluated" must not collapse together (§10, §11.8).

use crate::context::ScanContext;
use crate::model::{MatchedSignal, SignalCategory};

mod codesign;
mod entropy;
mod macho_structure;
mod package;
mod persistence;
mod quarantine_xattr;
mod strings;

pub use codesign::{
    AdHocSignedRule, NotarizedRule, RevokedSignatureRule, UnnotarizedSignedRule, UnsignedBinaryRule,
};
pub use entropy::HighEntropyRule;
pub use macho_structure::MachOStructureRule;
pub use package::{InstallerScriptRule, UnsignedPackageRule};
pub use persistence::LaunchdPersistenceRule;
pub use quarantine_xattr::QuarantineXattrRule;
pub use strings::SuspiciousStringsRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleOutcome {
    /// The rule fired: `true` if it contributed a signal, `false` if it ran
    /// cleanly and found nothing.
    Evaluated(bool),
    /// The rule couldn't be evaluated here (macOS-only check on Linux,
    /// unreadable file, …). Must degrade `ScanCompleteness`, not silently pass.
    NotApplicable,
}

pub trait Rule: Send + Sync {
    /// Stable id, used in output and by the false-positive harness.
    fn id(&self) -> &'static str;

    fn category(&self) -> SignalCategory;

    /// Evaluate against the given context. Implementations return
    /// `Ok(Some(signal))` when the rule matched, `Ok(None)` when it ran but
    /// found nothing, and `Err(RuleOutcome::NotApplicable)` when the rule
    /// itself couldn't run here.
    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome>;
}

/// The default built-in ruleset. Small for Phase 0a (§12) — the goal is
/// proving the scanner produces useful, low-noise verdicts, not coverage.
pub fn default_ruleset() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(HighEntropyRule::default()),
        Box::new(SuspiciousStringsRule),
        Box::new(UnsignedBinaryRule),
        Box::new(AdHocSignedRule),
        Box::new(RevokedSignatureRule),
        Box::new(UnnotarizedSignedRule),
        Box::new(NotarizedRule),
        Box::new(QuarantineXattrRule),
        Box::new(LaunchdPersistenceRule),
        Box::new(InstallerScriptRule),
        Box::new(UnsignedPackageRule),
        Box::new(MachOStructureRule),
    ]
}

/// Rules that make sense against container-extracted content (§6.1): the
/// content-only ones. Excludes anything needing a file on disk, and the
/// package rules — so a `.pkg` in a `.pkg`'s scripts can't loop the scanner.
pub fn embedded_content_ruleset() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(HighEntropyRule::default()),
        Box::new(SuspiciousStringsRule),
    ]
}
