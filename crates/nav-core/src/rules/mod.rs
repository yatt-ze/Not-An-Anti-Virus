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

/// Per-user/system temp and shared-writable locations a legitimate program
/// almost never runs or loads from. Shared so the persistence and
/// Mach-O-loader rules can't drift apart on what counts as transient (#39).
/// Private is enough: `persistence`/`macho_structure` are child modules of
/// `rules`, so they can already see a private item of their parent.
const TRANSIENT_PREFIXES: &[&str] = &[
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/private/var/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "/Users/Shared/",
];

pub trait Rule: Send + Sync {
    /// Stable id, used in output and by the false-positive harness.
    fn id(&self) -> &'static str;

    fn category(&self) -> SignalCategory;

    /// Evaluate against the given context. Implementations return
    /// `Ok(Some(signal))` when the rule matched, `Ok(None)` when it ran but
    /// found nothing, and `Err(RuleOutcome::NotApplicable)` when the rule
    /// itself couldn't run here.
    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome>;

    /// True only when this rule's result for `ctx` doesn't depend on bytes
    /// past `ctx.content` — it doesn't read content, or it read what it
    /// needed itself (`read_at`/`for_each_window`). A failed read must
    /// return `NotApplicable` or be recorded with
    /// `ScanContext::mark_stream_failed` so this returns `false`; it is
    /// called after `evaluate`. Only consulted when `ctx` is truncated; the
    /// default keeps "truncated ⇒ Partial" (§5.5).
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        false
    }
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
