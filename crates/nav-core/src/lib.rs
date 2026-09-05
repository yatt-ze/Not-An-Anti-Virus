//! `nav-core` — NAV's heuristics/scoring engine.
//!
//! Its own crate so `navctl scan` / `navctl rules test` can run a full static
//! analysis in-process, with no `navd`, root, or socket (§2, §12 Phase 0a).
//! `navd` links the same crate for the privileged cases.
//!
//! Knows nothing about event sources, the daemon, sockets, or notifications —
//! it only turns a file path into a `ScanResult`.

pub mod bundle;
pub mod context;
pub mod cpio;
pub mod inflate;
pub mod macho;
pub mod model;
pub mod plist;
pub mod rules;
pub mod scan;
pub mod target;
pub mod xar;
pub mod xml;

pub use bundle::BundleLayout;
pub use context::{ContentSource, ScanContext};
pub use cpio::{CpioArchive, CpioEntry, CpioHalt, CpioLimits};
pub use inflate::{gzip_decompress, inflate, zlib_decompress, InflateError};
pub use model::{
    EvidenceConfidence, MatchedSignal, Recommendation, ScanCompleteness, ScanResult, SignalCategory,
};
pub use plist::PlistValue;
pub use rules::{default_ruleset, embedded_content_ruleset, Rule, RuleOutcome};
pub use scan::{
    scan_context, scan_embedded_bytes, scan_file, scan_file_with_rules, ENGINE_VERSION,
};
pub use target::{
    scan_target, scan_target_with_budget, BudgetLimit, BudgetOutcome, ScanBudget, TargetKind,
    TargetScan,
};
pub use xar::{XarArchive, XarFile, XarHalt, XarLimits};
