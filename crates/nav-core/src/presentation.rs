//! Canonical presentation contract for a [`ScanResult`]: the versioned
//! `--json` envelope and the `ScanResult`/`TargetScan` → exit-code mapping
//! (§8). `navctl` and `navd` both render a verdict through here so they
//! can't drift on schema or exit taxonomy.

use serde::Serialize;
use std::process::ExitCode;

use crate::model::{Recommendation, ScanCompleteness, ScanResult};
use crate::target::TargetScan;

/// Version of the scan `--json` output shape (§8). Bump on any breaking
/// change to the emitted fields — scripts key off this to detect drift.
pub const SCAN_JSON_SCHEMA_VERSION: u32 = 1;

/// Serializes `value` to a JSON object with `schema_version` merged in.
/// `value` must serialize to a JSON object (every current caller does).
pub fn with_schema_version<T: Serialize>(value: &T) -> serde_json::Value {
    let mut v = serde_json::to_value(value).expect("scan JSON output always serializes");
    if let serde_json::Value::Object(map) = &mut v {
        map.insert("schema_version".into(), SCAN_JSON_SCHEMA_VERSION.into());
    }
    v
}

/// `result` as a single-line JSON string carrying `schema_version` — the
/// entry point for a caller (`navd`) that must not take its own
/// `serde_json` dependency just to print a verdict.
pub fn scan_result_json(result: &ScanResult) -> String {
    with_schema_version(result).to_string()
}

pub const CLEAN: u8 = 0;
pub const SUSPICIOUS: u8 = 1;
pub const HIGH_RISK: u8 = 2;
pub const INDETERMINATE: u8 = 3;
pub const OPERATIONAL_ERROR: u8 = 4;

/// Exit code for one file's [`ScanResult`] (§8): a real finding (`Notify` or
/// `NotifyAndSuggestQuarantine`) always reports its severity regardless of
/// completeness. `NoAction` maps to `CLEAN` only when `completeness` is
/// `Complete`; otherwise `INDETERMINATE` — incompleteness never reads as
/// `CLEAN` (§10/§11.8).
pub fn for_result(result: &ScanResult) -> u8 {
    match result.recommendation {
        Recommendation::NotifyAndSuggestQuarantine => HIGH_RISK,
        Recommendation::Notify => SUSPICIOUS,
        Recommendation::NoAction => {
            if matches!(result.completeness, ScanCompleteness::Complete) {
                CLEAN
            } else {
                INDETERMINATE
            }
        }
    }
}

/// Exit code for a whole-target scan (§8): the worst file's, per
/// [`TargetScan::worst`] (`CLEAN` when `results` is empty), raised to
/// `INDETERMINATE` if coverage was cut short (§11.12) and that severity was
/// `CLEAN` — a real finding still outranks "couldn't finish," but
/// incompleteness is never `CLEAN`.
pub fn for_target(scan: &TargetScan) -> u8 {
    let worst = scan.worst().map(for_result).unwrap_or(CLEAN);
    if !scan.coverage_complete() && worst == CLEAN {
        INDETERMINATE
    } else {
        worst
    }
}

/// Converts a taxonomy code into a process [`ExitCode`].
pub fn exit_code(value: u8) -> ExitCode {
    ExitCode::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EvidenceConfidence;
    use crate::target::{BudgetLimit, BudgetOutcome, TargetKind};
    use std::path::PathBuf;
    use std::time::SystemTime;

    fn sample_result() -> ScanResult {
        ScanResult {
            path: PathBuf::from("/tmp/sample"),
            score: 0,
            confidence: EvidenceConfidence::Low,
            completeness: ScanCompleteness::Complete,
            signals: Vec::new(),
            recommendation: Recommendation::NoAction,
            engine_version: "test".to_string(),
            evaluated_at: SystemTime::UNIX_EPOCH,
        }
    }

    /// A real finding reports its severity even when the result is partial.
    #[test]
    fn for_result_partial_high_risk_is_high_risk() {
        let result = ScanResult {
            completeness: ScanCompleteness::Partial,
            recommendation: Recommendation::NotifyAndSuggestQuarantine,
            ..sample_result()
        };
        assert_eq!(for_result(&result), HIGH_RISK);
    }

    /// A real finding reports its severity even when the result is partial.
    #[test]
    fn for_result_partial_notify_is_suspicious() {
        let result = ScanResult {
            completeness: ScanCompleteness::Partial,
            recommendation: Recommendation::Notify,
            ..sample_result()
        };
        assert_eq!(for_result(&result), SUSPICIOUS);
    }

    /// A partial "nothing found" result is indeterminate, not clean.
    #[test]
    fn for_result_partial_no_action_is_indeterminate() {
        let result = ScanResult {
            completeness: ScanCompleteness::Partial,
            recommendation: Recommendation::NoAction,
            ..sample_result()
        };
        assert_eq!(for_result(&result), INDETERMINATE);
    }

    /// An indeterminate "nothing found" result is indeterminate, not clean.
    #[test]
    fn for_result_indeterminate_no_action_is_indeterminate() {
        let result = ScanResult {
            completeness: ScanCompleteness::Indeterminate,
            recommendation: Recommendation::NoAction,
            ..sample_result()
        };
        assert_eq!(for_result(&result), INDETERMINATE);
    }

    /// A complete result maps each recommendation to its exit code directly.
    #[test]
    fn for_result_complete_maps_each_recommendation() {
        let no_action = ScanResult {
            recommendation: Recommendation::NoAction,
            ..sample_result()
        };
        let notify = ScanResult {
            recommendation: Recommendation::Notify,
            ..sample_result()
        };
        let quarantine = ScanResult {
            recommendation: Recommendation::NotifyAndSuggestQuarantine,
            ..sample_result()
        };
        assert_eq!(for_result(&no_action), CLEAN);
        assert_eq!(for_result(&notify), SUSPICIOUS);
        assert_eq!(for_result(&quarantine), HIGH_RISK);
    }

    #[test]
    fn with_schema_version_adds_field_alongside_existing_ones() {
        let value = with_schema_version(&sample_result());
        assert_eq!(value["schema_version"], SCAN_JSON_SCHEMA_VERSION);
        // Original fields still present — schema_version is additive.
        assert_eq!(value["score"], 0);
    }

    #[test]
    fn scan_result_json_parses_and_carries_schema_version() {
        let json = scan_result_json(&sample_result());
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["schema_version"], SCAN_JSON_SCHEMA_VERSION);
        assert_eq!(value["score"], 0);
    }

    /// A budget-exhausted target is never a clean exit, even when every file it
    /// managed to scan was individually complete and clean — "couldn't finish"
    /// is not "clean" at the target level (§8, §11.8/§11.12).
    #[test]
    fn partial_coverage_makes_the_target_exit_indeterminate() {
        let mk = |budget| TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable: Vec::new(),
            results: vec![sample_result()], // complete + NoAction
            budget,
        };
        assert_eq!(
            for_target(&mk(BudgetOutcome::Within)),
            CLEAN,
            "a fully covered clean target exits clean"
        );
        assert_eq!(
            for_target(&mk(BudgetOutcome::Exhausted(BudgetLimit::Files))),
            INDETERMINATE,
            "a target cut short by the budget is indeterminate, not clean"
        );
    }

    /// An unreadable subdirectory makes a target partial the same way a
    /// budget ceiling does, even when every scored file was clean
    /// (§11.8/§11.12).
    #[test]
    fn unreadable_subdirectory_makes_the_target_exit_indeterminate() {
        let scan = TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable: vec![PathBuf::from("/tmp/locked")],
            results: vec![sample_result()], // complete + NoAction
            budget: BudgetOutcome::Within,
        };
        assert!(!scan.coverage_complete());
        assert_eq!(for_target(&scan), INDETERMINATE);
    }

    /// #34: a high-risk file's exit code isn't masked by an unrelated
    /// partial file in the same target.
    #[test]
    fn issue_34_high_risk_outranks_a_partial_sibling() {
        let high_risk = ScanResult {
            recommendation: Recommendation::NotifyAndSuggestQuarantine,
            ..sample_result()
        };
        let partial_no_action = ScanResult {
            completeness: ScanCompleteness::Partial,
            ..sample_result()
        };
        let scan = TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable: Vec::new(),
            results: vec![high_risk, partial_no_action],
            budget: BudgetOutcome::Within,
        };
        assert!(scan.coverage_complete());
        assert_eq!(for_target(&scan), HIGH_RISK);
    }

    /// A `Notify` finding outranks an unrelated partial sibling the same way.
    #[test]
    fn suspicious_outranks_a_partial_sibling() {
        let notify = ScanResult {
            recommendation: Recommendation::Notify,
            ..sample_result()
        };
        let partial_no_action = ScanResult {
            completeness: ScanCompleteness::Partial,
            ..sample_result()
        };
        let scan = TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable: Vec::new(),
            results: vec![notify, partial_no_action],
            budget: BudgetOutcome::Within,
        };
        assert_eq!(for_target(&scan), SUSPICIOUS);
    }

    /// Two clean-or-nothing files, one partial, is indeterminate — there's no
    /// real finding to outrank the incompleteness.
    #[test]
    fn no_finding_and_a_partial_sibling_is_indeterminate() {
        let partial_no_action = ScanResult {
            completeness: ScanCompleteness::Partial,
            ..sample_result()
        };
        let scan = TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable: Vec::new(),
            results: vec![sample_result(), partial_no_action],
            budget: BudgetOutcome::Within,
        };
        assert_eq!(for_target(&scan), INDETERMINATE);
    }

    /// A budget-exhausted target with a complete high-risk file still exits
    /// high-risk — the finding outranks "couldn't finish."
    #[test]
    fn budget_exhausted_with_a_high_risk_file_is_high_risk() {
        let high_risk = ScanResult {
            recommendation: Recommendation::NotifyAndSuggestQuarantine,
            ..sample_result()
        };
        let scan = TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable: Vec::new(),
            results: vec![high_risk],
            budget: BudgetOutcome::Exhausted(BudgetLimit::Files),
        };
        assert_eq!(for_target(&scan), HIGH_RISK);
    }

    /// An unreadable subdirectory alongside a complete `Notify` file still
    /// exits suspicious — the finding outranks "couldn't finish."
    #[test]
    fn unreadable_subdirectory_with_a_notify_file_is_suspicious() {
        let notify = ScanResult {
            recommendation: Recommendation::Notify,
            ..sample_result()
        };
        let scan = TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable: vec![PathBuf::from("/tmp/locked")],
            results: vec![notify],
            budget: BudgetOutcome::Within,
        };
        assert!(!scan.coverage_complete());
        assert_eq!(for_target(&scan), SUSPICIOUS);
    }
}
