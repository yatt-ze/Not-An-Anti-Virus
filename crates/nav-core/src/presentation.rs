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

/// Exit code for one file's [`ScanResult`] (§8): completeness dominates the
/// verdict — anything short of `Complete` maps to `INDETERMINATE` regardless
/// of score, never folded into `CLEAN` (§10/§11.8).
pub fn for_result(result: &ScanResult) -> u8 {
    if !matches!(result.completeness, ScanCompleteness::Complete) {
        return INDETERMINATE;
    }
    match result.recommendation {
        Recommendation::NoAction => CLEAN,
        Recommendation::Notify => SUSPICIOUS,
        Recommendation::NotifyAndSuggestQuarantine => HIGH_RISK,
    }
}

/// Exit code for a whole-target scan: the worst scored file's code, raised to
/// `INDETERMINATE` when the target's coverage was cut short by the scan
/// budget (§11.12) — "couldn't finish scanning the target" is not "clean,"
/// the target-level counterpart to [`for_result`]. `CLEAN` when nothing was
/// scanned (callers that must tell "clean" from "empty" check `results`
/// first).
pub fn for_target(scan: &TargetScan) -> u8 {
    let worst = scan.results.iter().map(for_result).max().unwrap_or(CLEAN);
    if scan.coverage_complete() {
        worst
    } else {
        worst.max(INDETERMINATE)
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
}
