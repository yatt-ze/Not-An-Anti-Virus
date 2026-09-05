//! Exit codes (§8) — distinguish scan completeness from verdict, so a script
//! can't confuse a partial scan with a clean one.
//!
//! Kept as plain `u8` (not `ExitCode`, which can't be inspected once built) so
//! callers can combine results before converting once in `main`.

use std::process::ExitCode;

pub const CLEAN: u8 = 0;
pub const SUSPICIOUS: u8 = 1;
pub const HIGH_RISK: u8 = 2;
pub const INDETERMINATE: u8 = 3;
pub const OPERATIONAL_ERROR: u8 = 4;

pub fn for_result(result: &nav_core::ScanResult) -> u8 {
    use nav_core::{Recommendation, ScanCompleteness};

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
/// `INDETERMINATE` when the target's coverage was cut short by the scan budget
/// (§11.12) — "couldn't finish scanning the target" is not "clean," the
/// target-level counterpart to the per-file completeness check in
/// [`for_result`]. `CLEAN` when nothing was scanned (callers that must tell
/// "clean" from "empty" check `results` first).
pub fn for_target(scan: &nav_core::TargetScan) -> u8 {
    let worst = scan.results.iter().map(for_result).max().unwrap_or(CLEAN);
    if scan.coverage_complete() {
        worst
    } else {
        worst.max(INDETERMINATE)
    }
}

pub fn code(value: u8) -> ExitCode {
    ExitCode::from(value)
}
