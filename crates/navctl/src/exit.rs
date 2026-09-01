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

pub fn code(value: u8) -> ExitCode {
    ExitCode::from(value)
}
