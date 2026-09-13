//! Exit codes (§8) — re-exports the shared `ScanResult`/`TargetScan` → code
//! taxonomy now owned by `nav-core` (see `nav_core::presentation`), so every
//! call site in this crate is unchanged.
//!
//! Kept as plain `u8` (not `ExitCode`, which can't be inspected once built) so
//! callers can combine results before converting once in `main`.

pub use nav_core::{
    exit_code as code, for_result, for_target, CLEAN, INDETERMINATE, OPERATIONAL_ERROR,
};
