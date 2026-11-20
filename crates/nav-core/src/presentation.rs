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
/// Errors only if `value`'s own `Serialize` impl fails.
pub fn with_schema_version<T: Serialize>(
    value: &T,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut v = serde_json::to_value(value)?;
    if let serde_json::Value::Object(map) = &mut v {
        map.insert("schema_version".into(), SCAN_JSON_SCHEMA_VERSION.into());
    }
    Ok(v)
}

/// `result` as a single-line JSON string carrying `schema_version` — the
/// entry point for a caller (`navd`) that must not take its own
/// `serde_json` dependency just to print a verdict.
pub fn scan_result_json(result: &ScanResult) -> Result<String, serde_json::Error> {
    Ok(with_schema_version(result)?.to_string())
}

/// Human notes for the entries `scan`'s walk passed over by design (#159),
/// without a program prefix; empty when there were none. Informational
/// only: they do not change the exit code (§8). `all_links` adds the count
/// of links and special files that stay inside the target; links that
/// resolve outside it are always noted.
pub fn not_walked_notes(scan: &TargetScan, all_links: bool) -> Vec<String> {
    let nw = scan.not_walked;
    let root = scan.root.display();
    let mut notes = Vec::new();
    if nw.subdirs > 0 {
        notes.push(format!(
            "{} subdirector{} of {root} not scanned (use --recursive)",
            nw.subdirs,
            if nw.subdirs == 1 { "y" } else { "ies" }
        ));
    }
    if nw.links_outside > 0 {
        notes.push(format!(
            "{} symlink(s) under {root} point outside it (not followed)",
            nw.links_outside
        ));
    }
    let inside = nw.links_and_special - nw.links_outside;
    if all_links && inside > 0 {
        let other = if nw.links_outside > 0 { "other " } else { "" };
        notes.push(format!(
            "{inside} {other}symlink(s) or special file(s) under {root} not followed"
        ));
    }
    notes
}

/// `s` with control characters (C0, DEL, C1) and bidi embedding/override/
/// isolate characters replaced by U+FFFD, so untrusted text cannot rewrite
/// terminal output (§8). Borrows when nothing needs replacing.
pub fn terminal_safe(s: &str) -> std::borrow::Cow<'_, str> {
    fn unsafe_char(c: char) -> bool {
        c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
    }
    if !s.chars().any(unsafe_char) {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.chars()
            .map(|c| if unsafe_char(c) { '\u{FFFD}' } else { c })
            .collect(),
    )
}

/// `println!` through [`terminal_safe`]; for human output only.
#[macro_export]
macro_rules! safe_println {
    () => { ::std::println!() };
    ($($arg:tt)*) => {{
        let line = ::std::format!($($arg)*);
        ::std::println!("{}", $crate::presentation::terminal_safe(&line));
    }};
}

/// `print!` through [`terminal_safe`]; for human output only.
#[macro_export]
macro_rules! safe_print {
    ($($arg:tt)*) => {{
        let text = ::std::format!($($arg)*);
        ::std::print!("{}", $crate::presentation::terminal_safe(&text));
    }};
}

/// `eprintln!` through [`terminal_safe`]; for human output only.
#[macro_export]
macro_rules! safe_eprintln {
    ($($arg:tt)*) => {{
        let line = ::std::format!($($arg)*);
        ::std::eprintln!("{}", $crate::presentation::terminal_safe(&line));
    }};
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

    #[test]
    fn terminal_safe_replaces_controls_and_bidi() {
        let bad = [
            '\x1b', '\r', '\n', '\t', '\x7f', '\u{9b}', '\u{202A}', '\u{202B}', '\u{202C}',
            '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ];
        for c in bad {
            let s = format!("a{c}b");
            assert_eq!(terminal_safe(&s), "a\u{FFFD}b", "U+{:04X}", c as u32);
        }
    }

    #[test]
    fn terminal_safe_keeps_ordinary_text_borrowed() {
        for s in [
            "café",
            "日本語のテキスト",
            "plain ascii /tmp/x",
            "a\u{200E}b",
        ] {
            assert!(matches!(terminal_safe(s), std::borrow::Cow::Borrowed(_)));
            assert_eq!(terminal_safe(s), s);
        }
    }

    fn sample_result() -> ScanResult {
        ScanResult {
            path: PathBuf::from("/tmp/sample"),
            score: 0,
            confidence: EvidenceConfidence::Low,
            completeness: ScanCompleteness::Complete,
            coverage_gaps: Vec::new(),
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
        let value = with_schema_version(&sample_result()).unwrap();
        assert_eq!(value["schema_version"], SCAN_JSON_SCHEMA_VERSION);
        // Original fields still present — schema_version is additive.
        assert_eq!(value["score"], 0);
    }

    #[test]
    fn scan_result_json_parses_and_carries_schema_version() {
        let json = scan_result_json(&sample_result()).unwrap();
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
            not_walked: Default::default(),
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
            not_walked: Default::default(),
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
            not_walked: Default::default(),
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
            not_walked: Default::default(),
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
            not_walked: Default::default(),
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
            not_walked: Default::default(),
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
            not_walked: Default::default(),
            results: vec![notify],
            budget: BudgetOutcome::Within,
        };
        assert!(!scan.coverage_complete());
        assert_eq!(for_target(&scan), SUSPICIOUS);
    }

    /// A non-UTF-8 path serializes lossily instead of failing; a UTF-8 path
    /// is emitted unchanged.
    #[cfg(unix)]
    #[test]
    fn non_utf8_path_serializes_lossily() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let mut r = sample_result();
        r.path = PathBuf::from(OsStr::from_bytes(b"/tmp/\xff\xfe"));
        let value = with_schema_version(&r).expect("serializes");
        let text = serde_json::to_string(&value).unwrap();
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back["path"], "/tmp/\u{FFFD}\u{FFFD}");
        assert!(scan_result_json(&r).is_ok());
        assert_eq!(
            with_schema_version(&sample_result()).unwrap()["path"],
            "/tmp/sample"
        );
    }
}
