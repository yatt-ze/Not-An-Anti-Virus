//! Human and `--json` rendering for `scan` / `rules test` / `rules list`.
//!
//! `--json` mirrors the human structure — both render the same
//! `nav_core::ScanResult` (§5.5), plus a top-level `schema_version` marking
//! the JSON as a versioned contract (§8), via the shared envelope in
//! `nav_core::presentation`.
//! `scan` prints one terse line per file, except a `.app` bundle, which gets
//! one line for the bundle (per-file lines with `--verbose`);
//! `rules test` prints the worst file's full breakdown plus a roll-up.

use std::path::{Path, PathBuf};

use nav_core::model::lossy_path;
use std::process::ExitCode;

use nav_core::{
    scan_target, with_schema_version, BudgetLimit, BudgetOutcome, EvidenceConfidence,
    Recommendation, ScanCompleteness, ScanResult, TargetKind, TargetScan, SCAN_JSON_SCHEMA_VERSION,
};

use crate::exit;

pub fn run_scan(path: &Path, recursive: bool, json: bool, verbose: bool) -> ExitCode {
    let scan = match scan_target(path, recursive) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("navctl: {}: {e}", path.display());
            return exit::code(exit::OPERATIONAL_ERROR);
        }
    };

    if scan.results.is_empty() {
        if let Some(note) = unreadable_note(&scan) {
            eprintln!("{note}");
        }
        eprintln!("navctl: no files found under {}", path.display());
        return exit::code(empty_scan_exit_code(&scan));
    }

    let bundle_line = !json && scan.kind == TargetKind::Bundle;
    for result in &scan.results {
        if json {
            match with_schema_version(result) {
                Ok(v) => println!("{v}"),
                Err(e) => return json_error(&e),
            }
        } else if !bundle_line || verbose {
            print_scan_summary(result);
        }
    }
    if bundle_line {
        println!("{}", bundle_summary_line(&scan));
    }
    // Budget-exhausted coverage goes to stderr (keeping the --json stream on
    // stdout parseable as one object per file) and is folded into the exit
    // code below — a target cut short is not a clean target (§8, §11.8/§11.12).
    if let BudgetOutcome::Exhausted(limit) = scan.budget {
        eprintln!(
            "navctl: partial coverage — scan budget reached ({}); more of {} was not scanned",
            budget_limit_label(limit),
            path.display()
        );
    }
    if !json {
        for note in uninspected_notes(&scan.results) {
            eprintln!("{note}");
        }
    }
    if let Some(note) = unreadable_note(&scan) {
        eprintln!("{note}");
    }
    exit::code(exit::for_target(&scan))
}

pub fn run_rules_test(path: &Path, recursive: bool, json: bool) -> ExitCode {
    if !path.exists() {
        eprintln!("navctl: {} does not exist", path.display());
        return exit::code(exit::OPERATIONAL_ERROR);
    }

    let scan = match scan_target(path, recursive) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("navctl: {}: {e}", path.display());
            return exit::code(exit::OPERATIONAL_ERROR);
        }
    };

    // Single-file target: one full breakdown.
    if scan.kind == TargetKind::File {
        let result = &scan.results[0];
        if json {
            match with_schema_version(result).and_then(|v| serde_json::to_string_pretty(&v)) {
                Ok(s) => println!("{s}"),
                Err(e) => return json_error(&e),
            }
        } else {
            print_rules_test(result);
        }
        return exit::code(exit::for_result(result));
    }

    if scan.results.is_empty() {
        // Nothing readable — "couldn't check", not "clean" (§10, §11.8).
        if let Some(note) = unreadable_note(&scan) {
            eprintln!("{note}");
            // Unreadable subdirectories are structured data (§11.12), so a
            // `--json` caller gets the multi-target envelope — empty
            // `results`, `coverage_complete: false`, the `unreadable` array —
            // rather than only a stderr note. `print_rules_test_multi` isn't
            // usable here: it expects a non-empty `results` to pick a worst
            // file from.
            if json {
                return match print_multi_json(&scan) {
                    Ok(()) => exit::code(exit::INDETERMINATE),
                    Err(e) => json_error(&e),
                };
            }
        }
        eprintln!("navctl: no files to scan under {}", path.display());
        return exit::code(exit::INDETERMINATE);
    }

    if json {
        if let Err(e) = print_multi_json(&scan) {
            return json_error(&e);
        }
    } else {
        print_rules_test_multi(&scan);
    }

    exit::code(exit::for_target(&scan))
}

pub fn run_rules_list() -> ExitCode {
    for rule in nav_core::default_ruleset() {
        println!("{:<28} {:?}", rule.id(), rule.category());
    }
    exit::code(exit::CLEAN)
}

fn print_scan_summary(result: &ScanResult) {
    println!(
        "{}",
        summary_line(
            &result.path.display().to_string(),
            result.score,
            result.confidence,
            result.completeness,
            result.recommendation,
        )
    );
}

fn summary_line(
    path: &str,
    score: i32,
    confidence: EvidenceConfidence,
    completeness: ScanCompleteness,
    recommendation: Recommendation,
) -> String {
    format!(
        "{path}  score={:<4} confidence={:<6} completeness={:<13} -> {}",
        score,
        confidence_str(confidence),
        completeness_str(completeness),
        recommendation_str(recommendation, completeness),
    )
}

/// One line for a bundle: the worst file's verdict plus a file-count suffix.
/// The worst file's completeness, raised to `Partial` when that file was
/// `Complete` but the target's coverage was not. Precondition: `scan.results`
/// is non-empty.
fn target_completeness(scan: &TargetScan) -> ScanCompleteness {
    let worst = scan.worst().expect("non-empty results");
    match worst.completeness {
        ScanCompleteness::Complete if !scan.coverage_complete() => ScanCompleteness::Partial,
        c => c,
    }
}

fn bundle_summary_line(scan: &TargetScan) -> String {
    let worst = scan.worst().expect("non-empty results");
    let completeness = target_completeness(scan);
    let line = summary_line(
        &scan.root.display().to_string(),
        worst.score,
        worst.confidence,
        completeness,
        worst.recommendation,
    );
    let n = scan.results.len();
    // `worst()` ranks by severity then score, so this holds for every member.
    let all_clean = worst.completeness == ScanCompleteness::Complete
        && worst.recommendation == Recommendation::NoAction
        && worst.score <= 0;
    if all_clean {
        return format!("{line}  (bundle: {n} files)");
    }
    let star = if scan.primary.as_deref() == Some(worst.path.as_path()) {
        "*"
    } else {
        ""
    };
    format!(
        "{line}  (bundle: {n} files; worst: {}{star})",
        display_relative(&scan.root, &worst.path)
    )
}

fn print_rules_test(result: &ScanResult) {
    println!("Threat score:        {}", result.score);
    println!("Evidence confidence: {}", confidence_str(result.confidence));
    println!(
        "Scan completeness:   {}",
        completeness_str(result.completeness)
    );
    println!();

    if result.signals.is_empty() {
        println!("Signals matched: (none)");
    } else {
        println!("Signals matched:");
        for s in &result.signals {
            println!("  [{:+4}] {:<28} {}", s.weight, s.id, s.description);
        }
    }
    println!();
    println!(
        "Recommendation: {}",
        recommendation_str(result.recommendation, result.completeness)
    );
}

/// Directory / bundle breakdown: full detail for the worst file, a
/// one-line-per-file roll-up, then the target verdict (the worst file's —
/// scores are never summed).
fn print_rules_test_multi(scan: &TargetScan) {
    let worst = scan.worst().expect("non-empty results");

    if scan.kind == TargetKind::Bundle {
        println!("Bundle: {}", scan.root.display());
        match &scan.primary {
            Some(p) => println!("Main executable: {}", display_relative(&scan.root, p)),
            None => println!("Main executable: (could not resolve — scanned all members)"),
        }
        print!("Files scanned: {}", scan.results.len());
        if !scan.skipped.is_empty() {
            print!(" ({} compiled resource(s) not scored)", scan.skipped.len());
        }
        println!();
    } else {
        println!(
            "Target: {} ({} files scanned)",
            scan.root.display(),
            scan.results.len()
        );
    }
    if let Some(note) = budget_note(scan) {
        println!("{note}");
    }
    if let Some(note) = unreadable_coverage_note(scan) {
        println!("{note}");
    }
    println!();
    println!(
        "Worst finding — {}",
        display_relative(&scan.root, &worst.path)
    );
    println!("  Threat score:        {}", worst.score);
    println!(
        "  Evidence confidence: {}",
        confidence_str(worst.confidence)
    );
    println!(
        "  Scan completeness:   {}",
        completeness_str(worst.completeness)
    );
    if worst.signals.is_empty() {
        println!("  Signals matched: (none)");
    } else {
        println!("  Signals matched:");
        for s in &worst.signals {
            println!("    [{:+4}] {:<28} {}", s.weight, s.id, s.description);
        }
    }
    println!();

    println!("All files:");
    for result in &scan.results {
        let marker = if scan.primary.as_deref() == Some(result.path.as_path()) {
            "  *"
        } else {
            "   "
        };
        println!(
            "{marker} {:<48} score={:<4} completeness={:<13} -> {}",
            display_relative(&scan.root, &result.path),
            result.score,
            completeness_str(result.completeness),
            recommendation_str(result.recommendation, result.completeness),
        );
    }
    if scan.primary.is_some() {
        println!("  (* = bundle main executable)");
    }
    println!();
    println!(
        "Recommendation: {}",
        recommendation_str(scan.recommendation(), target_completeness(scan))
    );
}

/// Report a JSON serialization failure as an operational error (§8).
fn json_error(e: &serde_json::Error) -> ExitCode {
    eprintln!("navctl: cannot serialize JSON output: {e}");
    exit::code(exit::OPERATIONAL_ERROR)
}

fn print_multi_json(scan: &TargetScan) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(&multi_json(scan)?)?);
    Ok(())
}

fn multi_json(scan: &TargetScan) -> Result<serde_json::Value, serde_json::Error> {
    let kind = match scan.kind {
        TargetKind::Bundle => "bundle",
        _ => "directory",
    };
    let paths = |ps: &[PathBuf]| ps.iter().map(lossy_path::to_value).collect::<Vec<_>>();
    Ok(serde_json::json!({
        "schema_version": SCAN_JSON_SCHEMA_VERSION,
        "target": lossy_path::to_value(&scan.root),
        "kind": kind,
        "primary": scan.primary.as_ref().map(lossy_path::to_value),
        "skipped_resources": paths(&scan.skipped),
        "coverage_complete": scan.coverage_complete(),
        "budget_limit": budget_limit_str(scan),
        "unreadable": paths(&scan.unreadable),
        "recommendation": serde_json::to_value(scan.recommendation())?,
        "results": serde_json::to_value(&scan.results)?,
    }))
}

/// A human-readable warning when a scan budget cut the target short, or `None`
/// when the whole target was covered. Coverage that stops short is surfaced,
/// never silently dropped (§11.8).
fn budget_note(scan: &TargetScan) -> Option<String> {
    match scan.budget {
        BudgetOutcome::Within => None,
        BudgetOutcome::Exhausted(limit) => Some(format!(
            "  [PARTIAL COVERAGE: scan budget reached ({}) — more of this target was not scanned]",
            budget_limit_label(limit)
        )),
    }
}

/// Exit code for a `scan` target that scored no files: `INDETERMINATE` when
/// unreadable directories explain the emptiness — "couldn't check," not a
/// tool failure (§10/§11.8) — `OPERATIONAL_ERROR` otherwise (issue #29,
/// unchanged).
fn empty_scan_exit_code(scan: &TargetScan) -> u8 {
    if scan.unreadable.is_empty() {
        exit::OPERATIONAL_ERROR
    } else {
        exit::INDETERMINATE
    }
}

/// A stderr warning naming directories that couldn't be read during
/// traversal, or `None` when there were none. Traversal continues past each
/// one (§11.8); their presence is what makes the target's coverage partial
/// (§11.12).
fn unreadable_note(scan: &TargetScan) -> Option<String> {
    if scan.unreadable.is_empty() {
        return None;
    }
    let paths = scan
        .unreadable
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "navctl: partial coverage — {} director(ies) could not be read under {}: {}",
        scan.unreadable.len(),
        scan.root.display(),
        paths
    ))
}

/// One stderr line per result carrying the `uninspected-container` signal
/// (§10, §11.8), so a human sees why a clean-looking score exits 3.
fn uninspected_notes(results: &[ScanResult]) -> Vec<String> {
    results
        .iter()
        .flat_map(|r| {
            r.signals
                .iter()
                .filter(|s| s.id == "uninspected-container")
                .map(|s| format!("navctl: {}: {}", r.path.display(), s.description))
        })
        .collect()
}

/// Human-output counterpart to [`unreadable_note`], formatted like
/// [`budget_note`] for `rules test`'s multi-file breakdown.
fn unreadable_coverage_note(scan: &TargetScan) -> Option<String> {
    if scan.unreadable.is_empty() {
        return None;
    }
    let paths = scan
        .unreadable
        .iter()
        .map(|p| display_relative(&scan.root, p))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "  [PARTIAL COVERAGE: {} director(ies) could not be read under {}: {}]",
        scan.unreadable.len(),
        scan.root.display(),
        paths
    ))
}

/// Machine-readable budget-limit tag for `--json`, or `None` if within budget.
fn budget_limit_str(scan: &TargetScan) -> Option<&'static str> {
    match scan.budget {
        BudgetOutcome::Within => None,
        BudgetOutcome::Exhausted(limit) => Some(budget_limit_label(limit)),
    }
}

fn budget_limit_label(limit: BudgetLimit) -> &'static str {
    match limit {
        BudgetLimit::Files => "max-files",
        BudgetLimit::TotalBytes => "max-total-bytes",
        BudgetLimit::Depth => "max-depth",
        BudgetLimit::Entries => "max-entries",
    }
}

/// Render `path` relative to `root` when it sits under it, for compact output.
fn display_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

fn confidence_str(c: EvidenceConfidence) -> &'static str {
    match c {
        EvidenceConfidence::Low => "Low",
        EvidenceConfidence::Medium => "Medium",
        EvidenceConfidence::High => "High",
    }
}

fn completeness_str(c: ScanCompleteness) -> &'static str {
    match c {
        ScanCompleteness::Complete => "Complete",
        ScanCompleteness::Partial => "Partial",
        ScanCompleteness::Indeterminate => "Indeterminate",
    }
}

/// `NoAction` reads "clean" only when the scan was `Complete` (§10, §11.8).
fn recommendation_str(r: Recommendation, completeness: ScanCompleteness) -> &'static str {
    match r {
        Recommendation::NoAction if completeness == ScanCompleteness::Complete => {
            "no action (clean)"
        }
        Recommendation::NoAction => "no action (not fully checked)",
        Recommendation::Notify => "notify",
        Recommendation::NotifyAndSuggestQuarantine => {
            "notify + suggest quarantine (no auto-action without opt-in)"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn uninspected_notes_name_only_results_with_the_signal() {
        let mut flagged = sample_result();
        flagged.signals.push(nav_core::model::MatchedSignal {
            id: "uninspected-container".to_string(),
            weight: 0,
            description: "disk image not inspected".to_string(),
            category: nav_core::model::SignalCategory::Informational,
        });
        let notes = uninspected_notes(&[sample_result(), flagged]);
        assert_eq!(
            notes,
            vec!["navctl: /tmp/sample: disk image not inspected".to_string()]
        );
    }

    #[test]
    fn with_schema_version_adds_field_alongside_existing_ones() {
        let value = with_schema_version(&sample_result()).unwrap();
        assert_eq!(value["schema_version"], SCAN_JSON_SCHEMA_VERSION);
        // Original fields still present — schema_version is additive.
        assert_eq!(value["score"], 0);
    }

    #[test]
    fn multi_json_carries_schema_version() {
        let scan = TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable: Vec::new(),
            results: vec![sample_result()],
            budget: nav_core::BudgetOutcome::Within,
        };
        let value = multi_json(&scan).unwrap();
        assert_eq!(value["schema_version"], SCAN_JSON_SCHEMA_VERSION);
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
            exit::for_target(&mk(BudgetOutcome::Within)),
            exit::CLEAN,
            "a fully covered clean target exits clean"
        );
        assert_eq!(
            exit::for_target(&mk(BudgetOutcome::Exhausted(BudgetLimit::Files))),
            exit::INDETERMINATE,
            "a target cut short by the budget is indeterminate, not clean"
        );
    }

    fn empty_scan(unreadable: Vec<PathBuf>) -> TargetScan {
        TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable,
            results: Vec::new(),
            budget: nav_core::BudgetOutcome::Within,
        }
    }

    /// #32 follow-up: a target whose only content is unreadable subdirectories
    /// (the Phase 0b B3 TCC case) is "couldn't check," not a tool failure —
    /// distinct from a target that is genuinely empty (issue #29, unchanged).
    #[test]
    fn empty_scan_exit_code_is_indeterminate_only_when_unreadable_explains_it() {
        assert_eq!(
            empty_scan_exit_code(&empty_scan(Vec::new())),
            exit::OPERATIONAL_ERROR,
            "a genuinely empty, fully-readable target is still issue #29's exit 4"
        );
        assert_eq!(
            empty_scan_exit_code(&empty_scan(vec![PathBuf::from("/tmp/locked")])),
            exit::INDETERMINATE,
            "unreadable subdirectories explain the emptiness — couldn't check, not a failure"
        );
    }

    /// `multi_json` must stay safe on an empty-results scan — it backs the
    /// `rules test --json` branch for a target whose only content is
    /// unreadable subdirectories, which never reaches `print_rules_test_multi`
    /// (whose `worst().expect(..)` would panic on empty `results`).
    #[test]
    fn multi_json_on_empty_results_reports_incomplete_coverage() {
        let scan = empty_scan(vec![PathBuf::from("/tmp/locked")]);
        let value = multi_json(&scan).unwrap();
        assert_eq!(value["results"], serde_json::json!([]));
        assert_eq!(value["coverage_complete"], false);
        assert_eq!(value["unreadable"], serde_json::json!(["/tmp/locked"]));
    }

    /// Non-UTF-8 paths in every path-bearing field give valid JSON.
    #[cfg(unix)]
    #[test]
    fn multi_json_serializes_non_utf8_paths_lossily() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let bad = |s: &[u8]| PathBuf::from(OsStr::from_bytes(s));
        let mut result = sample_result();
        result.path = bad(b"/tmp/r\xff");
        let scan = TargetScan {
            root: bad(b"/tmp/root\xff"),
            kind: TargetKind::Bundle,
            primary: Some(bad(b"/tmp/root\xff/p\xfe")),
            skipped: vec![bad(b"/tmp/s\xfe")],
            unreadable: vec![bad(b"/tmp/u\xff\xfe")],
            results: vec![result],
            budget: nav_core::BudgetOutcome::Within,
        };
        let text = serde_json::to_string_pretty(&multi_json(&scan).expect("serializes")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["target"], "/tmp/root\u{FFFD}");
        assert_eq!(v["primary"], "/tmp/root\u{FFFD}/p\u{FFFD}");
        assert_eq!(
            v["skipped_resources"],
            serde_json::json!(["/tmp/s\u{FFFD}"])
        );
        assert_eq!(
            v["unreadable"],
            serde_json::json!(["/tmp/u\u{FFFD}\u{FFFD}"])
        );
        assert_eq!(v["results"][0]["path"], "/tmp/r\u{FFFD}");
    }

    fn member(path: &str, score: i32, completeness: ScanCompleteness) -> ScanResult {
        let mut r = sample_result();
        r.path = PathBuf::from(path);
        r.score = score;
        r.completeness = completeness;
        if score >= 40 {
            r.recommendation = Recommendation::Notify;
        }
        r
    }

    fn bundle(results: Vec<ScanResult>, budget: BudgetOutcome) -> TargetScan {
        TargetScan {
            root: PathBuf::from("/Apps/X.app"),
            kind: TargetKind::Bundle,
            primary: Some(PathBuf::from("/Apps/X.app/Contents/MacOS/X")),
            skipped: Vec::new(),
            unreadable: Vec::new(),
            results,
            budget,
        }
    }

    const MAIN: &str = "/Apps/X.app/Contents/MacOS/X";
    const EVIL: &str = "/Apps/X.app/Contents/Resources/evil.sh";

    #[test]
    fn no_action_is_clean_only_when_complete() {
        let label = |c| recommendation_str(Recommendation::NoAction, c);
        assert_eq!(label(ScanCompleteness::Complete), "no action (clean)");
        for c in [ScanCompleteness::Partial, ScanCompleteness::Indeterminate] {
            assert_eq!(label(c), "no action (not fully checked)");
        }
        assert_eq!(
            recommendation_str(Recommendation::Notify, ScanCompleteness::Partial),
            "notify"
        );
    }

    #[test]
    fn partial_and_indeterminate_summary_lines_are_not_clean() {
        for c in [ScanCompleteness::Partial, ScanCompleteness::Indeterminate] {
            let line = summary_line(
                "/tmp/x",
                0,
                EvidenceConfidence::Low,
                c,
                Recommendation::NoAction,
            );
            assert!(line.ends_with("-> no action (not fully checked)"), "{line}");
            assert!(!line.contains("(clean)"), "{line}");
        }
    }

    #[test]
    fn bundle_line_with_incomplete_coverage_is_not_clean() {
        let scan = bundle(
            vec![member(MAIN, 0, ScanCompleteness::Complete)],
            BudgetOutcome::Exhausted(BudgetLimit::Files),
        );
        let line = bundle_summary_line(&scan);
        assert!(line.contains("not fully checked"), "{line}");
        assert!(!line.contains("(clean)"), "{line}");
        assert_eq!(target_completeness(&scan), ScanCompleteness::Partial);
        assert_eq!(
            recommendation_str(scan.recommendation(), target_completeness(&scan)),
            "no action (not fully checked)"
        );
    }

    #[test]
    fn bundle_line_clean_and_complete_has_no_worst() {
        let scan = bundle(
            vec![
                member(MAIN, 0, ScanCompleteness::Complete),
                member(EVIL, 0, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&scan);
        assert!(line.starts_with("/Apps/X.app  score="), "{line}");
        assert!(line.ends_with("(bundle: 2 files)"), "{line}");
        assert!(line.contains("completeness=Complete"), "{line}");
        assert!(line.contains("no action (clean)"), "{line}");
        assert!(!line.contains("worst:"), "{line}");
    }

    #[test]
    fn bundle_line_names_the_worst_file() {
        let scan = bundle(
            vec![
                member(MAIN, 0, ScanCompleteness::Complete),
                member(EVIL, 40, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&scan);
        assert!(line.contains("score=40"), "{line}");
        assert!(line.contains("-> notify"), "{line}");
        assert!(
            line.ends_with("worst: Contents/Resources/evil.sh)"),
            "{line}"
        );
    }

    #[test]
    fn bundle_line_marks_the_main_executable() {
        let scan = bundle(
            vec![
                member(MAIN, 40, ScanCompleteness::Complete),
                member(EVIL, 0, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Within,
        );
        assert!(
            bundle_summary_line(&scan).contains("worst: Contents/MacOS/X*)"),
            "{}",
            bundle_summary_line(&scan)
        );
    }

    #[test]
    fn bundle_line_reports_a_clean_partial_member() {
        let scan = bundle(
            vec![
                member(MAIN, 0, ScanCompleteness::Complete),
                member(EVIL, 0, ScanCompleteness::Partial),
            ],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&scan);
        assert!(line.contains("completeness=Partial"), "{line}");
        assert!(line.contains("worst: Contents/Resources/evil.sh"), "{line}");
    }

    #[test]
    fn bundle_line_is_partial_when_the_budget_cut_the_scan_short() {
        let scan = bundle(
            vec![
                member(MAIN, 0, ScanCompleteness::Complete),
                member(EVIL, 0, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Exhausted(BudgetLimit::Files),
        );
        let line = bundle_summary_line(&scan);
        assert!(line.contains("completeness=Partial"), "{line}");
        assert!(!line.contains("completeness=Complete"), "{line}");
        assert!(!line.contains("worst:"), "{line}");
    }

    #[test]
    fn bundle_line_with_negative_scores_has_no_worst() {
        let scan = bundle(
            vec![
                member(MAIN, -3, ScanCompleteness::Complete),
                member(EVIL, 0, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&scan);
        assert!(line.ends_with("(bundle: 2 files)"), "{line}");
        assert!(!line.contains("worst:"), "{line}");

        let single = bundle(
            vec![member(MAIN, -3, ScanCompleteness::Complete)],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&single);
        assert!(line.contains("score=-3"), "{line}");
        assert!(!line.contains("worst:"), "{line}");
    }

    #[test]
    fn bundle_line_names_a_low_nonzero_score() {
        let scan = bundle(
            vec![
                member(MAIN, 0, ScanCompleteness::Complete),
                member(EVIL, 3, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&scan);
        assert!(line.contains("worst: Contents/Resources/evil.sh"), "{line}");
    }

    /// Guards the per-file format against drift.
    #[test]
    fn summary_line_matches_the_per_file_format() {
        let r = sample_result();
        assert_eq!(
            summary_line(
                &r.path.display().to_string(),
                r.score,
                r.confidence,
                r.completeness,
                r.recommendation
            ),
            "/tmp/sample  score=0    confidence=Low    completeness=Complete      -> no action (clean)"
        );
    }
}
