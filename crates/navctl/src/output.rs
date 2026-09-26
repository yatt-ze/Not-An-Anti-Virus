//! Human and `--json` rendering for `scan` / `rules test` / `rules list`.
//!
//! `--json` mirrors the human structure — both render the same
//! `nav_core::ScanResult` (§5.5), plus a top-level `schema_version` marking
//! the JSON as a versioned contract (§8), via the shared envelope in
//! `nav_core::presentation`.
//! `scan` prints one terse line per file;
//! `rules test` prints the worst file's full breakdown plus a roll-up.

use std::path::Path;
use std::process::ExitCode;

use nav_core::{
    scan_target, with_schema_version, BudgetLimit, BudgetOutcome, EvidenceConfidence,
    Recommendation, ScanCompleteness, ScanResult, TargetKind, TargetScan, SCAN_JSON_SCHEMA_VERSION,
};

use crate::exit;

pub fn run_scan(path: &Path, recursive: bool, json: bool) -> ExitCode {
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

    for result in &scan.results {
        if json {
            println!("{}", with_schema_version(result));
        } else {
            print_scan_summary(result);
        }
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
            println!(
                "{}",
                serde_json::to_string_pretty(&with_schema_version(result)).unwrap()
            );
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
                println!(
                    "{}",
                    serde_json::to_string_pretty(&multi_json(&scan)).unwrap()
                );
                return exit::code(exit::INDETERMINATE);
            }
        }
        eprintln!("navctl: no files to scan under {}", path.display());
        return exit::code(exit::INDETERMINATE);
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&multi_json(&scan)).unwrap()
        );
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
        "{}  score={:<4} confidence={:<6} completeness={:<13} -> {}",
        result.path.display(),
        result.score,
        confidence_str(result.confidence),
        completeness_str(result.completeness),
        recommendation_str(result.recommendation),
    );
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
        recommendation_str(result.recommendation)
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
            recommendation_str(result.recommendation),
        );
    }
    if scan.primary.is_some() {
        println!("  (* = bundle main executable)");
    }
    println!();
    println!(
        "Recommendation: {}",
        recommendation_str(scan.recommendation())
    );
}

fn multi_json(scan: &TargetScan) -> serde_json::Value {
    let kind = match scan.kind {
        TargetKind::Bundle => "bundle",
        _ => "directory",
    };
    serde_json::json!({
        "schema_version": SCAN_JSON_SCHEMA_VERSION,
        "target": scan.root,
        "kind": kind,
        "primary": scan.primary,
        "skipped_resources": scan.skipped,
        "coverage_complete": scan.coverage_complete(),
        "budget_limit": budget_limit_str(scan),
        "unreadable": scan.unreadable,
        "recommendation": scan.recommendation(),
        "results": scan.results,
    })
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

fn recommendation_str(r: Recommendation) -> &'static str {
    match r {
        Recommendation::NoAction => "no action (clean)",
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
    fn with_schema_version_adds_field_alongside_existing_ones() {
        let value = with_schema_version(&sample_result());
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
        let value = multi_json(&scan);
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
        let value = multi_json(&scan);
        assert_eq!(value["results"], serde_json::json!([]));
        assert_eq!(value["coverage_complete"], false);
        assert_eq!(value["unreadable"], serde_json::json!(["/tmp/locked"]));
    }
}
