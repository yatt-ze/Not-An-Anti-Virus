//! Human and `--json` rendering for `scan` / `rules test` / `rules list`.
//!
//! `--json` mirrors the human structure — both render the same
//! `nav_core::ScanResult` (§5.5). `scan` prints one terse line per file;
//! `rules test` prints the worst file's full breakdown plus a roll-up.

use std::path::Path;
use std::process::ExitCode;

use nav_core::{
    scan_target, EvidenceConfidence, Recommendation, ScanCompleteness, ScanResult, TargetKind,
    TargetScan,
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
        eprintln!("navctl: no files found under {}", path.display());
        return exit::code(exit::OPERATIONAL_ERROR);
    }

    let mut worst = exit::CLEAN;
    for result in &scan.results {
        if json {
            println!("{}", serde_json::to_string(result).unwrap());
        } else {
            print_scan_summary(result);
        }
        worst = worst.max(exit::for_result(result));
    }
    exit::code(worst)
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
            println!("{}", serde_json::to_string_pretty(result).unwrap());
        } else {
            print_rules_test(result);
        }
        return exit::code(exit::for_result(result));
    }

    if scan.results.is_empty() {
        // Nothing readable — "couldn't check", not "clean" (§10, §11.8).
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

    scan.results
        .iter()
        .map(exit::for_result)
        .max()
        .map(exit::code)
        .unwrap()
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
        "target": scan.root,
        "kind": kind,
        "primary": scan.primary,
        "skipped_resources": scan.skipped,
        "recommendation": scan.recommendation(),
        "results": scan.results,
    })
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
