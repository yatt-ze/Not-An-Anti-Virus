//! `navd scan-once` — a one-shot self-scan used by the Phase 0b B3 spike
//! (§12) to compare `navd`'s headless/root file-read behaviour against
//! `navctl rules test` run interactively. Reuses `nav_core::scan_target`
//! directly — no second scoring/verdict logic lives here.
//!
//! **Temporary scaffolding, not committed CLI surface.** On-demand scanning
//! is and stays `navctl`'s job, in-process against `nav-core` (§9.1); this
//! subcommand exists only to run the B3 spike and is removed once B3 is
//! answered (tracked in the phase-0b plan).

use std::path::Path;
use std::process::ExitCode;

use nav_core::{
    scan_result_json, scan_target, BudgetOutcome, EvidenceConfidence, Recommendation,
    ScanCompleteness, ScanResult, TargetScan,
};

/// Scans `path` once and prints the verdict, human or `--json`, exiting with
/// the shared §8 taxonomy. Never starts the daemon loop or its signal
/// handlers — a separate, short-lived invocation of the same binary.
pub fn run(path: &Path, recursive: bool, json: bool) -> ExitCode {
    let scan = match scan_target(path, recursive) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("navd scan-once: {}: {e}", path.display());
            return nav_core::exit_code(nav_core::OPERATIONAL_ERROR);
        }
    };

    if scan.results.is_empty() {
        // Nothing readable, not a tool failure — matches `navctl rules
        // test`'s empty-target code, the baseline B3 compares against.
        if let Some(note) = unreadable_note(&scan) {
            eprintln!("{note}");
        }
        eprintln!("navd scan-once: no files found under {}", path.display());
        return nav_core::exit_code(nav_core::INDETERMINATE);
    }

    for result in &scan.results {
        if json {
            match scan_result_json(result) {
                Ok(line) => println!("{line}"),
                Err(e) => {
                    eprintln!("navd scan-once: cannot serialize result: {e}");
                    return nav_core::exit_code(nav_core::OPERATIONAL_ERROR);
                }
            }
        } else {
            print_summary(result);
        }
    }

    if let BudgetOutcome::Exhausted(_) = scan.budget {
        eprintln!(
            "navd scan-once: partial coverage — scan budget reached; more of {} was not scanned",
            path.display()
        );
    }
    if let Some(note) = unreadable_note(&scan) {
        eprintln!("{note}");
    }

    nav_core::exit_code(nav_core::for_target(&scan))
}

/// A stderr warning naming directories that couldn't be read during
/// traversal, or `None` when there were none — shared by the empty-target
/// and normal-exit paths above (§11.12/#32).
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
        "navd scan-once: partial coverage — {} director(ies) could not be read under {}: {}",
        scan.unreadable.len(),
        scan.root.display(),
        paths
    ))
}

/// Terse one-line-per-file human summary (§5.5).
fn print_summary(result: &ScanResult) {
    println!(
        "{}  score={} confidence={} completeness={} -> {}",
        result.path.display(),
        result.score,
        confidence_str(result.confidence),
        completeness_str(result.completeness),
        recommendation_str(result.recommendation),
    );
}

// Local, deliberately not shared with nav-core or navctl: this whole module
// is a throwaway spike instrument (see the module doc comment), and these
// just mirror navctl/src/output.rs's spellings so an operator sees identical
// tokens from either binary.

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
