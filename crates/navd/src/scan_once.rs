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

use nav_core::{scan_result_json, scan_target, BudgetOutcome, ScanResult};

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
        eprintln!("navd scan-once: no files found under {}", path.display());
        return nav_core::exit_code(nav_core::OPERATIONAL_ERROR);
    }

    for result in &scan.results {
        if json {
            println!("{}", scan_result_json(result));
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

    nav_core::exit_code(nav_core::for_target(&scan))
}

/// Terse one-line-per-file human summary. The verdict content is secondary
/// here — `completeness` is the load-bearing field B3 measures (§5.5,
/// §10, §11.8): a TCC-blocked read must surface as `Indeterminate`, never
/// as a clean scan.
fn print_summary(result: &ScanResult) {
    println!(
        "{}  score={} completeness={:?} -> {:?}",
        result.path.display(),
        result.score,
        result.completeness,
        result.recommendation,
    );
}
