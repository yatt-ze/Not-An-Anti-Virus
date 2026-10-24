//! `cargo xtask corpus`: scan a large set of real files with navctl builds
//! and diff the verdicts, as the benign false-positive regression gate.
//! Exit status: 0 gate passed, 2 gate failed (see `diff`), 1 tool error.

mod compare;
mod diff;
mod parse;
mod plan;
mod scan;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum CorpusCommand {
    /// Scan roots with one navctl build into a JSONL file.
    Scan(ScanArgs),
    /// Diff two JSONL scans; exit 2 on a regression, a missing file or an empty base.
    Diff(DiffArgs),
    /// Build base and new navctl, scan both, diff.
    Compare(CompareArgs),
}

/// Options shared by every command that runs scans.
#[derive(Args, Clone)]
pub struct Tuning {
    /// Worker threads (default: available parallelism).
    #[arg(long)]
    pub jobs: Option<usize>,
    /// Directories with this many files or more are split into children
    /// (navctl's walk stops at 50,000 files).
    #[arg(long, default_value_t = 45_000)]
    pub split_at: usize,
    /// Files or directories to scan (default on macOS: system and app dirs).
    pub roots: Vec<PathBuf>,
}

#[derive(Args)]
pub struct ScanArgs {
    /// navctl binary to run.
    #[arg(long)]
    navctl: PathBuf,
    /// Output JSONL path; per-chunk errors go to `<out>.err`.
    #[arg(long)]
    out: PathBuf,
    #[command(flatten)]
    tuning: Tuning,
}

#[derive(Args)]
pub struct DiffArgs {
    /// Base JSONL; its `<base>.err` (if any) names budget-stopped targets.
    base: PathBuf,
    /// New JSONL; likewise `<new>.err`.
    new: PathBuf,
    /// Print every changed file instead of the first 200.
    #[arg(long)]
    all: bool,
}

#[derive(Args)]
pub struct CompareArgs {
    /// Git revision of the base build.
    #[arg(long, default_value = "origin/main")]
    base: String,
    /// Output directory (default: target/xtask-corpus/<unix-seconds>).
    #[arg(long)]
    out_dir: Option<PathBuf>,
    #[command(flatten)]
    tuning: Tuning,
}

pub fn run(cmd: CorpusCommand) -> Result<ExitCode> {
    match cmd {
        CorpusCommand::Scan(a) => {
            let planned = scan::plan_roots(&a.tuning)?;
            let target = scan::Target {
                navctl: &a.navctl,
                out: &a.out,
            };
            scan::run(&[target], &planned, a.tuning.jobs)?;
            Ok(ExitCode::SUCCESS)
        }
        CorpusCommand::Diff(a) => {
            let base = parse::load(&a.base)?;
            let new = parse::load(&a.new)?;
            let mut report = diff::diff(&base, &new);
            let stopped = stopped_in_both(&a.base, &a.new)?;
            diff::excuse_budget_cutoffs(&mut report, &base, &stopped);
            print!("{}", diff::render(&report, a.all));
            Ok(report.exit_code())
        }
        CorpusCommand::Compare(a) => compare::run(a),
    }
}

/// Targets the walk budget stopped in both scans, from their `.err` files.
pub fn stopped_in_both(base: &std::path::Path, new: &std::path::Path) -> Result<BTreeSet<PathBuf>> {
    let b = parse::load_budget_stopped(base)?;
    let n = parse::load_budget_stopped(new)?;
    Ok(b.intersection(&n).cloned().collect())
}

/// `path` joined onto the current directory if relative (no symlink
/// resolution, no existence check).
pub fn absolute(path: &std::path::Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("reading current directory")?
        .join(path))
}
