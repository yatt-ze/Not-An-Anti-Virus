//! `corpus compare`: build base and new navctl, scan the corpus with each,
//! diff.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};

use super::{diff, parse, scan, CompareArgs};
use crate::build::{build_pair, git, resolve_dirs, PairSpec};

pub fn run(args: CompareArgs) -> Result<ExitCode> {
    let repo = PathBuf::from(git(Path::new("."), &["rev-parse", "--show-toplevel"])?);
    let (target_dir, out_dir) = resolve_dirs(&repo, args.out_dir.as_deref(), "xtask-corpus")?;
    let (navctl_base, navctl_new) = build_pair(&PairSpec {
        repo: &repo,
        base_rev: &args.base,
        out_dir: &out_dir,
        new_target: &target_dir,
        base_target: &repo.join("target/xtask-corpus/base-target"),
        stale_root: &repo.join("target/xtask-corpus"),
    })?;
    let base_jsonl = out_dir.join("base.jsonl");
    let new_jsonl = out_dir.join("new.jsonl");
    let planned = scan::plan_roots(&args.tuning)?;
    let targets = [
        scan::Target {
            navctl: &navctl_base,
            out: &base_jsonl,
        },
        scan::Target {
            navctl: &navctl_new,
            out: &new_jsonl,
        },
    ];
    scan::run(&targets, &planned, args.tuning.jobs)?;

    let report = diff::diff(&parse::load(&base_jsonl)?, &parse::load(&new_jsonl)?);
    let text = diff::render(&report, false);
    let report_path = out_dir.join("diff.txt");
    std::fs::write(&report_path, &text).with_context(|| report_path.display().to_string())?;
    println!("\n{text}");
    println!("report: {}", report_path.display());
    Ok(report.exit_code())
}
