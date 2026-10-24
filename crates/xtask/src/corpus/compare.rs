//! `corpus compare`: build base and new navctl, scan the corpus with each,
//! diff.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use super::{diff, parse, scan, CompareArgs};

/// Removes a detached git worktree on drop, including on error paths.
struct Worktree<'a> {
    repo: &'a Path,
    dir: PathBuf,
}

impl Drop for Worktree<'_> {
    fn drop(&mut self) {
        let status = Command::new("git")
            .current_dir(self.repo)
            .args(["worktree", "remove", "--force"])
            .arg(&self.dir)
            .status();
        if !matches!(status, Ok(s) if s.success()) {
            eprintln!("warning: could not remove worktree {}", self.dir.display());
        }
    }
}

/// Runs `cmd`, failing with its stderr on nonzero exit; returns trimmed stdout.
fn capture(cmd: &mut Command) -> Result<String> {
    let out = cmd.output().with_context(|| format!("spawning {cmd:?}"))?;
    if !out.status.success() {
        bail!(
            "{cmd:?} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    capture(Command::new("git").current_dir(repo).args(args))
}

/// Removes base worktrees an interrupted run (Ctrl-C skips `Drop`) left
/// under `<repo>/target/xtask-corpus/`, then prunes stale registrations.
fn remove_stale_worktrees(repo: &Path) -> Result<()> {
    let ours = repo.join("target/xtask-corpus");
    let list = git(repo, &["worktree", "list", "--porcelain"])?;
    for path in list.lines().filter_map(|l| l.strip_prefix("worktree ")) {
        if Path::new(path).starts_with(&ours) {
            println!("note: removing stale worktree {path}");
            git(repo, &["worktree", "remove", "--force", path])?;
        }
    }
    git(repo, &["worktree", "prune"])?;
    Ok(())
}

/// `cargo build --release --locked -p navctl` in `dir` with `target_dir`;
/// returns the built binary's path.
fn build_navctl(dir: &Path, target_dir: &Path) -> Result<PathBuf> {
    let status = Command::new("cargo")
        .current_dir(dir)
        .env("CARGO_TARGET_DIR", target_dir)
        .args(["build", "--release", "--locked", "-p", "navctl"])
        .status()
        .context("spawning cargo")?;
    if !status.success() {
        bail!("cargo build failed in {}", dir.display());
    }
    Ok(target_dir.join("release/navctl"))
}

pub fn run(args: CompareArgs) -> Result<ExitCode> {
    let repo = PathBuf::from(git(Path::new("."), &["rev-parse", "--show-toplevel"])?);
    let target_dir = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(t) => super::absolute(Path::new(&t))?,
        None => repo.join("target"),
    };
    let out_dir = match &args.out_dir {
        Some(d) => super::absolute(d)?,
        None => {
            let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            repo.join(format!("target/xtask-corpus/{secs}"))
        }
    };
    std::fs::create_dir_all(&out_dir).with_context(|| out_dir.display().to_string())?;

    if !git(&repo, &["status", "--porcelain"])?.is_empty() {
        println!("note: working tree is dirty; the new build includes uncommitted changes");
    }
    let new_rev = git(&repo, &["rev-parse", "--short", "HEAD"])?;
    println!("new: HEAD {new_rev} (working tree)");
    let built = build_navctl(&repo, &target_dir)?;
    let navctl_new = out_dir.join("navctl-new");
    std::fs::copy(&built, &navctl_new).context("copying new navctl")?;

    remove_stale_worktrees(&repo)?;
    if args.base.starts_with("origin/") {
        git(&repo, &["fetch", "origin"])?;
    }
    let base_rev = git(&repo, &["rev-parse", "--short", &args.base])?;
    println!("base: {} ({base_rev})", args.base);
    let navctl_base = out_dir.join("navctl-base");
    {
        let wt = Worktree {
            repo: &repo,
            dir: out_dir.join("base-src"),
        };
        git(
            &repo,
            &[
                "worktree",
                "add",
                "--detach",
                &wt.dir.to_string_lossy(),
                &args.base,
            ],
        )?;
        let built = build_navctl(&wt.dir, &repo.join("target/xtask-corpus/base-target"))?;
        std::fs::copy(&built, &navctl_base).context("copying base navctl")?;
    }

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
