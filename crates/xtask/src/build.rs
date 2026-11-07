//! Git worktree and `cargo build` helpers shared by the `corpus` and
//! `malware` compare commands.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

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

pub fn git(repo: &Path, args: &[&str]) -> Result<String> {
    capture(Command::new("git").current_dir(repo).args(args))
}

/// Removes worktrees an interrupted run (Ctrl-C skips `Drop`) left under
/// `ours`, then prunes stale registrations.
fn remove_stale_worktrees(repo: &Path, ours: &Path) -> Result<()> {
    let list = git(repo, &["worktree", "list", "--porcelain"])?;
    for path in list.lines().filter_map(|l| l.strip_prefix("worktree ")) {
        if Path::new(path).starts_with(ours) {
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

/// Where a compare run builds and writes: the cargo target dir and the
/// output dir (default `<repo>/target/<default_sub>/<unix-seconds>`).
pub fn resolve_dirs(
    repo: &Path,
    out_dir: Option<&Path>,
    default_sub: &str,
) -> Result<(PathBuf, PathBuf)> {
    let target_dir = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(t) => crate::corpus::absolute(Path::new(&t))?,
        None => repo.join("target"),
    };
    let out_dir = match out_dir {
        Some(d) => crate::corpus::absolute(d)?,
        None => {
            let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            repo.join(format!("target/{default_sub}/{secs}"))
        }
    };
    std::fs::create_dir_all(&out_dir).with_context(|| out_dir.display().to_string())?;
    Ok((target_dir, out_dir))
}

/// Inputs to [`build_pair`].
pub struct PairSpec<'a> {
    pub repo: &'a Path,
    /// Git revision of the base build.
    pub base_rev: &'a str,
    /// Receives `navctl-new`, `navctl-base` and the temporary `base-src`.
    pub out_dir: &'a Path,
    pub new_target: &'a Path,
    pub base_target: &'a Path,
    /// Worktrees left under here (or under `out_dir`) by an interrupted run
    /// are removed first.
    pub stale_root: &'a Path,
}

/// Builds navctl from the working tree, then from a detached worktree of
/// `base_rev`, copying each binary into `out_dir` right after its build.
/// Returns `(base, new)` binary paths.
pub fn build_pair(spec: &PairSpec) -> Result<(PathBuf, PathBuf)> {
    let repo = spec.repo;
    if !git(repo, &["status", "--porcelain"])?.is_empty() {
        println!("note: working tree is dirty; the new build includes uncommitted changes");
    }
    let new_rev = git(repo, &["rev-parse", "--short", "HEAD"])?;
    println!("new: HEAD {new_rev} (working tree)");
    let navctl_new = spec.out_dir.join("navctl-new");
    let built = build_navctl(repo, spec.new_target)?;
    std::fs::copy(&built, &navctl_new).context("copying new navctl")?;

    remove_stale_worktrees(repo, spec.stale_root)?;
    remove_stale_worktrees(repo, spec.out_dir)?;
    if spec.base_rev.starts_with("origin/") {
        git(repo, &["fetch", "origin"])?;
    }
    let base_rev = git(repo, &["rev-parse", "--short", spec.base_rev])?;
    println!("base: {} ({base_rev})", spec.base_rev);
    let navctl_base = spec.out_dir.join("navctl-base");
    let wt = Worktree {
        repo,
        dir: spec.out_dir.join("base-src"),
    };
    git(
        repo,
        &[
            "worktree",
            "add",
            "--detach",
            &wt.dir.to_string_lossy(),
            spec.base_rev,
        ],
    )?;
    let built = build_navctl(&wt.dir, spec.base_target)?;
    std::fs::copy(&built, &navctl_base).context("copying base navctl")?;
    Ok((navctl_base, navctl_new))
}
