//! `benign vm survey` and `benign vm compare`: run the survey set in a
//! throwaway clone of the golden Tart VM, from the host (§11.1b). Only
//! commits go in; only UTF-8 text results come back.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use clap::{Args, Subcommand};

use super::manifest::Manifest;
use crate::build::{git, resolve_dirs};
use crate::vm::{
    check_tart, copy_in, make_bundle, map_exit, resolve_sha, tart, vm_name, wait_for_agent,
    warn_stale_vms, TempFile, VmGuard,
};

const VM_PREFIX: &str = "nav-benign-run-";
const REF_NS: &str = "xtask-benign-vm";
/// Largest survey output accepted from the guest.
const MAX_OUTPUT: u64 = 16 << 20;
/// Largest compare result file accepted; JSONL over the large items is big.
const MAX_RESULT: u64 = 256 << 20;

#[derive(Subcommand)]
pub enum VmCommand {
    /// Prepare the set in a clone of the golden VM and run a script over it (host side).
    Survey(SurveyArgs),
    /// Fetch, then build base and new navctl and diff their scans of the set (host side).
    Compare(VmCompareArgs),
}

#[derive(Args)]
pub struct VmCompareArgs {
    /// Revision under test.
    #[arg(long, default_value = "HEAD")]
    branch: String,
    /// Base revision (`origin/*` is fetched first).
    #[arg(long, default_value = "origin/main")]
    base: String,
    /// Keep the cloned VM instead of deleting it.
    #[arg(long)]
    keep: bool,
    /// Golden Tart VM to clone.
    #[arg(long, default_value = "nav-bench-golden")]
    golden: String,
}

const RESULT_FILES: [&str; 3] = ["report.txt", "base.jsonl", "new.jsonl"];

/// Guest script for `compare`. Positionals: new commit, base commit, bundle
/// ref namespace. `fetch` exiting 2 does not stop the run: `compare` reports
/// every item it could not stage.
const COMPARE_SCRIPT: &str = r#"set -eu
if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
cd "$HOME"
new=$1; base=$2; ns=$3
rm -rf nav out
git init --quiet nav
cd nav
git fetch --quiet ../nav.bundle "refs/$ns/*:refs/$ns/*"
git checkout --quiet --detach "$new"
st=0
cargo xtask benign fetch || st=$?
case $st in 0|2) ;; *) exit 1 ;; esac
st=0
cargo xtask benign compare --base "$base" --out-dir "$HOME/out" || st=$?
exit $st
"#;

/// Positional args for [`COMPARE_SCRIPT`] after the `zsh` argv0.
fn compare_args(new: &str, base: &str) -> Vec<String> {
    vec![new.to_string(), base.to_string(), REF_NS.to_string()]
}

#[derive(Args)]
pub struct SurveyArgs {
    /// Survey script, run in the VM as `<script> ~/nav-benign [<malware store>]`.
    script: PathBuf,
    /// Also fetch the §11.1a malware store and pass its path as the second argument.
    #[arg(long)]
    with_malware: bool,
    /// Keep the cloned VM instead of deleting it.
    #[arg(long)]
    keep: bool,
    /// Golden Tart VM to clone.
    #[arg(long, default_value = "nav-bench-golden")]
    golden: String,
}

/// Guest script. Positionals: commit, bundle ref namespace, `yes`/`no`
/// (fetch the malware store). `fetch` and `prepare` exiting 2 (an item
/// missing) does not stop the run; the script's own status is the result.
const GUEST_SCRIPT: &str = r#"set -eu
if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
cd "$HOME"
sha=$1; ns=$2; with_malware=$3
rm -rf nav out
mkdir out
git init --quiet nav
cd nav
git fetch --quiet ../nav.bundle "refs/$ns/*:refs/$ns/*"
git checkout --quiet --detach "$sha"
st=0
cargo xtask benign fetch || st=$?
case $st in 0|2) ;; *) exit 1 ;; esac
st=0
cargo xtask benign prepare || st=$?
case $st in 0|2) ;; *) exit 1 ;; esac
store=
if [ "$with_malware" = yes ]; then
  st=0
  cargo xtask malware fetch || st=$?
  case $st in 0|2) ;; *) exit 1 ;; esac
  store="$HOME/nav/crates/nav-core/fixtures/real-world/store"
fi
chmod 700 "$HOME/survey-script"
cd "$HOME"
st=0
"$HOME/survey-script" "$HOME/nav-benign" ${store:+"$store"} > "$HOME/out/survey.txt" 2>&1 || st=$?
exit $st
"#;

/// Positional args for [`GUEST_SCRIPT`] after the `zsh` argv0.
fn guest_args(commit: &str, with_malware: bool) -> Vec<String> {
    vec![
        commit.to_string(),
        REF_NS.to_string(),
        if with_malware { "yes" } else { "no" }.to_string(),
    ]
}

/// Reads `r` to the end as UTF-8, failing if it holds more than `max` bytes
/// or is not valid UTF-8. Never reads more than `max + 1` bytes.
fn read_text(r: impl Read, max: u64) -> Result<String> {
    let mut buf = Vec::new();
    r.take(max + 1).read_to_end(&mut buf)?;
    ensure!(buf.len() as u64 <= max, "output exceeds {max} bytes");
    String::from_utf8(buf).context("output is not valid UTF-8")
}

/// A guest file that was too big or not UTF-8; nothing was written.
#[derive(Debug)]
struct Rejected(String);

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Rejected {}

/// Copies `$HOME/out/<file>` from the guest to `dest`, only if it passes
/// [`read_text`] with `max`; otherwise nothing is written and a rejection
/// is a [`Rejected`] error.
fn copy_text(name: &str, file: &str, dest: &Path, max: u64) -> Result<()> {
    let mut child = tart()
        .args([
            "exec",
            name,
            "/bin/sh",
            "-c",
            "cat \"$HOME/out/$1\"",
            "sh",
            file,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .context("spawning tart exec")?;
    let out = child.stdout.take().context("no stdout pipe")?;
    let text = read_text(out, max).map_err(|e| anyhow::Error::new(Rejected(format!("{e:#}"))));
    if text.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let text = text?;
    ensure!(
        status.success(),
        "reading {file} in the VM failed ({status})"
    );
    std::fs::write(dest, text).with_context(|| dest.display().to_string())
}

/// Fails if HEAD's manifest has an unrecorded url item: the survey VM would
/// have to download it, and recording happens in the golden image first.
fn check_recorded(repo: &Path) -> Result<()> {
    let spec = "HEAD:crates/nav-core/fixtures/real-world/benign.toml";
    let manifest = Manifest::parse(&git(repo, &["show", spec])?)?;
    let missing: Vec<&str> = manifest
        .items
        .iter()
        .filter(|i| !i.recorded())
        .map(|i| i.id.as_str())
        .collect();
    ensure!(
        missing.is_empty(),
        "unrecorded manifest items: {}; boot the golden image, run `cargo xtask benign fetch --record` there and commit the rewritten benign.toml",
        missing.join(", ")
    );
    Ok(())
}

pub fn run(cmd: VmCommand) -> Result<ExitCode> {
    match cmd {
        VmCommand::Survey(a) => survey(a),
        VmCommand::Compare(a) => compare(a),
    }
}

/// Rejects a golden VM name that `tart` would read as a flag.
fn check_golden(golden: &str) -> Result<()> {
    ensure!(
        !golden.starts_with('-'),
        "--golden {golden:?} looks like a flag"
    );
    Ok(())
}

/// Clones `golden` as `nav-benign-run-<secs>`, boots it headless (log in
/// `out_dir/tart-run.log`) and waits for the guest agent.
fn boot(golden: &str, secs: u64, keep: bool, out_dir: &Path) -> Result<VmGuard> {
    let name = vm_name(VM_PREFIX, secs);
    warn_stale_vms(VM_PREFIX, &name);
    let st = tart().args(["clone", golden, &name]).status()?;
    if !st.success() {
        bail!("`tart clone {golden} {name}` failed ({st})");
    }
    let mut guard = VmGuard {
        name: name.clone(),
        keep,
        child: None,
    };
    let log = File::create(out_dir.join("tart-run.log"))?;
    guard.child = Some(
        tart()
            .args(["run", "--no-graphics", &name])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .context("spawning tart run")?,
    );
    wait_for_agent(&mut guard)?;
    Ok(guard)
}

fn compare(a: VmCompareArgs) -> Result<ExitCode> {
    check_tart()?;
    check_golden(&a.golden)?;
    let repo = PathBuf::from(git(Path::new("."), &["rev-parse", "--show-toplevel"])?);
    if a.base.starts_with("origin/") {
        git(&repo, &["fetch", "origin"])?;
    }
    let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let new = resolve_sha(&repo, &a.branch)?;
    let base = resolve_sha(&repo, &a.base)?;
    println!("new: {} ({new})\nbase: {} ({base})", a.branch, a.base);
    let dirty = !git(&repo, &["status", "--porcelain"])?.is_empty();
    if dirty && new == resolve_sha(&repo, "HEAD")? {
        println!("note: working tree is dirty; uncommitted changes are NOT in the VM run");
    }
    let (_, out_dir) = resolve_dirs(&repo, None, REF_NS)?;
    let bundle = out_dir.join("src.bundle");
    let _bundle_file = TempFile(bundle.clone());
    make_bundle(&repo, REF_NS, &new, &base, &bundle, secs)?;

    let guard = boot(&a.golden, secs, a.keep, &out_dir)?;
    let name = guard.name.clone();
    copy_in(&name, &bundle, "nav.bundle")?;
    let status = tart()
        .args(["exec", &name, "/bin/zsh", "-c", COMPARE_SCRIPT, "zsh"])
        .args(compare_args(&new, &base))
        .status()
        .context("spawning tart exec")?;
    let mut rejected = false;
    for f in RESULT_FILES {
        if let Err(e) = copy_text(&name, f, &out_dir.join(f), MAX_RESULT) {
            eprintln!("warning: could not copy {f} out of the VM: {e:#}");
            rejected |= e.is::<Rejected>();
        }
    }
    println!("results: {}", out_dir.display());
    if rejected {
        eprintln!("error: a result file was not text or too large and was discarded");
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::from(map_exit(status.code())))
}

fn survey(a: SurveyArgs) -> Result<ExitCode> {
    check_tart()?;
    ensure!(a.script.is_file(), "{} is not a file", a.script.display());
    check_golden(&a.golden)?;
    let repo = PathBuf::from(git(Path::new("."), &["rev-parse", "--show-toplevel"])?);
    let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let commit = resolve_sha(&repo, "HEAD")?;
    check_recorded(&repo)?;
    println!("commit: HEAD ({commit})");
    if !git(&repo, &["status", "--porcelain"])?.is_empty() {
        println!("note: working tree is dirty; uncommitted changes are NOT in the VM run");
    }
    let (_, out_dir) = resolve_dirs(&repo, None, REF_NS)?;
    let bundle = out_dir.join("src.bundle");
    let _bundle_file = TempFile(bundle.clone());
    make_bundle(&repo, REF_NS, &commit, &commit, &bundle, secs)?;

    let guard = boot(&a.golden, secs, a.keep, &out_dir)?;
    let name = guard.name.clone();
    copy_in(&name, &bundle, "nav.bundle")?;
    copy_in(&name, &a.script, "survey-script")?;
    let status = tart()
        .args(["exec", &name, "/bin/zsh", "-c", GUEST_SCRIPT, "zsh"])
        .args(guest_args(&commit, a.with_malware))
        .status()
        .context("spawning tart exec")?;
    let dest = out_dir.join("survey.txt");
    let guest = map_exit(status.code());
    match copy_text(&name, "survey.txt", &dest, MAX_OUTPUT) {
        Ok(()) => {
            println!("results: {}", dest.display());
            Ok(ExitCode::from(guest))
        }
        Err(e) => {
            eprintln!("error: survey output discarded; nothing was copied out of the VM: {e:#}");
            if guest != 0 {
                eprintln!("error: the guest run itself exited with status {guest}");
            }
            Ok(ExitCode::from(1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_flag_rejected() {
        assert!(check_golden("nav-bench-golden").is_ok());
        assert!(check_golden("--help").is_err());
    }

    #[test]
    fn guest_args_are_fixed() {
        let v = guest_args(&"a".repeat(40), true);
        assert_eq!(v, ["a".repeat(40), REF_NS.to_string(), "yes".to_string()]);
        assert_eq!(guest_args("c", false)[2], "no");
        // User input (script path, golden name) never reaches the guest argv or script text.
        assert!(!GUEST_SCRIPT.contains("xtask-benign-vm"));
    }

    #[test]
    fn compare_args_are_fixed() {
        let (n, b) = ("n".repeat(40), "b".repeat(40));
        assert_eq!(compare_args(&n, &b), [n, b, REF_NS.to_string()]);
        assert!(!COMPARE_SCRIPT.contains(REF_NS));
    }

    #[test]
    fn reads_small_utf8() {
        assert_eq!(read_text(&b"hello\n"[..], 16).unwrap(), "hello\n");
        assert_eq!(read_text(&b"0123456789abcdef"[..], 16).unwrap().len(), 16);
    }

    #[test]
    fn rejects_oversize() {
        let e = read_text(&b"0123456789abcdefg"[..], 16).unwrap_err();
        assert!(e.to_string().contains("exceeds"), "{e}");
    }

    #[test]
    fn rejects_non_utf8() {
        let e = read_text(&b"ok\xff\xfe"[..], 16).unwrap_err();
        assert!(e.to_string().contains("UTF-8"), "{e:#}");
    }

    #[test]
    fn caps_bytes_read() {
        struct Endless(u64);
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0 += buf.len() as u64;
                buf.fill(b'a');
                Ok(buf.len())
            }
        }
        let mut r = Endless(0);
        assert!(read_text(&mut r, 100).is_err());
        assert!(r.0 <= 101 + 8192, "read {}", r.0);
    }
}
