//! Tart VM plumbing shared by the host-side VM runners (§11.1a, §11.1b):
//! throwaway-clone lifecycle, guest file copy, and commit bundles.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::build::git;

const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const AGENT_TIMEOUT: Duration = Duration::from_secs(180);

/// Refuses to run outside a VM so fetched bytes never touch the host; `section`
/// is the design section cited in the error.
pub fn ensure_vm(section: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>();
        // SAFETY: the name is NUL-terminated and `val`/`len` describe a valid
        // c_int buffer.
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.hv_vmm_present".as_ptr(),
                (&mut val as *mut libc::c_int).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || val != 1 {
            bail!(
                "this command only runs inside the macOS benchmark VM (kern.hv_vmm_present != 1), {section}"
            );
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    bail!("this command only runs inside the macOS benchmark VM, {section}")
}

/// Accepts exactly 40 lowercase hex digits.
pub fn validate_sha(s: &str) -> Result<()> {
    if s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        bail!("not a full 40-hex commit id: {s:?}")
    }
}

/// `<prefix><secs>`; `prefix` also drives the stale-VM check.
pub fn vm_name(prefix: &str, secs: u64) -> String {
    format!("{prefix}{secs}")
}

/// Names from `tart list --quiet` output that start with `prefix` and aren't `own`.
fn stale_vms(list: &str, prefix: &str, own: &str) -> Vec<String> {
    list.lines()
        .map(str::trim)
        .filter(|l| l.starts_with(prefix) && *l != own)
        .map(String::from)
        .collect()
}

/// Warns about leftover VMs named `<prefix>*` other than `own`.
pub fn warn_stale_vms(prefix: &str, own: &str) {
    match tart().args(["list", "--quiet"]).output() {
        Ok(o) if o.status.success() => {
            for old in stale_vms(&String::from_utf8_lossy(&o.stdout), prefix, own) {
                eprintln!(
                    "warning: VM {old} exists (leftover, or another run still going); if leftover: tart delete {old}"
                );
            }
        }
        _ => eprintln!("warning: could not list VMs; stale {prefix}* VMs not checked"),
    }
}

/// Guest exit status to host exit status: 0 and 2 pass through, else 1.
pub fn map_exit(code: Option<i32>) -> u8 {
    match code {
        Some(0) => 0,
        Some(2) => 2,
        _ => 1,
    }
}

pub fn tart() -> Command {
    Command::new("tart")
}

/// Per-run temporary bundle refs `(new, base)` under `refs/<ns>/<secs>/`.
fn bundle_refs(ns: &str, secs: u64) -> (String, String) {
    (
        format!("refs/{ns}/{secs}/new"),
        format!("refs/{ns}/{secs}/base"),
    )
}

/// Runs `cmd` with null stdio; true if it exits 0 within `limit` (killed after).
fn ok_within(cmd: &mut Command, limit: Duration) -> bool {
    let Ok(mut child) = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return st.success(),
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

fn tart_ok(args: &[&str]) -> bool {
    ok_within(tart().args(args), Duration::from_secs(120))
}

/// Resolves `rev` to a full commit id in `repo`.
pub fn resolve_sha(repo: &Path, rev: &str) -> Result<String> {
    let sha = git(
        repo,
        &["rev-parse", "--verify", &format!("{rev}^{{commit}}")],
    )?;
    validate_sha(&sha)?;
    Ok(sha)
}

/// Deletes the temporary bundle refs on drop.
struct BundleRefs<'a>(&'a Path, [String; 2]);

impl Drop for BundleRefs<'_> {
    fn drop(&mut self) {
        for r in &self.1 {
            if git(self.0, &["update-ref", "-d", r]).is_err() {
                eprintln!("warning: could not delete ref {r}");
            }
        }
    }
}

/// Writes a bundle holding both commits to `path`, using temporary refs under
/// `refs/<ns>/<secs>/`. The guest fetches `refs/<ns>/*`.
pub fn make_bundle(
    repo: &Path,
    ns: &str,
    new: &str,
    base: &str,
    path: &Path,
    secs: u64,
) -> Result<()> {
    let (ref_new, ref_base) = bundle_refs(ns, secs);
    let _refs = BundleRefs(repo, [ref_new.clone(), ref_base.clone()]);
    git(repo, &["update-ref", &ref_new, new])?;
    git(repo, &["update-ref", &ref_base, base])?;
    git(
        repo,
        &[
            "bundle",
            "create",
            &path.to_string_lossy(),
            &ref_new,
            &ref_base,
        ],
    )?;
    Ok(())
}

/// Removes a file on drop.
pub struct TempFile(pub PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Stops and (unless `keep`) deletes the VM on drop.
pub struct VmGuard {
    pub name: String,
    pub keep: bool,
    pub child: Option<Child>,
}

impl Drop for VmGuard {
    fn drop(&mut self) {
        if !tart_ok(&["stop", &self.name]) {
            eprintln!("warning: `tart stop {}` failed", self.name);
        }
        if let Some(c) = &mut self.child {
            let _ = c.kill();
            let _ = c.wait();
        }
        if self.keep {
            println!(
                "kept VM {}; remove it with: tart delete {}",
                self.name, self.name
            );
            return;
        }
        if !tart_ok(&["delete", &self.name]) {
            eprintln!(
                "warning: could not delete VM {}; run: tart delete {}",
                self.name, self.name
            );
        }
    }
}

/// Polls `tart exec` until the guest agent answers; fails if `tart run` exits.
pub fn wait_for_agent(g: &mut VmGuard) -> Result<()> {
    let start = Instant::now();
    loop {
        let left = AGENT_TIMEOUT.saturating_sub(start.elapsed());
        let limit = PROBE_TIMEOUT.min(left.max(Duration::from_secs(1)));
        if ok_within(tart().args(["exec", &g.name, "/usr/bin/true"]), limit) {
            return Ok(());
        }
        if let Some(c) = &mut g.child {
            if let Some(st) = c.try_wait()? {
                bail!("`tart run` exited early ({st}); see tart-run.log");
            }
        }
        if start.elapsed() > AGENT_TIMEOUT {
            bail!("guest agent not ready after {}s", AGENT_TIMEOUT.as_secs());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Streams `src` into `dest` (a path under the guest's `$HOME`).
pub fn copy_in(name: &str, src: &Path, dest: &str) -> Result<()> {
    let file = File::open(src).with_context(|| src.display().to_string())?;
    let st = tart()
        .args([
            "exec",
            "-i",
            name,
            "/bin/sh",
            "-c",
            "cat > \"$HOME/$1\"",
            "sh",
            dest,
        ])
        .stdin(file)
        .status()
        .context("spawning tart exec")?;
    if !st.success() {
        bail!("copying {} into the VM failed ({st})", src.display());
    }
    Ok(())
}

/// Copies one result file out of the guest's `$HOME/out/`; a failure is only a warning.
pub fn copy_out(name: &str, file: &str, out_dir: &Path) {
    let res = (|| -> Result<()> {
        let dest = File::create(out_dir.join(file))?;
        let st = tart()
            .args([
                "exec",
                name,
                "/bin/sh",
                "-c",
                "cat \"$HOME/out/$1\"",
                "sh",
                file,
            ])
            .stdout(dest)
            .status()?;
        if !st.success() {
            bail!("{st}");
        }
        Ok(())
    })();
    if let Err(e) = res {
        eprintln!("warning: could not copy {file} out of the VM: {e}");
        let _ = std::fs::remove_file(out_dir.join(file));
    }
}

/// Fails unless `tart` is installed and answers `--version`.
pub fn check_tart() -> Result<()> {
    match tart_ok(&["--version"]) {
        true => Ok(()),
        false => bail!("`tart` not found on PATH; install it (brew install cirruslabs/cli/tart)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_validation() {
        assert!(validate_sha(&"a".repeat(40)).is_ok());
        assert!(validate_sha(&"A".repeat(40)).is_err());
        assert!(validate_sha("abc").is_err());
        assert!(validate_sha(&format!("{}g", "a".repeat(39))).is_err());
    }

    #[test]
    fn names_and_stale_filter() {
        assert_eq!(vm_name("nav-bench-run-", 5), "nav-bench-run-5");
        let list = "nav-bench-golden\nnav-bench-run-1\n nav-bench-run-5 \nother\n";
        assert_eq!(
            stale_vms(list, "nav-bench-run-", "nav-bench-run-5"),
            ["nav-bench-run-1"]
        );
    }

    #[test]
    fn refs_are_per_run() {
        let (n, b) = bundle_refs("xtask-malware-vm", 7);
        assert_eq!(n, "refs/xtask-malware-vm/7/new");
        assert_eq!(b, "refs/xtask-malware-vm/7/base");
    }

    #[test]
    fn ok_within_reports_status_and_kills_hangs() {
        assert!(ok_within(&mut Command::new("true"), Duration::from_secs(5)));
        assert!(!ok_within(
            &mut Command::new("false"),
            Duration::from_secs(5)
        ));
        let t = Instant::now();
        let mut sleep = Command::new("sleep");
        sleep.arg("30");
        assert!(!ok_within(&mut sleep, Duration::from_millis(300)));
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn exit_mapping() {
        assert_eq!(map_exit(Some(0)), 0);
        assert_eq!(map_exit(Some(2)), 2);
        assert_eq!(map_exit(Some(1)), 1);
        assert_eq!(map_exit(Some(137)), 1);
        assert_eq!(map_exit(None), 1);
    }
}
