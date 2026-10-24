//! End-to-end coverage for `navctl scan`'s target-level exit code (§8),
//! driving the built binary as a subprocess. Regression coverage for #34.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const DROPPER_SH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../nav-core/fixtures/suspicious/dropper.sh"
);

/// A throwaway directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "navctl-exit-codes-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_scan(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_navctl"))
        .arg("scan")
        .arg(path)
        .output()
        .expect("navctl scan spawns")
}

/// Writes a clean shell script past the §3 8 MiB read cap: it scans `Partial`,
/// since the script-entropy checks only see the prefix (#45).
fn write_oversized_script(dir: &Path) {
    let mut script = b"#!/bin/sh\n".to_vec();
    while script.len() <= 8 * 1024 * 1024 {
        script.extend_from_slice(b"# padding line to keep this script large.\n");
    }
    std::fs::write(dir.join("big.sh"), script).unwrap();
}

/// #34: a real finding (dropper.sh, `Notify` on every platform) must not be
/// masked by an unrelated `Partial` sibling.
#[test]
fn a_flagged_file_is_not_masked_by_an_oversized_sibling() {
    let dir = TempDir::new("flagged-plus-oversized");
    write_oversized_script(dir.path());
    // Precondition: the sibling alone really is incomplete, or this test proves nothing.
    assert_eq!(run_scan(dir.path()).status.code(), Some(3));
    std::fs::copy(DROPPER_SH, dir.path().join("dropper.sh")).unwrap();

    let out = run_scan(dir.path());

    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// An oversized clean file has no finding, but wasn't fully examined either:
/// indeterminate, not clean.
#[test]
fn an_oversized_clean_file_alone_is_indeterminate() {
    let dir = TempDir::new("oversized-only");
    write_oversized_script(dir.path());

    let out = run_scan(dir.path());

    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn navctl(args: &[&str], path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_navctl"))
        .args(args)
        .arg(path)
        .output()
        .expect("navctl spawns")
}

/// `--max-files` lowers the walk budget for both commands, and a larger
/// value lets the same directory finish (§11.12).
#[test]
fn max_files_flag_sets_the_walk_budget() {
    let dir = TempDir::new("max-files");
    std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
    std::fs::write(dir.path().join("b.txt"), "world\n").unwrap();

    for cmd in [&["scan"][..], &["rules", "test"][..]] {
        let cut = navctl(&[cmd, &["--max-files", "1"]].concat(), dir.path());
        assert_eq!(cut.status.code(), Some(3), "{cmd:?}");
        // `scan` warns on stderr; `rules test` in its stdout report.
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&cut.stdout),
            String::from_utf8_lossy(&cut.stderr)
        );
        assert!(text.contains("max-files"), "{cmd:?}: {text}");

        // Enough budget: no warning, and the same exit as no flags (not
        // always 0: off macOS some rules can't run, so files scan Partial).
        let ok = navctl(&[cmd, &["--max-files", "10"]].concat(), dir.path());
        let plain = navctl(cmd, dir.path());
        assert_eq!(ok.status.code(), plain.status.code(), "{cmd:?}");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&ok.stdout),
            String::from_utf8_lossy(&ok.stderr)
        );
        assert!(!text.contains("scan budget reached"), "{cmd:?}: {text}");
    }
}

/// `--max-total-bytes` below the first file still scans that file, then
/// stops (the first file is always admitted).
#[test]
fn max_total_bytes_flag_sets_the_byte_budget() {
    let dir = TempDir::new("max-bytes");
    std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
    std::fs::write(dir.path().join("b.txt"), "world\n").unwrap();

    let cut = navctl(&["scan", "--max-total-bytes", "1"], dir.path());
    assert_eq!(cut.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&cut.stderr).contains("max-total-bytes"));
}

/// A budget that admits no file is partial coverage (exit 3, with the
/// budget warning), not "no files found" (exit 4).
#[test]
fn a_budget_that_admits_no_file_is_indeterminate() {
    let dir = TempDir::new("max-files-0");
    std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
    for cmd in [&["scan"][..], &["rules", "test"][..]] {
        let out = navctl(&[cmd, &["--max-files", "0"]].concat(), dir.path());
        assert_eq!(out.status.code(), Some(3), "{cmd:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("scan budget reached (max-files)"),
            "{cmd:?}: {stderr}"
        );
    }
    let json = navctl(&["rules", "test", "--json", "--max-files", "0"], dir.path());
    assert!(String::from_utf8_lossy(&json.stdout).contains("\"coverage_complete\": false"));
}
