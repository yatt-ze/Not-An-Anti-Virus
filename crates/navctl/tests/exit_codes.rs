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
        // Timestamps alone collide across threads (macOS clocks are µs).
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "navctl-exit-codes-{tag}-{}-{}-{:?}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
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

/// #159: a subdirectory skipped without `--recursive` is named on stderr,
/// and the note alone does not change the exit code.
#[test]
fn subdir_note_keeps_exit_code() {
    let dir = TempDir::new("not-recursive");
    std::fs::write(dir.path().join("readme.txt"), b"hello\n").unwrap();
    let baseline = run_scan(dir.path()).status.code();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::copy(DROPPER_SH, dir.path().join("sub/dropper.sh")).unwrap();

    let out = run_scan(dir.path());

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1 subdirectory of ") && stderr.contains("(use --recursive)"),
        "stderr: {stderr}"
    );
    assert_eq!(out.status.code(), baseline, "stderr: {stderr}");
}

/// Parse each stdout line of `navctl scan --json` as one JSON object.
fn json_lines(out: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is one JSON object"))
        .collect()
}

/// #51: a directory scan ends with one summary line, the only object with
/// a `kind` key, whose `files` counts the per-file lines before it.
#[test]
fn dir_scan_ends_with_summary() {
    let dir = TempDir::new("json-summary");
    std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
    std::fs::write(dir.path().join("b.txt"), "world\n").unwrap();
    let out = navctl(&["scan", "--json"], dir.path());
    let lines = json_lines(&out);
    let (summary, files) = lines.split_last().unwrap();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|f| f.get("kind").is_none()));
    assert_eq!(summary["kind"], "directory");
    assert_eq!(summary["files"], 2);
    assert_eq!(
        summary["schema_version"],
        nav_core::SCAN_JSON_SCHEMA_VERSION
    );
    assert!(summary["coverage_complete"].is_boolean());
    assert_eq!(summary["budget_limits"], serde_json::json!([]));
    assert!(summary.get("results").is_none());
}

/// #51: a budget stop shows in the summary, not only on stderr.
#[test]
fn budget_stop_in_summary() {
    let dir = TempDir::new("json-budget");
    std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
    std::fs::write(dir.path().join("b.txt"), "world\n").unwrap();
    let out = navctl(&["scan", "--json", "--max-files", "1"], dir.path());
    let lines = json_lines(&out);
    let summary = lines.last().unwrap();
    assert_eq!(summary["files"], 1);
    assert_eq!(summary["coverage_complete"], false);
    assert_eq!(summary["budget_limits"], serde_json::json!(["max-files"]));
}

/// #51: a budget that admits no file still prints the summary, `files: 0`.
#[test]
fn empty_scan_prints_summary() {
    let dir = TempDir::new("json-empty");
    std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
    let out = navctl(&["scan", "--json", "--max-files", "0"], dir.path());
    assert_eq!(out.status.code(), Some(3));
    let lines = json_lines(&out);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["files"], 0);
    assert_eq!(lines[0]["coverage_complete"], false);
}

/// #51: a single-file target stays one object with no summary.
#[test]
fn file_scan_has_no_summary() {
    let dir = TempDir::new("json-file");
    let file = dir.path().join("a.txt");
    std::fs::write(&file, "hello\n").unwrap();
    let out = navctl(&["scan", "--json"], &file);
    let lines = json_lines(&out);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].get("kind").is_none());
}

/// #29: a readable empty directory is indeterminate (exit 3) for both commands.
#[test]
fn empty_dir_indeterminate() {
    let dir = TempDir::new("empty-dir");
    for args in [
        &["scan"][..],
        &["scan", "--json"],
        &["rules", "test"],
        &["rules", "test", "--json"],
    ] {
        let out = navctl(args, dir.path());
        assert_eq!(out.status.code(), Some(3), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("no files to scan under"), "{args:?}: {err}");
    }
    // `scan --json` still prints its target summary, with zero files.
    let out = navctl(&["scan", "--json"], dir.path());
    let lines = json_lines(&out);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["files"], 0);
}
