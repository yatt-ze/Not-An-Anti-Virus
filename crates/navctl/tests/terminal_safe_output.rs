//! Human output never carries raw control or bidi characters from file names
//! (§8, #156); `--json` keeps the raw name.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FILE_NAME: &str = "a\x1b[2K\rCLEAN\x1b[0m\n.sh";
const FILE_SAFE: &str = "a\u{FFFD}[2K\u{FFFD}CLEAN\u{FFFD}[0m\u{FFFD}.sh";
const DIR_NAME: &str = "d\x1b\r\n\u{202E}dir";

/// A throwaway directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        // Timestamps alone collide across threads (macOS clocks are µs).
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "navctl-terminal-safe-{tag}-{}-{}-{:?}",
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

fn fixture() -> TempDir {
    let dir = TempDir::new("scan");
    std::fs::write(dir.path().join(FILE_NAME), "#!/bin/sh\necho hello\n").unwrap();
    let sub = dir.path().join(DIR_NAME);
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("inner.sh"), "#!/bin/sh\ntrue\n").unwrap();
    dir
}

fn navctl(args: &[&str], path: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_navctl"))
        .args(args)
        .arg(path)
        .args(extra)
        .output()
        .expect("navctl spawns")
}

fn assert_terminal_safe(out: &Output) {
    for (name, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains('\x1b'), "{name} has ESC: {text:?}");
        assert!(!text.contains('\r'), "{name} has CR: {text:?}");
        assert!(!text.contains('\u{202E}'), "{name} has U+202E: {text:?}");
    }
}

#[test]
fn scan_human_output_is_terminal_safe() {
    let dir = fixture();
    let out = navctl(&["scan"], dir.path(), &["--recursive"]);
    assert_terminal_safe(&out);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains('\u{FFFD}'), "{text:?}");
    assert!(text.contains(FILE_SAFE), "{text:?}");
    assert_eq!(text.lines().count(), 2, "one line per file: {text:?}");
}

#[test]
fn rules_test_human_output_is_terminal_safe() {
    let dir = fixture();
    let out = navctl(&["rules", "test"], dir.path(), &["--recursive"]);
    assert_terminal_safe(&out);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains('\u{FFFD}'), "{text:?}");
    assert!(text.contains(FILE_SAFE), "{text:?}");
}

#[test]
fn scan_json_keeps_the_raw_name() {
    let dir = fixture();
    let out = navctl(&["scan"], dir.path(), &["--recursive", "--json"]);
    let text = String::from_utf8_lossy(&out.stdout);
    let paths: Vec<String> = text
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("JSON line"))
        .filter(|v| v.get("kind").is_none()) // skip the target summary (#51)
        .map(|v| v["path"].as_str().expect("path").to_string())
        .collect();
    assert_eq!(paths.len(), 2, "{text:?}");
    let want = dir.path().join(FILE_NAME).to_string_lossy().into_owned();
    assert!(paths.contains(&want), "{paths:?}");
}
