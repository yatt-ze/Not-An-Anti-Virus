//! A closed stdout stops output, not the scan or its exit code (§8, #160).

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// A throwaway directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "navctl-closed-stdout-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn closed_stdout(json: bool) {
    let dir = TempDir::new(if json { "json" } else { "human" });
    // Long names so the output exceeds the pipe buffer.
    for i in 0..1500 {
        let name = format!("{}-{i}.sh", "f".repeat(100));
        std::fs::write(dir.0.join(name), "#!/bin/sh\necho hi\n").unwrap();
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_navctl"));
    cmd.arg("scan");
    if json {
        cmd.arg("--json");
    }
    let mut child = cmd
        .arg(&dir.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    // Dropping the reader closes the read end of stdout.
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    assert!(!first.is_empty());
    let out = child.wait_with_output().unwrap();
    let code = out.status.code();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(matches!(code, Some(0..=4)), "exit {code:?}: {stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn human_output() {
    closed_stdout(false);
}

#[test]
fn json_output() {
    closed_stdout(true);
}
