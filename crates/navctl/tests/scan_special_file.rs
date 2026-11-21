//! A FIFO scan target is refused with a clear message, not `ENOTDIR` (§8).

#![cfg(unix)]

use std::process::Command;

#[test]
fn fifo_target_refused() {
    let dir = std::env::temp_dir().join(format!("nav-fifo-target-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("pipe");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

    let out = Command::new(env!("CARGO_BIN_EXE_navctl"))
        .arg("scan")
        .arg(&fifo)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(out.status.code(), Some(4));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not a regular file or directory"), "{err}");
    assert!(!err.contains("Not a directory"), "{err}");
}
