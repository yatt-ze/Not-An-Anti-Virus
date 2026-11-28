//! `service install` without a `navd` beside `navctl` fails before the root
//! check, with exit 4 (§8, #250).

#![cfg(unix)]

use std::process::Command;

#[test]
fn missing_navd_refused() {
    let dir = std::env::temp_dir().join(format!("nav-no-navd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A copy outside target/, where cargo has built navd beside navctl.
    let navctl = dir.join("navctl");
    std::fs::copy(env!("CARGO_BIN_EXE_navctl"), &navctl).unwrap();

    let out = Command::new(&navctl)
        .args(["service", "install"])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(out.status.code(), Some(4));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("standalone navctl CLI"), "{err}");
    assert!(!err.contains("must run as root"), "{err}");
}
