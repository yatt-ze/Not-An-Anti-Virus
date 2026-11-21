//! `navctl scan --quick` / `--full` are declared but not built yet (§8); they
//! must fail loudly rather than be silently ignored. Regression coverage for #167.

use std::process::{Command, Output};

const SAMPLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../nav-core/fixtures/suspicious/dropper.sh"
);

fn scan(flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_navctl"))
        .arg("scan")
        .arg(SAMPLE)
        .args(flags)
        .output()
        .expect("navctl scan spawns")
}

#[test]
fn unbuilt_flags_exit_4() {
    for flag in ["--quick", "--full"] {
        let out = scan(&[flag]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(4), "{flag}: {stderr}");
        assert!(stderr.contains("isn't built yet"), "{flag}: {stderr}");
        assert!(stderr.contains(&format!("scan {flag}")), "{flag}: {stderr}");
        assert!(out.stdout.is_empty(), "{flag} must not scan");
    }
}

#[test]
fn flags_conflict() {
    let out = scan(&["--quick", "--full"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot be used with"));
}
