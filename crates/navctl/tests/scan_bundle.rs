//! End-to-end coverage for `navctl scan` on a `.app` bundle (#84), driving
//! the built binary as a subprocess.

use std::process::{Command, Output};

const BUNDLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../nav-core/fixtures/benign/SampleHelper.app"
);
const BENIGN_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../nav-core/fixtures/benign");

fn navctl(args: &[&str], target: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_navctl"))
        .arg("scan")
        .args(args)
        .arg(target)
        .output()
        .expect("navctl scan spawns")
}

fn lines(out: &Output) -> Vec<String> {
    String::from_utf8(out.stdout.clone())
        .expect("utf-8 stdout")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn assert_json_lines(out: &Output) -> usize {
    let ls = lines(out);
    for l in &ls {
        serde_json::from_str::<serde_json::Value>(l).expect("each line is JSON");
    }
    ls.len()
}

#[test]
fn bundle_scan_prints_one_line_and_verbose_adds_file_lines() {
    let json = navctl(&["--json"], BUNDLE);
    let n = assert_json_lines(&json);
    assert!(n >= 2, "fixture bundle should have several files, got {n}");

    let plain = navctl(&[], BUNDLE);
    let plain_lines = lines(&plain);
    assert_eq!(plain_lines.len(), 1, "{plain_lines:?}");
    assert!(plain_lines[0].starts_with(BUNDLE), "{}", plain_lines[0]);
    assert!(
        plain_lines[0].contains(&format!("(bundle: {n} files")),
        "{}",
        plain_lines[0]
    );

    let verbose = navctl(&["--verbose"], BUNDLE);
    let v = lines(&verbose);
    assert_eq!(v.len(), n + 1);
    assert_eq!(v.last(), plain_lines.first());
    assert!(v[..n].iter().all(|l| !l.contains("(bundle:")), "{v:?}");

    let json_verbose = navctl(&["--json", "--verbose"], BUNDLE);
    assert_eq!(assert_json_lines(&json_verbose), n);

    let code = plain.status.code();
    assert!(code.is_some());
    for out in [&json, &verbose, &json_verbose] {
        assert_eq!(out.status.code(), code);
    }
}

/// #159: a bundle's links that leave it are always noted; the ones that
/// stay inside only with `--verbose`.
#[cfg(unix)]
#[test]
fn bundle_link_notes() {
    use std::os::unix::fs::symlink;
    let base = std::env::temp_dir().join(format!("navctl-links-{}", std::process::id()));
    let app = base.join("Evil.app");
    let res = app.join("Contents/Resources");
    std::fs::create_dir_all(&res).unwrap();
    std::fs::write(base.join("evil.sh"), b"x").unwrap();
    std::fs::write(res.join("a.txt"), b"x").unwrap();
    symlink("a.txt", res.join("inside")).unwrap();
    symlink("../../../evil.sh", res.join("y.sh")).unwrap();
    let target = app.to_str().unwrap();

    let plain = String::from_utf8_lossy(&navctl(&[], target).stderr).into_owned();
    let verbose = String::from_utf8_lossy(&navctl(&["--verbose"], target).stderr).into_owned();
    let _ = std::fs::remove_dir_all(&base);

    assert!(plain.contains("1 symlink(s) under "), "{plain}");
    assert!(plain.contains("point outside it"), "{plain}");
    assert!(!plain.contains("other symlink"), "{plain}");
    assert!(verbose.contains("1 other symlink(s)"), "{verbose}");
}

#[test]
fn directory_scan_ignores_verbose() {
    let plain = navctl(&[], BENIGN_DIR);
    let verbose = navctl(&["--verbose"], BENIGN_DIR);
    assert!(!plain.stdout.is_empty());
    assert_eq!(plain.stdout, verbose.stdout);
    assert_eq!(plain.status.code(), verbose.status.code());
}
