//! An unmounted disk-image target carries why in its coverage gaps (§6.2, §8, #208).

use std::path::{Path, PathBuf};
use std::process::Command;

/// A file with sparse-image magic: detected as a disk image, never mountable.
fn fake_image(tag: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("navctl-unmounted-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let image = dir.join("fake.dmg");
    let mut bytes = b"sprs".to_vec();
    bytes.resize(4096, 0);
    std::fs::write(&image, bytes).unwrap();
    (dir, image)
}

fn first_object(args: &[&str], target: &Path) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_navctl"))
        .args(args)
        .arg(target)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    serde_json::from_str(text.lines().next().unwrap()).unwrap()
}

fn not_mounted_reason(v: &serde_json::Value) -> String {
    assert_eq!(v["completeness"], "partial", "{v}");
    let gaps = v["coverage_gaps"].as_array().unwrap();
    let gap = gaps
        .iter()
        .find(|g| g["kind"] == "not-mounted")
        .unwrap_or_else(|| panic!("no not-mounted gap: {v}"));
    gap["reason"].as_str().unwrap().to_owned()
}

#[test]
fn no_mount_names_its_reason() {
    let (dir, image) = fake_image("no-mount");
    let v = first_object(&["scan", "--json", "--no-mount"], &image);
    assert_eq!(not_mounted_reason(&v), "--no-mount");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failed_mount_names_its_reason() {
    let (dir, image) = fake_image("failed");
    let v = first_object(&["scan", "--json"], &image);
    let reason = not_mounted_reason(&v);
    assert!(!reason.is_empty() && reason != "--no-mount", "{reason}");
    if !cfg!(target_os = "macos") {
        assert_eq!(reason, "disk images are only mounted on macOS");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_plain_file_has_no_such_gap() {
    let dir = std::env::temp_dir().join(format!("navctl-unmounted-plain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("a.txt");
    std::fs::write(&file, "hello\n").unwrap();
    let v = first_object(&["scan", "--json", "--no-mount"], &file);
    assert!(v["coverage_gaps"].as_array().unwrap().is_empty(), "{v}");
    std::fs::remove_dir_all(&dir).unwrap();
}
