//! An unmounted disk-image target carries why in its coverage gaps (§6.2, §8, #208).

use std::path::{Path, PathBuf};
use std::process::Command;

/// A temp directory removed on drop, panic included.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("navctl-unmounted-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A file with sparse-image magic: detected as a disk image, never mountable.
fn fake_image(tag: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new(tag);
    let image = dir.0.join("fake.dmg");
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
    let (_dir, image) = fake_image("no-mount");
    let v = first_object(&["scan", "--json", "--no-mount"], &image);
    assert_eq!(not_mounted_reason(&v), "--no-mount");
}

#[test]
fn a_failed_mount_names_its_reason() {
    let (_dir, image) = fake_image("failed");
    let v = first_object(&["scan", "--json"], &image);
    let reason = not_mounted_reason(&v);
    assert!(!reason.is_empty() && reason != "--no-mount", "{reason}");
    if !cfg!(target_os = "macos") {
        assert_eq!(reason, "disk images are only mounted on macOS");
    }
}

#[test]
fn a_plain_file_has_no_such_gap() {
    let dir = TempDir::new("plain");
    let file = dir.0.join("a.txt");
    std::fs::write(&file, "hello\n").unwrap();
    let v = first_object(&["scan", "--json", "--no-mount"], &file);
    // Not `is_empty()`: off macOS, macOS-only rules add rule-not-applicable gaps.
    let gaps = v["coverage_gaps"].as_array().unwrap();
    assert!(gaps.iter().all(|g| g["kind"] != "not-mounted"), "{v}");
}

#[test]
fn a_directory_holding_an_image_has_no_such_gap() {
    let (dir, _image) = fake_image("dir");
    let v = first_object(&["scan", "--json", "--no-mount"], &dir.0);
    let gaps = v["coverage_gaps"].as_array().unwrap();
    assert!(gaps.iter().all(|g| g["kind"] != "not-mounted"), "{v}");
}
