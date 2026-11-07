//! `navctl rules test` lists the coverage gaps behind a non-Complete result (§5.5, #146).

use std::path::{Path, PathBuf};
use std::process::Command;

const GAP: &str = "- uninspected-container did not finish";
/// No end-of-central-directory record, so the scan is `Partial`.
const BROKEN_ZIP: &[u8] = b"PK\x03\x04not-a-real-zip";

/// A throwaway directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "navctl-rules-test-gaps-{tag}-{}-{:?}",
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

fn rules_test(path: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_navctl"))
        .args(["rules", "test"])
        .arg(path)
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap()
}

/// The run of lines right after the first line containing `needle` that start with
/// `<indent>- `; panics with the full output if `needle` is absent.
fn gap_block<'a>(lines: &[&'a str], needle: &str, indent: &str) -> Vec<&'a str> {
    let Some(i) = lines.iter().position(|l| l.contains(needle)) else {
        panic!("{needle:?} not found in:\n{}", lines.join("\n"));
    };
    let prefix = format!("{indent}- ");
    lines[i + 1..]
        .iter()
        .copied()
        .take_while(|l| l.starts_with(&prefix))
        .collect()
}

fn assert_has_zip_gap(block: &[&str], indent: &str, out: &str) {
    let want = format!("{indent}{GAP}");
    assert!(
        block.contains(&want.as_str()),
        "{block:?} lacks {want:?} in:\n{out}"
    );
}

fn assert_no_zip_gap(block: &[&str], out: &str) {
    assert!(
        !block.iter().any(|l| l.ends_with(GAP)),
        "{block:?} has the zip gap in:\n{out}"
    );
}

#[test]
fn single_file_output_lists_gaps_only_when_partial() {
    let dir = TempDir::new("single");
    let zip = dir.path().join("broken.zip");
    let notes = dir.path().join("notes.txt");
    std::fs::write(&zip, BROKEN_ZIP).unwrap();
    std::fs::write(&notes, "plain notes\n").unwrap();

    let out = rules_test(&zip);
    let lines: Vec<&str> = out.lines().collect();
    let block = gap_block(&lines, "Scan completeness:", "  ");
    assert_has_zip_gap(&block, "  ", &out);

    let out = rules_test(&notes);
    let lines: Vec<&str> = out.lines().collect();
    let block = gap_block(&lines, "Scan completeness:", "  ");
    assert_no_zip_gap(&block, &out);
    #[cfg(target_os = "macos")]
    {
        assert!(out.contains("Scan completeness:   Complete"), "{out}");
        assert!(block.is_empty(), "{out}");
    }
}

#[test]
fn multi_file_output_lists_gaps_for_the_worst_and_each_partial_member() {
    let dir = TempDir::new("multi");
    std::fs::write(dir.path().join("a.zip"), BROKEN_ZIP).unwrap();
    std::fs::write(dir.path().join("b.zip"), BROKEN_ZIP).unwrap();
    std::fs::write(dir.path().join("notes.txt"), "plain notes\n").unwrap();

    let out = rules_test(dir.path());
    let lines: Vec<&str> = out.lines().collect();

    // Every file is Partial off macOS, so the worst may be notes.txt there.
    let worst = gap_block(&lines, "  Scan completeness:", "    ");
    assert!(!worst.is_empty(), "{out}");
    #[cfg(target_os = "macos")]
    assert_has_zip_gap(&worst, "    ", &out);

    let start = lines
        .iter()
        .position(|l| l.starts_with("All files:"))
        .unwrap_or_else(|| panic!("no `All files:` in:\n{out}"));
    let listing = &lines[start..];
    for name in ["a.zip", "b.zip"] {
        let block = gap_block(listing, name, "        ");
        assert_has_zip_gap(&block, "        ", &out);
    }
    let notes = gap_block(listing, "notes.txt", "        ");
    assert_no_zip_gap(&notes, &out);
    #[cfg(target_os = "macos")]
    assert!(notes.is_empty(), "{out}");

    #[cfg(target_os = "macos")]
    assert_eq!(
        lines.iter().filter(|l| l.ends_with(GAP)).count(),
        3,
        "{out}"
    );
}
