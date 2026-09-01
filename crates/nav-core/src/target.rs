//! Turning a scan *target* (the path the user named) into the set of files
//! scanned, and folding their [`ScanResult`]s into one answer.
//!
//! `navctl scan` and `navctl rules test` both route through here so they can't
//! diverge on what a target means — `scan` renders it tersely, `rules test` in
//! full, both from the same [`TargetScan`].

use std::io;
use std::path::{Path, PathBuf};

use crate::bundle::{self, BundleLayout};
use crate::model::{Recommendation, ScanCompleteness, ScanResult};
use crate::scan::scan_file;

/// What the named target turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    File,
    Directory,
    /// A macOS `.app` bundle — a directory, but scanned as one logical unit
    /// with a resolved main executable (see [`crate::bundle`]).
    Bundle,
}

/// The outcome of scanning a target path: every file that was scanned, plus
/// enough structure to render either output style and derive one verdict.
#[derive(Debug)]
pub struct TargetScan {
    /// The path the caller named.
    pub root: PathBuf,
    pub kind: TargetKind,
    /// Per-file results, in deterministic (sorted-by-path) order.
    pub results: Vec<ScanResult>,
    /// For a `Bundle` target: the resolved main executable, if any.
    pub primary: Option<PathBuf>,
    /// Bundle members traversed but not scored (see
    /// [`bundle::is_inert_bundle_resource`]).
    pub skipped: Vec<PathBuf>,
}

impl TargetScan {
    /// The single most severe result — the one the target's overall verdict
    /// is taken from. `None` only when nothing was scanned.
    pub fn worst(&self) -> Option<&ScanResult> {
        self.results.iter().max_by(|a, b| {
            severity_rank(a)
                .cmp(&severity_rank(b))
                .then(a.score.cmp(&b.score))
        })
    }

    /// The result for the bundle's resolved main executable, if any.
    pub fn primary_result(&self) -> Option<&ScanResult> {
        let primary = self.primary.as_ref()?;
        self.results.iter().find(|r| &r.path == primary)
    }

    /// Overall recommendation for the target: the worst file's. Returns
    /// `NoAction` when nothing was scanned — callers that must distinguish
    /// "clean" from "nothing to scan" should check `results` first.
    pub fn recommendation(&self) -> Recommendation {
        self.worst()
            .map(|r| r.recommendation)
            .unwrap_or(Recommendation::NoAction)
    }
}

/// Severity ordering for picking the worst result. An incomplete scan that
/// found nothing ranks above a complete clean one ("couldn't check" != "clean",
/// §10/§11.8) but below any real finding.
fn severity_rank(r: &ScanResult) -> u8 {
    match (r.completeness, r.recommendation) {
        (ScanCompleteness::Complete, Recommendation::NoAction) => 0,
        (_, Recommendation::NoAction) => 1,
        (_, Recommendation::Notify) => 2,
        (_, Recommendation::NotifyAndSuggestQuarantine) => 3,
    }
}

/// Scan a target path.
///
/// - A file scans as itself.
/// - An `.app` bundle (§5.8) is scanned as one unit: every member is
///   traversed regardless of `recursive`, compiled resources are skipped
///   from scoring, and the main executable is resolved for context.
/// - Any other directory scans every file under it (recursively when
///   `recursive`), in sorted order.
pub fn scan_target(path: &Path, recursive: bool) -> io::Result<TargetScan> {
    // Follow a symlink named as the target itself (the user's intent); ones
    // met mid-traversal are not followed (see `collect_files`).
    let meta = std::fs::metadata(path)?;

    if meta.is_file() {
        return Ok(TargetScan {
            root: path.to_path_buf(),
            kind: TargetKind::File,
            results: vec![scan_file(path)],
            primary: None,
            skipped: Vec::new(),
        });
    }

    if let Some(layout) = BundleLayout::detect(path) {
        // A bundle is always traversed in full; `recursive` doesn't apply.
        let all = collect_files(path, true)?;
        let (to_scan, skipped): (Vec<PathBuf>, Vec<PathBuf>) = all
            .into_iter()
            .partition(|p| !bundle::is_inert_bundle_resource(p));
        let results = to_scan.iter().map(|f| scan_file(f)).collect();
        return Ok(TargetScan {
            root: path.to_path_buf(),
            kind: TargetKind::Bundle,
            results,
            primary: layout.main_executable,
            skipped,
        });
    }

    let files = collect_files(path, recursive)?;
    let results = files.iter().map(|f| scan_file(f)).collect();
    Ok(TargetScan {
        root: path.to_path_buf(),
        kind: TargetKind::Directory,
        results,
        primary: None,
        skipped: Vec::new(),
    })
}

/// Depth-first file collection under `root`, sorted for determinism (§11.1).
/// Directory symlinks are not followed (traversal cycles, scan escape).
fn collect_files(root: &Path, recursive: bool) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            // `DirEntry::file_type` does not traverse a symlink.
            let file_type = entry.file_type()?;
            let path = entry.path();

            if file_type.is_dir() {
                if recursive {
                    stack.push(path);
                }
            } else if file_type.is_file() {
                out.push(path);
            }
            // Symlinks, sockets, fifos, devices: skip.
        }
    }

    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A throwaway directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "nav-target-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&base).unwrap();
            TempDir(base)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn file_target_scans_as_itself() {
        let dir = TempDir::new("file");
        let f = dir.path().join("hello.txt");
        fs::write(&f, b"hello world").unwrap();

        let scan = scan_target(&f, false).unwrap();
        assert_eq!(scan.kind, TargetKind::File);
        assert_eq!(scan.results.len(), 1);
        assert_eq!(scan.results[0].path, f);
    }

    #[test]
    fn directory_target_scans_each_file_sorted() {
        let dir = TempDir::new("dir");
        fs::write(dir.path().join("b.txt"), b"second").unwrap();
        fs::write(dir.path().join("a.txt"), b"first").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/c.txt"), b"nested").unwrap();

        let shallow = scan_target(dir.path(), false).unwrap();
        assert_eq!(shallow.kind, TargetKind::Directory);
        let names: Vec<_> = shallow
            .results
            .iter()
            .map(|r| r.path.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["a.txt", "b.txt"]);

        let deep = scan_target(dir.path(), true).unwrap();
        assert_eq!(deep.results.len(), 3);
        assert!(deep.results.iter().any(|r| r.path.ends_with("sub/c.txt")));
    }

    #[test]
    fn app_bundle_is_scanned_as_one_unit_with_resources_skipped() {
        let dir = TempDir::new("bundle");
        let app = dir.path().join("Widget.app");
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::create_dir_all(app.join("Contents/Resources")).unwrap();
        fs::create_dir_all(app.join("Contents/_CodeSignature")).unwrap();
        fs::write(app.join("Contents/Info.plist"), b"<plist/>").unwrap();
        fs::write(app.join("Contents/MacOS/Widget"), b"#!/bin/sh\necho hi\n").unwrap();
        fs::write(
            app.join("Contents/Resources/Assets.car"),
            b"\x00\x01\x02car",
        )
        .unwrap();
        fs::write(app.join("Contents/Resources/helper.sh"), b"#!/bin/sh\n").unwrap();
        fs::write(
            app.join("Contents/_CodeSignature/CodeResources"),
            b"<plist/>",
        )
        .unwrap();

        // The `recursive` flag is irrelevant for a bundle — it always
        // traverses in full.
        let scan = scan_target(&app, false).unwrap();
        assert_eq!(scan.kind, TargetKind::Bundle);
        assert_eq!(scan.primary, Some(app.join("Contents/MacOS/Widget")));

        let scanned: Vec<_> = scan
            .results
            .iter()
            .map(|r| {
                r.path
                    .strip_prefix(&app)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(
            scanned,
            vec!["Contents/MacOS/Widget", "Contents/Resources/helper.sh"]
        );

        let skipped: Vec<_> = scan
            .skipped
            .iter()
            .map(|p| p.strip_prefix(&app).unwrap().to_str().unwrap().to_string())
            .collect();
        assert!(skipped.contains(&"Contents/Info.plist".to_string()));
        assert!(skipped.contains(&"Contents/Resources/Assets.car".to_string()));
        assert!(skipped.contains(&"Contents/_CodeSignature/CodeResources".to_string()));

        assert!(scan.primary_result().is_some());
    }

    #[test]
    fn missing_target_is_an_io_error_not_a_clean_verdict() {
        let dir = TempDir::new("missing");
        let err = scan_target(&dir.path().join("nope"), false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn directory_symlinks_are_not_followed() {
        let dir = TempDir::new("symlink");
        fs::create_dir(dir.path().join("real")).unwrap();
        fs::write(dir.path().join("real/x.txt"), b"x").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
            let scan = scan_target(dir.path(), true).unwrap();
            // "real/x.txt" once, not also via "link/x.txt".
            assert_eq!(scan.results.len(), 1);
        }
    }
}
