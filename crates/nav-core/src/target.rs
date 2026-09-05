//! Turning a scan *target* (the path the user named) into the set of files
//! scanned, and folding their [`ScanResult`]s into one answer.
//!
//! `navctl scan` and `navctl rules test` both route through here so they can't
//! diverge on what a target means — `scan` renders it tersely, `rules test` in
//! full, both from the same [`TargetScan`].

use std::io;
use std::path::{Path, PathBuf};

use crate::bundle::{self, BundleLayout};
use crate::context::MAX_CONTENT_BYTES;
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

/// Ceilings on a whole-target scan, so a directory or bundle with
/// pathologically many, deep, or large files can't become unbounded work
/// (NAV-004/011, §11). These are the target-level counterpart to the per-file
/// read cap (§3) and per-container extraction limits (§6.2), which still apply
/// independently. Hitting a ceiling is treated as incomplete coverage, never
/// as a clean result (§10/§11.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanBudget {
    /// Maximum number of files scored in one target scan.
    pub max_files: usize,
    /// Maximum summed input across the target, each file counted at the bytes
    /// actually read for it (its length clipped to the §3 per-file cap).
    pub max_total_bytes: u64,
    /// Maximum directory-recursion depth below the named target.
    pub max_depth: usize,
}

impl Default for ScanBudget {
    /// Generous enough for a large but legitimate tree, low enough that a
    /// hostile or runaway target is bounded. Tunable later via `navctl config`.
    fn default() -> Self {
        Self {
            max_files: 50_000,
            max_total_bytes: 4 * 1024 * 1024 * 1024, // 4 GiB read
            max_depth: 64,
        }
    }
}

/// Which budget ceiling stopped a target scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetLimit {
    Files,
    TotalBytes,
    Depth,
}

/// Whether a target scan fit inside its [`ScanBudget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetOutcome {
    /// The whole target was traversed and scored within budget.
    Within,
    /// A ceiling was hit, so the target was only partially scanned — the
    /// result must be read as incomplete coverage even if every scored file
    /// was individually `Complete` (§11.8).
    Exhausted(BudgetLimit),
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
    /// Whether the scan fit inside its budget, or was cut short (and how).
    pub budget: BudgetOutcome,
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

    /// Whether the whole target was covered. `false` when a [`ScanBudget`]
    /// ceiling cut the traversal short, so the target result is partial even
    /// if every scored file was individually `Complete` — "couldn't finish"
    /// is not "clean" (§11.8).
    pub fn coverage_complete(&self) -> bool {
        self.budget == BudgetOutcome::Within
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
    scan_target_with_budget(path, recursive, &ScanBudget::default())
}

/// Like [`scan_target`], but with an explicit [`ScanBudget`]. A ceiling hit
/// during traversal or scanning stops the scan and records
/// [`BudgetOutcome::Exhausted`] rather than silently dropping coverage.
pub fn scan_target_with_budget(
    path: &Path,
    recursive: bool,
    budget: &ScanBudget,
) -> io::Result<TargetScan> {
    // Follow a symlink named as the target itself (the user's intent); ones
    // met mid-traversal are not followed (see `collect_files`).
    let meta = std::fs::metadata(path)?;

    // A directly named single file has nothing to traverse, so the budget
    // (which bounds *traversal* — file count, depth, aggregate size) doesn't
    // apply; the file is already bounded by the §3 per-file read cap. Coverage
    // is complete by construction (§11.12).
    if meta.is_file() {
        return Ok(TargetScan {
            root: path.to_path_buf(),
            kind: TargetKind::File,
            results: vec![scan_file(path)],
            primary: None,
            skipped: Vec::new(),
            budget: BudgetOutcome::Within,
        });
    }

    if let Some(layout) = BundleLayout::detect(path) {
        // A bundle is always traversed in full; `recursive` doesn't apply.
        let (all, collect_limit) = collect_files(path, true, budget)?;
        let (to_scan, skipped): (Vec<PathBuf>, Vec<PathBuf>) = all
            .into_iter()
            .partition(|p| !bundle::is_inert_bundle_resource(p));
        let (results, byte_limit) = scan_within_bytes(&to_scan, budget);
        return Ok(TargetScan {
            root: path.to_path_buf(),
            kind: TargetKind::Bundle,
            results,
            primary: layout.main_executable,
            skipped,
            budget: outcome(collect_limit, byte_limit),
        });
    }

    let (files, collect_limit) = collect_files(path, recursive, budget)?;
    let (results, byte_limit) = scan_within_bytes(&files, budget);
    Ok(TargetScan {
        root: path.to_path_buf(),
        kind: TargetKind::Directory,
        results,
        primary: None,
        skipped: Vec::new(),
        budget: outcome(collect_limit, byte_limit),
    })
}

/// Fold the collection-time and scan-time budget limits into one outcome. A
/// structural limit (files/depth) is reported ahead of a byte limit, since it
/// bounds what was even discovered.
fn outcome(collect_limit: Option<BudgetLimit>, byte_limit: Option<BudgetLimit>) -> BudgetOutcome {
    match collect_limit.or(byte_limit) {
        Some(limit) => BudgetOutcome::Exhausted(limit),
        None => BudgetOutcome::Within,
    }
}

/// Scan `files` in order until the summed read (each file's length clipped to
/// the §3 per-file cap) would exceed `max_total_bytes`. Returns the results
/// scored and `Some(TotalBytes)` if the cap stopped it short.
fn scan_within_bytes(
    files: &[PathBuf],
    budget: &ScanBudget,
) -> (Vec<ScanResult>, Option<BudgetLimit>) {
    let mut results = Vec::new();
    let mut used: u64 = 0;
    for f in files {
        let read_len = std::fs::metadata(f)
            .map(|m| m.len().min(MAX_CONTENT_BYTES as u64))
            .unwrap_or(0);
        // Always allow the first file through, so one large file still scans.
        if !results.is_empty() && used.saturating_add(read_len) > budget.max_total_bytes {
            return (results, Some(BudgetLimit::TotalBytes));
        }
        used = used.saturating_add(read_len);
        results.push(scan_file(f));
    }
    (results, None)
}

/// Depth-first file collection under `root`, sorted for determinism (§11.1).
/// Directory symlinks are not followed (traversal cycles, scan escape).
/// Stops early if the budget's file-count or depth ceiling is reached,
/// returning which limit was hit so the target can be marked partial.
fn collect_files(
    root: &Path,
    recursive: bool,
    budget: &ScanBudget,
) -> io::Result<(Vec<PathBuf>, Option<BudgetLimit>)> {
    let mut out = Vec::new();
    let mut limit_hit = None;
    // Depth is measured relative to `root`, which sits at depth 0.
    let mut stack = vec![(root.to_path_buf(), 0usize)];

    'walk: while let Some((dir, depth)) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            // `DirEntry::file_type` does not traverse a symlink.
            let file_type = entry.file_type()?;
            let path = entry.path();

            if file_type.is_dir() {
                if recursive {
                    if depth < budget.max_depth {
                        stack.push((path, depth + 1));
                    } else {
                        limit_hit.get_or_insert(BudgetLimit::Depth);
                    }
                }
            } else if file_type.is_file() {
                if out.len() >= budget.max_files {
                    limit_hit = Some(BudgetLimit::Files);
                    break 'walk;
                }
                out.push(path);
            }
            // Symlinks, sockets, fifos, devices: skip.
        }
    }

    out.sort();
    Ok((out, limit_hit))
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
    fn default_budget_leaves_a_small_target_complete() {
        let dir = TempDir::new("budget-ok");
        fs::write(dir.path().join("a.txt"), b"a").unwrap();
        fs::write(dir.path().join("b.txt"), b"b").unwrap();
        let scan = scan_target(dir.path(), true).unwrap();
        assert_eq!(scan.budget, BudgetOutcome::Within);
        assert!(scan.coverage_complete());
    }

    #[test]
    fn file_count_ceiling_marks_the_target_partial() {
        let dir = TempDir::new("budget-files");
        for i in 0..5 {
            fs::write(dir.path().join(format!("f{i}.txt")), b"x").unwrap();
        }
        let budget = ScanBudget {
            max_files: 2,
            ..ScanBudget::default()
        };
        let scan = scan_target_with_budget(dir.path(), true, &budget).unwrap();
        assert_eq!(scan.results.len(), 2);
        assert_eq!(scan.budget, BudgetOutcome::Exhausted(BudgetLimit::Files));
        assert!(!scan.coverage_complete());
    }

    #[test]
    fn depth_ceiling_marks_the_target_partial_and_stops_descent() {
        let dir = TempDir::new("budget-depth");
        fs::write(dir.path().join("top.txt"), b"t").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/deep.txt"), b"d").unwrap();

        let budget = ScanBudget {
            max_depth: 0,
            ..ScanBudget::default()
        };
        let scan = scan_target_with_budget(dir.path(), true, &budget).unwrap();
        // Only the top-level file is scored; the depth-1 file is out of budget.
        assert!(scan.results.iter().any(|r| r.path.ends_with("top.txt")));
        assert!(!scan
            .results
            .iter()
            .any(|r| r.path.ends_with("sub/deep.txt")));
        assert_eq!(scan.budget, BudgetOutcome::Exhausted(BudgetLimit::Depth));
    }

    #[test]
    fn total_bytes_ceiling_still_scans_the_first_file() {
        let dir = TempDir::new("budget-bytes");
        fs::write(dir.path().join("a.bin"), vec![0u8; 4096]).unwrap();
        fs::write(dir.path().join("b.bin"), vec![0u8; 4096]).unwrap();
        // A cap below one file's size: the first file always gets through, the
        // second trips the ceiling.
        let budget = ScanBudget {
            max_total_bytes: 100,
            ..ScanBudget::default()
        };
        let scan = scan_target_with_budget(dir.path(), true, &budget).unwrap();
        assert_eq!(scan.results.len(), 1);
        assert_eq!(
            scan.budget,
            BudgetOutcome::Exhausted(BudgetLimit::TotalBytes)
        );
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
