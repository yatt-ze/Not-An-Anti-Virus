//! Turning a scan *target* (the path the user named) into the set of files
//! scanned, and folding their [`ScanResult`]s into one answer.
//!
//! `navctl scan` and `navctl rules test` both route through here so they can't
//! diverge on what a target means — `scan` renders it tersely, `rules test` in
//! full, both from the same [`TargetScan`].

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::FileType;

use crate::beneath::ScanRoot;
use crate::bundle::{self, BundleLayout};
use crate::bundle_signals::{self, Finding, Member, MemberFacts};
use crate::context::{ScanContext, MAX_STREAM_BYTES};
use crate::model::{CoverageGap, EvidenceConfidence, Recommendation, ScanCompleteness, ScanResult};
use crate::rules::{default_ruleset, signing_summary};
use crate::scan::{scan_context, scan_file, score_signals};

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
    /// Maximum bytes the scan reads from disk across the target, re-reads
    /// included, plus the bytes container readers decompress
    /// ([`ScanContext::decoded_bytes`]); `codesign`/`spctl` reads are not
    /// counted (§11.12, #106). The in-process reads and decodes never exceed
    /// it: each file may spend only what is left.
    pub max_total_bytes: u64,
    /// Maximum directory-recursion depth below the named target.
    pub max_depth: usize,
    /// Maximum directory entries examined during traversal — files,
    /// directories, and skipped special files alike. Bounds the *breadth* of
    /// the walk, the work `max_files`/`max_total_bytes` miss: a tree of
    /// pathologically many empty directories scores no files and reads no
    /// bytes, so only an entry ceiling bounds it.
    pub max_entries: usize,
}

impl Default for ScanBudget {
    /// Generous enough for a large but legitimate tree, low enough that a
    /// hostile or runaway target is bounded. Tunable later via `navctl config`.
    fn default() -> Self {
        Self {
            max_files: 50_000,
            max_total_bytes: 4 * 1024 * 1024 * 1024, // 4 GiB read or decoded
            max_depth: 64,
            max_entries: 1_000_000,
        }
    }
}

/// Which budget ceiling stopped a target scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetLimit {
    Files,
    TotalBytes,
    Depth,
    Entries,
}

impl BudgetLimit {
    /// Every limit, in declaration order.
    pub const ALL: [BudgetLimit; 4] = [
        BudgetLimit::Files,
        BudgetLimit::TotalBytes,
        BudgetLimit::Depth,
        BudgetLimit::Entries,
    ];

    fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// A set of [`BudgetLimit`]s.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BudgetLimits(u8);

impl BudgetLimits {
    pub fn insert(&mut self, limit: BudgetLimit) {
        self.0 |= limit.bit();
    }

    pub fn contains(self, limit: BudgetLimit) -> bool {
        self.0 & limit.bit() != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The limits in the set, in [`BudgetLimit`] declaration order.
    pub fn iter(self) -> impl Iterator<Item = BudgetLimit> {
        BudgetLimit::ALL
            .into_iter()
            .filter(move |l| self.contains(*l))
    }
}

impl From<BudgetLimit> for BudgetLimits {
    fn from(limit: BudgetLimit) -> Self {
        Self(limit.bit())
    }
}

impl<const N: usize> From<[BudgetLimit; N]> for BudgetLimits {
    fn from(limits: [BudgetLimit; N]) -> Self {
        let mut set = Self::default();
        for limit in limits {
            set.insert(limit);
        }
        set
    }
}

/// Whether a target scan fit inside its [`ScanBudget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetOutcome {
    /// The whole target was traversed and scored within budget.
    Within,
    /// One or more ceilings were hit (never an empty set), so the target was
    /// only partially scanned — the result must be read as incomplete
    /// coverage even if every scored file was individually `Complete` (§11.8).
    Exhausted(BudgetLimits),
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
    /// [`bundle::is_signature_manifest`]).
    pub skipped: Vec<PathBuf>,
    /// Directories whose listing failed in whole or in part (permission
    /// denied, race), sorted and deduped (§11.1). Traversal continues past
    /// each one rather than aborting (§11.8); non-empty means the target's
    /// coverage is partial (§11.12). Always empty for a single-file target.
    pub unreadable: Vec<PathBuf>,
    /// Entries the walk passed over by design. Reported as a note only: they
    /// do not affect [`Self::coverage_complete`] (§8, §11.8).
    pub not_walked: NotWalked,
    /// Whether the scan fit inside its budget, or was cut short (and how).
    pub budget: BudgetOutcome,
}

/// Counts of directory entries a target walk did not enter or follow (#159).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NotWalked {
    /// Subdirectories not entered because the walk was not recursive.
    pub subdirs: usize,
    /// Symlinks, sockets, FIFOs and devices, which are never followed.
    pub links_and_special: usize,
    /// Of those, symlinks that resolve outside the target.
    pub links_outside: usize,
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
    /// ceiling cut the traversal short, or a subdirectory couldn't be read,
    /// so the target result is partial even if every scored file was
    /// individually `Complete` — "couldn't finish" is not "clean"
    /// (§11.8/§11.12).
    pub fn coverage_complete(&self) -> bool {
        self.budget == BudgetOutcome::Within && self.unreadable.is_empty()
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
///   traversed regardless of `recursive`, signature manifests are skipped
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
    // apply; there's no target-level ceiling to check against a single file.
    // Coverage is complete by construction (§11.12).
    if meta.is_file() {
        return Ok(TargetScan {
            root: path.to_path_buf(),
            kind: TargetKind::File,
            results: vec![scan_file(path)],
            primary: None,
            skipped: Vec::new(),
            unreadable: Vec::new(),
            not_walked: NotWalked::default(),
            budget: BudgetOutcome::Within,
        });
    }

    if let Some(layout) = BundleLayout::detect(path) {
        let anchor = Arc::new(ScanRoot::open(path)?);
        // A bundle is always traversed in full; `recursive` doesn't apply.
        let walk = collect_files(&anchor, path, true, budget)?;
        let (to_scan, skipped): (Vec<PathBuf>, Vec<PathBuf>) =
            walk.files.into_iter().partition(|p| {
                let rel = p.strip_prefix(path).unwrap_or(p);
                !bundle::is_signature_manifest(&anchor, rel)
            });
        let (mut results, byte_limit, _, facts) = scan_members(&anchor, path, &to_scan, budget);
        apply_bundle_signals(&mut results, facts, path, layout.main_executable.as_deref());
        return Ok(TargetScan {
            root: path.to_path_buf(),
            kind: TargetKind::Bundle,
            results,
            primary: layout.main_executable,
            skipped,
            unreadable: walk.unreadable,
            not_walked: walk.not_walked,
            budget: outcome(walk.limits, byte_limit),
        });
    }

    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file or directory",
        ));
    }

    let anchor = Arc::new(ScanRoot::open(path)?);
    let walk = collect_files(&anchor, path, recursive, budget)?;
    let (results, byte_limit, _) = scan_within_bytes(&anchor, path, &walk.files, budget);
    Ok(TargetScan {
        root: path.to_path_buf(),
        kind: TargetKind::Directory,
        results,
        primary: None,
        skipped: Vec::new(),
        unreadable: walk.unreadable,
        not_walked: walk.not_walked,
        budget: outcome(walk.limits, byte_limit),
    })
}

/// Every limit hit while collecting or scanning, as one outcome (§11.12).
fn outcome(mut collect_limits: BudgetLimits, byte_limit: Option<BudgetLimit>) -> BudgetOutcome {
    if let Some(limit) = byte_limit {
        collect_limits.insert(limit);
    }
    if collect_limits.is_empty() {
        BudgetOutcome::Within
    } else {
        BudgetOutcome::Exhausted(collect_limits)
    }
}

/// Scan `files` (paths under `base`, each opened beneath `anchor` without
/// following a symlink, §11.7) in order, each with a hard allowance of what
/// is left of `max_total_bytes` (§11.12): its disk reads and decoded bytes are
/// charged as they happen, and work past the allowance is refused. After the
/// first file, a file is started only if its length, clipped to
/// `MAX_STREAM_BYTES`, fits in what is left. Returns the results scored,
/// `Some(TotalBytes)` if a file was refused or one's allowance cut its scan
/// short, and the bytes spent.
fn scan_within_bytes(
    anchor: &Arc<ScanRoot>,
    base: &Path,
    files: &[PathBuf],
    budget: &ScanBudget,
) -> (Vec<ScanResult>, Option<BudgetLimit>, u64) {
    let (results, hit, used, _) = scan_members(anchor, base, files, budget);
    (results, hit, used)
}

/// [`scan_within_bytes`], also returning each result's [`MemberFacts`] (same
/// order) for the bundle signals.
fn scan_members(
    anchor: &Arc<ScanRoot>,
    base: &Path,
    files: &[PathBuf],
    budget: &ScanBudget,
) -> (Vec<ScanResult>, Option<BudgetLimit>, u64, Vec<MemberFacts>) {
    let rules = default_ruleset();
    let mut results = Vec::new();
    let mut facts = Vec::new();
    let mut used: u64 = 0;
    let mut hit = None;
    for f in files {
        let left = budget.max_total_bytes.saturating_sub(used);
        // Always allow the first file through, so one large file still scans.
        let first = results.is_empty();
        let admit = |len: u64| first || len.min(MAX_STREAM_BYTES) <= left;
        // Not under `base` can't happen; the absolute path then fails to open.
        let rel = f.strip_prefix(base).unwrap_or(f);
        let Some(ctx) = ScanContext::load_beneath(anchor, rel, f.clone(), left, admit) else {
            return (results, Some(BudgetLimit::TotalBytes), used, facts);
        };
        results.push(scan_context(&ctx, &rules));
        facts.push(member_facts(&ctx));
        used += left - ctx.allowance_left();
        if ctx.allowance_hit() {
            hit = Some(BudgetLimit::TotalBytes);
        }
    }
    (results, hit, used, facts)
}

/// What a scanned member tells the bundle signals, read from state the
/// rules already computed; nothing is spawned or parsed here.
fn member_facts(ctx: &ScanContext) -> MemberFacts {
    let Some(macho) = ctx.macho_cache.get().filter(|m| m.is_macho) else {
        return MemberFacts::default();
    };
    let mut dylibs: Vec<String> = Vec::new();
    for load in macho.images.iter().flat_map(|i| &i.dylibs) {
        if !dylibs.contains(load) {
            dylibs.push(load.clone());
        }
    }
    MemberFacts {
        is_macho: true,
        signing: signing_summary(ctx),
        dylibs,
    }
}

/// Append the §5.8 bundle-level findings to the members they attach to and
/// rescore those members. A finding that could not be checked becomes a
/// coverage gap, so the member is no longer `Complete`.
fn apply_bundle_signals(
    results: &mut [ScanResult],
    facts: Vec<MemberFacts>,
    root: &Path,
    main: Option<&Path>,
) {
    let members: Vec<Member> = results
        .iter()
        .zip(facts)
        .map(|(r, facts)| Member {
            rel: r.path.strip_prefix(root).unwrap_or(&r.path).to_path_buf(),
            facts,
        })
        .collect();
    let main_idx = main.and_then(|m| results.iter().position(|r| r.path == m));
    for (i, finding) in bundle_signals::findings(&members, main_idx) {
        let result = &mut results[i];
        match finding {
            Finding::Signal(signal) => {
                if result.signals.iter().any(|s| s.id == signal.id) {
                    continue;
                }
                result.signals.push(signal);
                (result.score, result.recommendation) = score_signals(&result.signals);
            }
            Finding::NotApplicable(rule) => {
                result
                    .coverage_gaps
                    .push(CoverageGap::RuleNotApplicable { rule: rule.into() });
                if result.completeness == ScanCompleteness::Complete {
                    result.completeness = ScanCompleteness::Partial;
                    result.confidence = EvidenceConfidence::Medium;
                }
            }
        }
    }
}

/// What [`collect_files`] found.
struct Walk {
    /// Regular files, sorted.
    files: Vec<PathBuf>,
    /// The budget ceilings the walk hit; empty if none.
    limits: BudgetLimits,
    /// Directories that could not be listed, sorted.
    unreadable: Vec<PathBuf>,
    not_walked: NotWalked,
}

/// Sorted regular files under `root` (the path `anchor` was opened from),
/// each directory listed beneath `anchor` with no symlink followed (§11.7).
/// Returned paths are `root` joined with the path beneath it, plus every
/// budget limit hit. Errors only if `root` itself can't be listed; a deeper
/// directory or entry that fails is recorded as unreadable (§11.8).
fn collect_files(
    anchor: &ScanRoot,
    root: &Path,
    recursive: bool,
    budget: &ScanBudget,
) -> io::Result<Walk> {
    walk_files(anchor, root, recursive, budget, |_| {})
}

/// [`collect_files`], calling `after_list` with each directory's path beneath
/// the root once it has been listed (a test seam for swaps mid-walk).
fn walk_files(
    anchor: &ScanRoot,
    root: &Path,
    recursive: bool,
    budget: &ScanBudget,
    mut after_list: impl FnMut(&Path),
) -> io::Result<Walk> {
    let mut out = Vec::new();
    let mut limits_hit = BudgetLimits::default();
    let mut unreadable: BTreeSet<PathBuf> = BTreeSet::new();
    let mut not_walked = NotWalked::default();
    // Every directory entry examined, across the whole walk — bounds breadth
    // (and, since each queued directory was itself one such entry, the stack)
    // so an all-empty-directory tree can't run unbounded past `max_files`.
    let mut entries_seen = 0usize;
    // Relative paths, not descriptors: the stack can hold `max_entries`
    // directories, so each is reopened beneath the anchor when popped.
    // Depth is measured relative to `root`, which sits at depth 0.
    let mut stack = vec![(PathBuf::new(), 0usize)];

    'walk: while let Some((rel, depth)) = stack.pop() {
        // Not `root.join("")`, which would add a trailing separator.
        let dir = if depth == 0 {
            root.to_path_buf()
        } else {
            root.join(&rel)
        };
        let listing = match anchor.list_dir(&rel) {
            Ok(list) => list,
            Err(e) => {
                if depth == 0 {
                    return Err(e);
                }
                unreadable.insert(dir);
                continue;
            }
        };

        for entry in listing {
            entries_seen += 1;
            if entries_seen > budget.max_entries {
                limits_hit.insert(BudgetLimit::Entries);
                break 'walk;
            }
            let (name, file_type) = match entry {
                Ok(e) => e,
                Err(_) => {
                    unreadable.insert(dir.clone());
                    continue;
                }
            };
            let child = rel.join(&name);

            match file_type {
                FileType::Directory => {
                    if recursive {
                        if depth < budget.max_depth {
                            stack.push((child, depth + 1));
                        } else {
                            limits_hit.insert(BudgetLimit::Depth);
                        }
                    } else {
                        not_walked.subdirs += 1;
                    }
                }
                FileType::RegularFile => {
                    if out.len() >= budget.max_files {
                        limits_hit.insert(BudgetLimit::Files);
                        break 'walk;
                    }
                    out.push(root.join(child));
                }
                other => {
                    not_walked.links_and_special += 1;
                    if other == FileType::Symlink
                        && points_outside(&root.join(child), anchor.path())
                    {
                        not_walked.links_outside += 1;
                    }
                }
            }
        }
        after_list(&rel);
    }

    out.sort();
    Ok(Walk {
        files: out,
        limits: limits_hit,
        unreadable: unreadable.into_iter().collect(),
        not_walked,
    })
}

/// Whether symlink `link` points outside `real_root` (a canonical path).
/// A link that won't resolve (dangling, looping, unreadable on the way) is
/// judged by its own text, read lexically from its real parent directory.
fn points_outside(link: &Path, real_root: &Path) -> bool {
    if let Ok(target) = link.canonicalize() {
        return !target.starts_with(real_root);
    }
    let (Ok(text), Some(Ok(parent))) = (
        std::fs::read_link(link),
        link.parent().map(Path::canonicalize),
    ) else {
        return true; // can't tell where it goes: don't call it inside
    };
    let mut resolved = PathBuf::new();
    for part in parent.join(text).components() {
        match part {
            std::path::Component::ParentDir => {
                resolved.pop();
            }
            std::path::Component::CurDir => {}
            other => resolved.push(other),
        }
    }
    !resolved.starts_with(real_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CoverageGap;
    use std::fs;

    /// A throwaway directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            // Timestamps alone collide across threads (macOS clocks are µs).
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let base = std::env::temp_dir().join(format!(
                "nav-target-{tag}-{}-{}-{:?}",
                std::process::id(),
                SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
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
    fn app_bundle_scores_every_member_except_a_plist_signature_manifest() {
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
            b"<?xml version=\"1.0\"?><plist/>",
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
            vec![
                "Contents/Info.plist",
                "Contents/MacOS/Widget",
                "Contents/Resources/Assets.car",
                "Contents/Resources/helper.sh"
            ]
        );

        let skipped: Vec<_> = scan
            .skipped
            .iter()
            .map(|p| p.strip_prefix(&app).unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(skipped, vec!["Contents/_CodeSignature/CodeResources"]);

        assert!(scan.primary_result().is_some());
    }

    #[test]
    fn non_plist_code_resources_is_scored() {
        let dir = TempDir::new("fake-manifest");
        let app = dir.path().join("Widget.app");
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::create_dir_all(app.join("Contents/_CodeSignature")).unwrap();
        fs::write(app.join("Contents/MacOS/Widget"), b"#!/bin/sh\necho hi\n").unwrap();
        fs::write(
            app.join("Contents/_CodeSignature/CodeResources"),
            b"#!/bin/sh\necho hi\n",
        )
        .unwrap();

        let scan = scan_target(&app, false).unwrap();
        assert!(scan.skipped.is_empty());
        assert!(scan
            .results
            .iter()
            .any(|r| r.path.ends_with("_CodeSignature/CodeResources")));
    }

    #[test]
    fn bundle_under_an_lproj_ancestor_still_scores_its_members() {
        let dir = TempDir::new("lproj-ancestor");
        let app = dir.path().join("x.lproj/Widget.app");
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::write(app.join("Contents/Info.plist"), b"<plist/>").unwrap();
        fs::write(app.join("Contents/MacOS/Widget"), b"#!/bin/sh\necho hi\n").unwrap();

        let scan = scan_target(&app, false).unwrap();
        assert_eq!(scan.kind, TargetKind::Bundle);
        assert_eq!(scan.results.len(), 2);
        assert!(scan.skipped.is_empty());
        assert!(scan
            .results
            .iter()
            .any(|r| r.path.ends_with("Contents/MacOS/Widget")));
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
        assert_eq!(
            scan.budget,
            BudgetOutcome::Exhausted(BudgetLimit::Files.into())
        );
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
        assert_eq!(
            scan.budget,
            BudgetOutcome::Exhausted(BudgetLimit::Depth.into())
        );
    }

    fn bytes_read_scanning(path: &Path) -> u64 {
        let ctx = ScanContext::load(path);
        scan_context(&ctx, &default_ruleset());
        ctx.bytes_read()
    }

    /// A Mach-O whose `__text` runs past the 8 MiB prefix is read twice past
    /// it (strings streams the file, entropy streams `__text`); the budget
    /// is charged both reads, not the file's length once (#53).
    #[test]
    fn total_bytes_charges_re_reads_not_file_length() {
        const MIB: usize = 1024 * 1024;
        let payload: Vec<u8> = (0..12 * MIB).map(|i| (i % 251) as u8).collect();
        let (image, _) = crate::macho::tests_support::synth_macho_64(&payload);
        let dir = TempDir::new("budget-reread");
        fs::write(dir.path().join("a"), &image).unwrap();
        fs::write(dir.path().join("b"), &image).unwrap();

        let len = image.len() as u64;
        let read = bytes_read_scanning(&dir.path().join("a"));
        assert!(read > len + 3 * MIB as u64, "{read}");

        // Both files fit when each is charged its length; the re-reads don't.
        let budget = ScanBudget {
            max_total_bytes: 2 * len + MIB as u64,
            ..ScanBudget::default()
        };
        let scan = scan_target_with_budget(dir.path(), true, &budget).unwrap();
        assert_eq!(scan.results.len(), 1);
        assert_eq!(
            scan.budget,
            BudgetOutcome::Exhausted(BudgetLimit::TotalBytes.into())
        );
    }

    /// The files under `dir` scanned within `budget`: results, limit, spent.
    fn scan_dir_within(
        dir: &Path,
        max_total_bytes: u64,
    ) -> (Vec<ScanResult>, Option<BudgetLimit>, u64) {
        let budget = ScanBudget {
            max_total_bytes,
            ..ScanBudget::default()
        };
        let anchor = Arc::new(ScanRoot::open(dir).unwrap());
        let walk = collect_files(&anchor, dir, true, &budget).unwrap();
        scan_within_bytes(&anchor, dir, &walk.files, &budget)
    }

    /// A file whose re-reads would pass the budget is cut at it: the reads
    /// it can't afford are refused, so the total never exceeds the budget
    /// and the file is not reported complete (§11.12, #104).
    #[test]
    fn a_file_is_cut_at_its_allowance_and_the_total_never_exceeds_the_budget() {
        const MIB: usize = 1024 * 1024;
        let payload: Vec<u8> = (0..12 * MIB).map(|i| (i % 251) as u8).collect();
        let (image, _) = crate::macho::tests_support::synth_macho_64(&payload);
        let dir = TempDir::new("budget-allowance");
        fs::write(dir.path().join("a"), &image).unwrap();
        fs::write(dir.path().join("b"), b"#!/bin/sh\necho hi\n").unwrap();
        let len = image.len() as u64;
        assert!(bytes_read_scanning(&dir.path().join("a")) > len + 3 * MIB as u64);

        for max in [100, MIB as u64, len, len + MIB as u64, len + 2 * MIB as u64] {
            let (results, limit, spent) = scan_dir_within(dir.path(), max);
            assert!(spent <= max, "{spent} > {max}");
            assert_eq!(limit, Some(BudgetLimit::TotalBytes), "{max}");
            assert_ne!(results[0].completeness, ScanCompleteness::Complete);
            assert!(results[0]
                .coverage_gaps
                .contains(&crate::model::CoverageGap::ByteBudget));
        }
    }

    /// With room for the tool's whole-file read gone, `codesign` is not run:
    /// its rules report not-applicable and the target the byte budget.
    #[test]
    fn a_tool_is_not_run_once_the_allowance_cannot_cover_the_file() {
        let (image, _) = crate::macho::tests_support::synth_macho_64(b"code");
        let dir = TempDir::new("budget-tool");
        fs::write(dir.path().join("a"), &image).unwrap();
        let len = image.len() as u64;
        let skipped = |r: &ScanResult| {
            r.coverage_gaps
                .contains(&crate::model::CoverageGap::RuleNotApplicable {
                    rule: "unsigned-binary".to_string(),
                })
        };

        let (results, limit, spent) = scan_dir_within(dir.path(), len + len / 2);
        assert!(spent <= len + len / 2);
        assert_eq!(limit, Some(BudgetLimit::TotalBytes));
        assert!(skipped(&results[0]));
        assert_ne!(results[0].completeness, ScanCompleteness::Complete);
        assert!(results[0]
            .coverage_gaps
            .contains(&crate::model::CoverageGap::ByteBudget));

        let (results, limit, _) = scan_dir_within(dir.path(), 4 * len);
        assert_eq!(limit, None);
        assert!(!results[0]
            .coverage_gaps
            .contains(&crate::model::CoverageGap::ByteBudget));
        // Off macOS the tool never runs, so the rule is not applicable anyway.
        #[cfg(target_os = "macos")]
        assert!(!skipped(&results[0]));
        let _ = results;
    }

    /// Zips small on disk whose members inflate far past their size stop the
    /// target at `TotalBytes` once the decoded bytes add up (#166).
    #[test]
    fn total_bytes_charges_decoded_container_bytes() {
        use crate::zip::tests_support::{plain, Spec};
        const MIB: usize = 1024 * 1024;
        let zip = plain(&[Spec::run("a.txt", b'a', MIB)]);
        assert!(zip.len() < 64 * 1024, "{}", zip.len());
        let dir = TempDir::new("budget-decoded");
        for name in ["a.zip", "b.zip", "c.zip", "d.zip"] {
            fs::write(dir.path().join(name), &zip).unwrap();
        }
        let ctx = ScanContext::load(&dir.path().join("a.zip"));
        scan_context(&ctx, &default_ruleset());
        assert_eq!(ctx.decoded_bytes(), MIB as u64);
        assert_eq!(ctx.bytes_read(), zip.len() as u64);

        let max = 5 * MIB as u64 / 2;
        let (results, limit, spent) = scan_dir_within(dir.path(), max);
        assert!(spent <= max, "{spent} > {max}");
        assert_eq!(limit, Some(BudgetLimit::TotalBytes));
        assert!(results.len() >= 3, "{}", results.len());
        // The third zip's decode is cut at its allowance, not finished.
        assert_ne!(results[2].completeness, ScanCompleteness::Complete);
    }

    /// A plain file decodes nothing: it is charged its reads alone.
    #[test]
    fn a_plain_file_is_charged_only_its_reads() {
        let dir = TempDir::new("budget-plain");
        let path = dir.path().join("a.sh");
        let script = b"#!/bin/sh\necho hi\n";
        fs::write(&path, script).unwrap();
        let ctx = ScanContext::load(&path);
        scan_context(&ctx, &default_ruleset());
        assert_eq!(ctx.decoded_bytes(), 0);
        assert_eq!(ctx.bytes_read(), script.len() as u64);
    }

    /// A non-Mach-O file over `MAX_STREAM_BYTES` is read only in its prefix:
    /// too big for suspicious-strings to stream, so it is charged that, not
    /// its length.
    #[test]
    fn a_large_non_macho_file_is_charged_only_what_was_read() {
        let dir = TempDir::new("budget-large-blob");
        let big = dir.path().join("a.bin");
        fs::File::create(&big)
            .unwrap()
            .set_len(MAX_STREAM_BYTES + 4096)
            .unwrap();
        let read = bytes_read_scanning(&big);
        assert!(read < 16 * 1024 * 1024, "{read}");
    }

    /// The walk stops at `max_files` and scoring then stops at the byte
    /// limit: both are reported (§11.12).
    #[test]
    fn files_and_bytes_reported() {
        let dir = TempDir::new("budget-both");
        for name in ["a.bin", "b.bin", "c.bin"] {
            fs::write(dir.path().join(name), vec![0u8; 4096]).unwrap();
        }
        let budget = ScanBudget {
            max_files: 2,
            max_total_bytes: 100,
            ..ScanBudget::default()
        };
        let scan = scan_target_with_budget(dir.path(), true, &budget).unwrap();
        assert_eq!(scan.results.len(), 1);
        assert_eq!(
            scan.budget,
            BudgetOutcome::Exhausted([BudgetLimit::Files, BudgetLimit::TotalBytes].into())
        );
    }

    /// A subdirectory past `max_depth` and a later `max_files` stop are both
    /// reported: the file stop doesn't overwrite the depth one.
    #[test]
    fn depth_and_files_reported() {
        let dir = TempDir::new("budget-depth-files");
        fs::create_dir(dir.path().join("a")).unwrap();
        fs::write(dir.path().join("a/deep.txt"), b"d").unwrap();
        for name in ["b.txt", "c.txt", "d.txt"] {
            fs::write(dir.path().join(name), b"x").unwrap();
        }
        let budget = ScanBudget {
            max_files: 2,
            max_depth: 0,
            ..ScanBudget::default()
        };
        let scan = scan_target_with_budget(dir.path(), true, &budget).unwrap();
        assert_eq!(scan.results.len(), 2);
        assert_eq!(
            scan.budget,
            BudgetOutcome::Exhausted([BudgetLimit::Files, BudgetLimit::Depth].into())
        );
    }

    /// Every limit hit is reported, collection-time and byte alike.
    #[test]
    fn every_limit_is_reported() {
        for fixed in [BudgetLimit::Depth, BudgetLimit::Entries] {
            let both = outcome(fixed.into(), Some(BudgetLimit::TotalBytes));
            assert_eq!(
                both,
                BudgetOutcome::Exhausted([fixed, BudgetLimit::TotalBytes].into())
            );
        }
        assert_eq!(
            outcome(BudgetLimits::default(), None),
            BudgetOutcome::Within
        );
    }

    #[test]
    fn limits_iterate_in_order() {
        let set: BudgetLimits = [BudgetLimit::Entries, BudgetLimit::Files].into();
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [BudgetLimit::Files, BudgetLimit::Entries]
        );
        assert!(!set.contains(BudgetLimit::Depth));
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
            BudgetOutcome::Exhausted(BudgetLimit::TotalBytes.into())
        );
    }

    #[test]
    fn empty_directory_breadth_is_bounded_by_the_entry_budget() {
        let dir = TempDir::new("budget-entries");
        // No files at all — just empty subdirectories, which score no files
        // and read no bytes, so only the entry ceiling can bound them.
        for i in 0..10 {
            fs::create_dir(dir.path().join(format!("d{i}"))).unwrap();
        }
        let budget = ScanBudget {
            max_entries: 3,
            ..ScanBudget::default()
        };
        let scan = scan_target_with_budget(dir.path(), true, &budget).unwrap();
        assert!(scan.results.is_empty());
        assert_eq!(
            scan.budget,
            BudgetOutcome::Exhausted(BudgetLimit::Entries.into())
        );
        assert!(!scan.coverage_complete());
    }

    #[test]
    fn directory_symlinks_are_not_followed() {
        let dir = TempDir::new("symlink");
        fs::create_dir(dir.path().join("real")).unwrap();
        fs::write(dir.path().join("real/x.txt"), b"x").unwrap();

        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        let scan = scan_target(dir.path(), true).unwrap();
        // "real/x.txt" once, not also via "link/x.txt".
        assert_eq!(scan.results.len(), 1);
        assert_eq!(scan.not_walked.links_and_special, 1);
        assert_eq!(scan.not_walked.links_outside, 0);
        assert!(scan.coverage_complete());
    }

    /// A link that points outside the target is counted apart (#159),
    /// dangling or not; a dangling link that stays inside is not.
    #[test]
    fn counts_links_outside() {
        use std::os::unix::fs::symlink;
        let outside = TempDir::new("outside");
        fs::write(outside.path().join("evil.sh"), b"x").unwrap();
        let dir = TempDir::new("links");
        fs::write(dir.path().join("a.txt"), b"x").unwrap();
        symlink("a.txt", dir.path().join("inside")).unwrap();
        symlink(outside.path().join("evil.sh"), dir.path().join("out")).unwrap();
        symlink("missing", dir.path().join("dangling")).unwrap();
        symlink(outside.path().join("gone"), dir.path().join("dangling-out")).unwrap();
        symlink("../../nowhere", dir.path().join("dangling-up")).unwrap();

        let scan = scan_target(dir.path(), false).unwrap();
        assert_eq!(scan.not_walked.links_and_special, 5);
        assert_eq!(scan.not_walked.links_outside, 3);
    }

    /// Without `recursive`, subdirectories are counted, not silently
    /// dropped, and the target is still complete (#159).
    #[test]
    fn counts_skipped_subdirs() {
        let dir = TempDir::new("nonrecursive");
        fs::write(dir.path().join("readme.txt"), b"x").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/evil.sh"), b"x").unwrap();
        fs::create_dir(dir.path().join("sub2")).unwrap();

        let scan = scan_target(dir.path(), false).unwrap();
        assert_eq!(scan.results.len(), 1);
        assert_eq!(scan.not_walked.subdirs, 2);
        assert!(scan.coverage_complete());

        let scan = scan_target(dir.path(), true).unwrap();
        assert_eq!(scan.results.len(), 2);
        assert_eq!(scan.not_walked, NotWalked::default());
    }

    /// A `chmod 000` subdirectory is recorded, not fatal: the rest of the
    /// target still scans and the target is reported partial (§11.8/§11.12).
    #[test]
    fn unreadable_subdirectory_is_recorded_and_traversal_continues() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("unreadable");
        fs::write(dir.path().join("readable.txt"), b"ok").unwrap();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join("inside.txt"), b"hidden").unwrap();

        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        // Some environments (root, certain CI containers) ignore directory
        // permission bits — skip rather than assert a bogus failure.
        if fs::read_dir(&locked).is_ok() {
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }

        let scan = scan_target(dir.path(), true);

        // Always restore permissions before the TempDir drops, regardless of
        // the outcome above, so cleanup can recurse into `locked`.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

        let scan = scan.unwrap();
        assert!(scan
            .results
            .iter()
            .any(|r| r.path.ends_with("readable.txt")));
        assert_eq!(scan.unreadable, vec![locked]);
        assert!(!scan.coverage_complete());
    }

    const DROPPER: &[u8] = include_bytes!("../fixtures/suspicious/dropper.sh");

    /// Walk `root`, run `swap` between the walk and the scan, then scan.
    fn scan_after(root: &Path, swap: impl FnOnce()) -> Vec<ScanResult> {
        let budget = ScanBudget::default();
        let anchor = Arc::new(ScanRoot::open(root).unwrap());
        let walk = collect_files(&anchor, root, true, &budget).unwrap();
        swap();
        scan_within_bytes(&anchor, root, &walk.files, &budget).0
    }

    /// The listed path's result: unreadable, and nothing from outside.
    fn assert_gap(results: &[ScanResult], name: &str) {
        let r = results.iter().find(|r| r.path.ends_with(name)).unwrap();
        assert!(r.coverage_gaps.contains(&CoverageGap::Unreadable), "{r:?}");
        assert_ne!(r.completeness, ScanCompleteness::Complete);
        assert_eq!(r.recommendation, Recommendation::NoAction);
        assert!(r.signals.iter().all(|s| s.weight == 0), "{r:?}");
    }

    /// A collected file swapped to a symlink before it is opened is a gap,
    /// not a read of the link's target (§11.7, §11.8).
    #[test]
    fn swapped_leaf_is_gap() {
        let (root, outside) = (TempDir::new("leaf-root"), TempDir::new("leaf-out"));
        fs::write(root.path().join("note.sh"), b"echo hi\n").unwrap();
        fs::write(outside.path().join("secret.sh"), DROPPER).unwrap();
        let results = scan_after(root.path(), || {
            let note = root.path().join("note.sh");
            fs::remove_file(&note).unwrap();
            std::os::unix::fs::symlink(outside.path().join("secret.sh"), note).unwrap();
        });
        assert_gap(&results, "note.sh");
    }

    /// A parent directory swapped to a symlink is a gap the same way.
    #[test]
    fn swapped_parent_is_gap() {
        let (root, outside) = (TempDir::new("parent-root"), TempDir::new("parent-out"));
        fs::create_dir(root.path().join("sub")).unwrap();
        fs::write(root.path().join("sub/note.sh"), b"echo hi\n").unwrap();
        fs::write(outside.path().join("note.sh"), DROPPER).unwrap();
        let results = scan_after(root.path(), || {
            let sub = root.path().join("sub");
            fs::rename(&sub, root.path().join("aside")).unwrap();
            std::os::unix::fs::symlink(outside.path(), sub).unwrap();
        });
        assert_gap(&results, "sub/note.sh");
    }

    /// A subdirectory swapped to a symlink after its parent is listed but
    /// before it is listed is unreadable; no outside name is collected (§11.7).
    #[test]
    fn swapped_dir_not_listed() {
        let (root, outside) = (TempDir::new("list-root"), TempDir::new("list-out"));
        fs::create_dir(root.path().join("sub")).unwrap();
        fs::write(root.path().join("sub/note.sh"), b"echo hi\n").unwrap();
        fs::write(outside.path().join("outside-only.sh"), DROPPER).unwrap();
        let anchor = ScanRoot::open(root.path()).unwrap();
        let sub = root.path().join("sub");
        let walk = walk_files(&anchor, root.path(), true, &ScanBudget::default(), |rel| {
            if rel.as_os_str().is_empty() {
                fs::rename(&sub, root.path().join("aside")).unwrap();
                std::os::unix::fs::symlink(outside.path(), &sub).unwrap();
            }
        })
        .unwrap();
        assert!(walk.files.is_empty(), "{:?}", walk.files);
        assert_eq!(walk.unreadable, vec![sub]);
    }

    /// A target named through a symlink, and a hard link inside it, scan in
    /// full: only components beneath the resolved root are refused.
    #[test]
    fn linked_root_scans_fully() {
        let (real, links) = (TempDir::new("linked-real"), TempDir::new("linked-via"));
        fs::create_dir_all(real.path().join("a/b")).unwrap();
        fs::write(real.path().join("a/b/drop.sh"), DROPPER).unwrap();
        fs::write(real.path().join("plain.txt"), b"hello\n").unwrap();
        fs::hard_link(real.path().join("a/b/drop.sh"), real.path().join("hard.sh")).unwrap();
        let via = links.path().join("root");
        std::os::unix::fs::symlink(real.path(), &via).unwrap();
        let scan = scan_target(&via, true).unwrap();
        assert!(scan.coverage_complete());
        assert_eq!(scan.results.len(), 3);
        for r in &scan.results {
            assert!(r.path.starts_with(&via), "{r:?}");
            assert!(!r.coverage_gaps.contains(&CoverageGap::Unreadable), "{r:?}");
        }
        for name in ["drop.sh", "hard.sh"] {
            let r = scan
                .results
                .iter()
                .find(|r| r.path.ends_with(name))
                .unwrap();
            assert_ne!(r.recommendation, Recommendation::NoAction, "{r:?}");
        }
    }
}
