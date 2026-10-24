//! Splitting scan roots into navctl invocations that fit its walk budget
//! (file count and bytes read), mirroring navctl's traversal rules (target.rs).

use std::fs;
use std::path::{Path, PathBuf};

use nav_core::context::MAX_STREAM_BYTES;
use nav_core::{BundleLayout, ScanBudget};

/// One navctl invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub path: PathBuf,
    /// `scan --recursive` over a directory or bundle; otherwise one file, or
    /// a directory's top-level files only.
    pub recursive: bool,
}

#[derive(Debug, Default)]
pub struct Plan {
    pub chunks: Vec<Chunk>,
    /// Human-readable notes: skipped roots/dirs, oversize bundles.
    pub notes: Vec<String>,
}

/// Files and budget-charged bytes under a directory, possibly stopped early.
#[derive(Debug, Clone, Copy, Default)]
struct Size {
    files: usize,
    bytes: u64,
}

/// Split thresholds: `split_at` files, or 7/8 of navctl's byte budget.
#[derive(Debug, Clone, Copy)]
struct Limits {
    files: usize,
    bytes: u64,
}

impl Limits {
    fn new(split_at: usize) -> Self {
        Self {
            files: split_at,
            bytes: ScanBudget::default().max_total_bytes / 8 * 7,
        }
    }

    fn fits(&self, s: Size) -> bool {
        s.files < self.files && s.bytes < self.bytes
    }
}

/// Bytes navctl charges a file against its budget (its length, clipped).
fn charged(len: u64) -> u64 {
    len.min(MAX_STREAM_BYTES)
}

/// Plans scans for `roots`. A root is followed even if it is a symlink
/// (navctl follows the named target); symlinks met while walking are skipped.
/// Directories over `split_at` files or the byte limit are split into their
/// children; an `.app` bundle is never split.
pub fn plan(roots: &[PathBuf], split_at: usize) -> Plan {
    plan_with(roots, Limits::new(split_at))
}

fn plan_with(roots: &[PathBuf], limits: Limits) -> Plan {
    let mut plan = Plan::default();
    for root in roots {
        match fs::metadata(root) {
            Ok(m) if m.is_file() => plan.chunks.push(Chunk {
                path: root.clone(),
                recursive: false,
            }),
            Ok(m) if m.is_dir() => plan_dir(root, limits, &mut plan),
            Ok(_) => plan.notes.push(format!(
                "skipped {}: not a file or directory",
                root.display()
            )),
            Err(e) => plan.notes.push(format!("skipped {}: {e}", root.display())),
        }
    }
    plan
}

fn plan_dir(dir: &Path, limits: Limits, plan: &mut Plan) {
    let size = measure(dir, limits);
    if BundleLayout::detect(dir).is_some() {
        if !limits.fits(size) {
            plan.notes.push(format!(
                "{} is a bundle over the split limit; scanned whole",
                dir.display()
            ));
        }
        plan.chunks.push(Chunk {
            path: dir.to_path_buf(),
            recursive: true,
        });
        return;
    }
    if size.files == 0 {
        plan.notes
            .push(format!("skipped {}: no files", dir.display()));
        return;
    }
    if limits.fits(size) {
        plan.chunks.push(Chunk {
            path: dir.to_path_buf(),
            recursive: true,
        });
        return;
    }
    let mut children: Vec<_> = match fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(Result::ok).collect(),
        Err(e) => {
            plan.notes.push(format!("skipped {}: {e}", dir.display()));
            return;
        }
    };
    children.sort_by_key(|e| e.file_name());
    let mut loose = Vec::new();
    let mut loose_size = Size::default();
    for child in children {
        let Ok(ft) = child.file_type() else { continue };
        if ft.is_file() {
            loose_size.files += 1;
            loose_size.bytes += child.metadata().map_or(0, |m| charged(m.len()));
            loose.push(child.path());
        } else if ft.is_dir() {
            plan_dir(&child.path(), limits, plan);
        }
    }
    if loose.is_empty() {
        return;
    }
    if limits.fits(loose_size) {
        // A non-recursive directory scan covers just its top-level files.
        plan.chunks.push(Chunk {
            path: dir.to_path_buf(),
            recursive: false,
        });
    } else {
        plan.chunks.extend(loose.into_iter().map(|path| Chunk {
            path,
            recursive: false,
        }));
    }
}

/// Regular files under `dir` and their charged bytes (symlinks not
/// followed); stops early once `limits` no longer fit.
fn measure(dir: &Path, limits: Limits) -> Size {
    let mut size = Size::default();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for entry in rd.filter_map(Result::ok) {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_file() {
                size.files += 1;
                size.bytes += entry.metadata().map_or(0, |m| charged(m.len()));
                if !limits.fits(size) {
                    return size;
                }
            } else if ft.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    size
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            // Parallel tests can read the same clock tick (macOS has µs
            // resolution), so a per-process counter keeps the names apart.
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default();
            let p = std::env::temp_dir()
                .join(format!("nav-xtask-plan-{}-{nanos}-{n}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        fn files(&self, rel: &str, n: usize) -> PathBuf {
            let d = self.0.join(rel);
            fs::create_dir_all(&d).unwrap();
            for i in 0..n {
                fs::write(d.join(format!("f{i}")), b"x").unwrap();
            }
            d
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn paths(p: &Plan) -> Vec<(PathBuf, bool)> {
        p.chunks
            .iter()
            .map(|c| (c.path.clone(), c.recursive))
            .collect()
    }

    #[test]
    fn small_dir_is_one_recursive_chunk() {
        let t = Tmp::new();
        t.files("small", 2);
        let p = plan(&[t.0.join("small")], 3);
        assert_eq!(paths(&p), vec![(t.0.join("small"), true)]);
    }

    #[test]
    fn large_dir_splits_into_files_and_subdirs() {
        let t = Tmp::new();
        t.files("big", 2);
        t.files("big/a", 1);
        t.files("big/b", 5);
        t.files("big/b/deep", 1);
        let p = plan(&[t.0.join("big")], 3);
        let got = paths(&p);
        // big's 2 loose files fit: one top-level-only scan of big.
        assert!(got.contains(&(t.0.join("big"), false)));
        assert!(!got.contains(&(t.0.join("big/f0"), false)));
        assert!(got.contains(&(t.0.join("big/a"), true)));
        // b has 6 files (>= 3): split again; its 5 loose files don't fit
        // one chunk, so each is scanned alone.
        assert!(!got.contains(&(t.0.join("big/b"), true)));
        assert!(!got.contains(&(t.0.join("big/b"), false)));
        assert!(got.contains(&(t.0.join("big/b/deep"), true)));
        assert!(got.contains(&(t.0.join("big/b/f4"), false)));
        assert!(!got.contains(&(t.0.join("big"), true)));
    }

    #[test]
    fn bundle_is_never_split() {
        let t = Tmp::new();
        t.files("apps/Big.app/Contents/Resources", 10);
        t.files("apps/other", 1);
        let p = plan(&[t.0.join("apps")], 3);
        let got = paths(&p);
        assert!(got.contains(&(t.0.join("apps/Big.app"), true)));
        assert!(got.contains(&(t.0.join("apps/other"), true)));
        assert!(!got
            .iter()
            .any(|(p, _)| p.starts_with(t.0.join("apps/Big.app/Contents"))));
        assert!(p.notes.iter().any(|n| n.contains("Big.app")));
    }

    #[test]
    fn app_without_contents_is_a_plain_directory() {
        let t = Tmp::new();
        t.files("apps/Fake.app/a", 2);
        t.files("apps/other", 2);
        let p = plan(&[t.0.join("apps")], 3);
        assert!(!paths(&p).contains(&(t.0.join("apps/Fake.app/a"), true)));
        assert!(paths(&p).contains(&(t.0.join("apps/Fake.app"), true)));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_mid_walk_but_followed_as_root() {
        use std::os::unix::fs::symlink;
        let t = Tmp::new();
        let real = t.files("real", 4);
        let top = t.files("top", 1);
        symlink(&real, top.join("dirlink")).unwrap();
        symlink(top.join("f0"), top.join("filelink")).unwrap();
        // Links don't count toward the threshold nor become chunks.
        let roomy = Limits {
            files: 100,
            bytes: u64::MAX,
        };
        assert_eq!(measure(&top, roomy).files, 1);
        let p = plan(std::slice::from_ref(&top), 100);
        assert_eq!(paths(&p), vec![(top.clone(), true)]);
        let split = plan(std::slice::from_ref(&top), 1);
        assert_eq!(paths(&split), vec![(top.join("f0"), false)]);

        // A symlink named as a root is followed.
        let root_link = t.0.join("rootlink");
        symlink(&real, &root_link).unwrap();
        let p = plan(std::slice::from_ref(&root_link), 100);
        assert_eq!(paths(&p), vec![(root_link, true)]);
    }

    #[test]
    fn byte_limit_splits_a_dir_under_the_file_limit() {
        let t = Tmp::new();
        for sub in ["d/a", "d/b"] {
            fs::create_dir_all(t.0.join(sub)).unwrap();
            fs::write(t.0.join(sub).join("blob"), [0u8; 6]).unwrap();
        }
        let limits = Limits {
            files: 100,
            bytes: 10,
        };
        let p = plan_with(&[t.0.join("d")], limits);
        assert_eq!(
            paths(&p),
            vec![(t.0.join("d/a"), true), (t.0.join("d/b"), true)]
        );
    }

    #[test]
    fn missing_roots_and_empty_dirs_are_noted() {
        let t = Tmp::new();
        fs::create_dir_all(t.0.join("empty")).unwrap();
        let p = plan(&[t.0.join("nope"), t.0.join("empty")], 3);
        assert!(p.chunks.is_empty());
        assert_eq!(p.notes.len(), 2);
    }

    #[test]
    fn file_root_is_a_single_file_chunk() {
        let t = Tmp::new();
        t.files("d", 1);
        let p = plan(&[t.0.join("d/f0")], 3);
        assert_eq!(paths(&p), vec![(t.0.join("d/f0"), false)]);
    }
}
