//! Splitting scan roots into navctl invocations that fit its 50,000-file
//! walk budget, mirroring navctl's own traversal rules (target.rs).

use std::fs;
use std::path::{Path, PathBuf};

/// One navctl invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub path: PathBuf,
    /// `scan --recursive` over a directory (or `.app` bundle) vs a single file.
    pub recursive: bool,
}

#[derive(Debug, Default)]
pub struct Plan {
    pub chunks: Vec<Chunk>,
    /// Human-readable notes: skipped roots/dirs, oversize bundles.
    pub notes: Vec<String>,
}

/// Plans scans for `roots`. A root is followed even if it is a symlink
/// (navctl follows the named target); symlinks met while walking are skipped.
/// Directories with `split_at` files or more are split into their children;
/// an `.app` bundle is never split.
pub fn plan(roots: &[PathBuf], split_at: usize) -> Plan {
    let mut plan = Plan::default();
    for root in roots {
        match fs::metadata(root) {
            Ok(m) if m.is_file() => plan.chunks.push(Chunk {
                path: root.clone(),
                recursive: false,
            }),
            Ok(m) if m.is_dir() => plan_dir(root, split_at, &mut plan),
            Ok(_) => plan.notes.push(format!(
                "skipped {}: not a file or directory",
                root.display()
            )),
            Err(e) => plan.notes.push(format!("skipped {}: {e}", root.display())),
        }
    }
    plan
}

fn plan_dir(dir: &Path, split_at: usize, plan: &mut Plan) {
    let count = count_files(dir, split_at);
    if is_bundle(dir) {
        if count >= split_at {
            plan.notes.push(format!(
                "{} is a bundle with at least {split_at} files; scanned whole",
                dir.display()
            ));
        }
        plan.chunks.push(Chunk {
            path: dir.to_path_buf(),
            recursive: true,
        });
        return;
    }
    if count == 0 {
        plan.notes
            .push(format!("skipped {}: no files", dir.display()));
        return;
    }
    if count < split_at {
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
    for child in children {
        let Ok(ft) = child.file_type() else { continue };
        if ft.is_file() {
            plan.chunks.push(Chunk {
                path: child.path(),
                recursive: false,
            });
        } else if ft.is_dir() {
            plan_dir(&child.path(), split_at, plan);
        }
    }
}

/// Mirrors `BundleLayout::detect`: a directory named `*.app` with a
/// `Contents/` directory.
fn is_bundle(dir: &Path) -> bool {
    dir.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().ends_with(".app"))
        && dir.join("Contents").is_dir()
}

/// Regular files under `dir` (symlinks not followed), counting stops once
/// `limit` is reached.
fn count_files(dir: &Path, limit: usize) -> usize {
    let mut count = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for entry in rd.filter_map(Result::ok) {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_file() {
                count += 1;
                if count >= limit {
                    return count;
                }
            } else if ft.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default();
            let p =
                std::env::temp_dir().join(format!("nav-xtask-plan-{}-{nanos}", std::process::id()));
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
        assert!(got.contains(&(t.0.join("big/f0"), false)));
        assert!(got.contains(&(t.0.join("big/f1"), false)));
        assert!(got.contains(&(t.0.join("big/a"), true)));
        // b itself has 6 files (>= 3): split again.
        assert!(!got.contains(&(t.0.join("big/b"), true)));
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
        assert_eq!(count_files(&top, 100), 1);
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
