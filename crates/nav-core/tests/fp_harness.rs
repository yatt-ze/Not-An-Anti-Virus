//! False-positive evaluation harness (§11.1). Known-benign and
//! synthetic-suspicious fixtures under `fixtures/`, checked against the
//! engine's output. Grow it by adding files or `.app` dirs under
//! `fixtures/benign/` or `fixtures/suspicious/` — no code changes.
//!
//! Guards against: a rule change pushing a benign sample over the alert
//! threshold, or making scoring nondeterministic.

use std::path::{Path, PathBuf};

use nav_core::{scan_target, Recommendation, TargetScan};

fn fixtures_dir(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(sub)
}

/// A fixture is a plain file or an `.app` bundle directory (other dirs just
/// contain bundle fixtures).
fn is_fixture(path: &Path) -> bool {
    if path.is_file() {
        return true;
    }
    path.is_dir()
        && path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.to_ascii_lowercase().ends_with(".app"))
}

fn list_fixtures(sub: &str) -> Vec<PathBuf> {
    let dir = fixtures_dir(sub);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("failed to read fixtures dir {}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| is_fixture(p))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "expected at least one fixture under {}",
        dir.display()
    );
    files
}

fn scan(path: &Path) -> TargetScan {
    scan_target(path, false)
        .unwrap_or_else(|e| panic!("failed to scan fixture {}: {e}", path.display()))
}

#[test]
fn benign_fixtures_never_alert() {
    for path in list_fixtures("benign") {
        let result = scan(&path);
        assert_eq!(
            result.recommendation(),
            Recommendation::NoAction,
            "benign fixture {} triggered {:?} — a rule regression pushed a known-good sample \
             over the alert threshold. Worst file: {:#?}",
            path.display(),
            result.recommendation(),
            result.worst(),
        );
    }
}

#[test]
fn suspicious_fixtures_are_never_silently_clean() {
    for path in list_fixtures("suspicious") {
        let result = scan(&path);
        let any_signal = result.results.iter().any(|r| !r.signals.is_empty());
        assert!(
            any_signal || result.recommendation() != Recommendation::NoAction,
            "synthetic-suspicious fixture {} produced no signals at all — the scanner failed \
             to notice content that was deliberately constructed to be suspicious.",
            path.display(),
        );
    }
}

#[test]
fn scoring_is_deterministic() {
    // Run every fixture twice; require identical signal sets and scores (§11.1).
    for sub in ["benign", "suspicious"] {
        for path in list_fixtures(sub) {
            let a = scan(&path);
            let b = scan(&path);

            let ids = |t: &TargetScan| -> Vec<(PathBuf, i32, Vec<String>)> {
                t.results
                    .iter()
                    .map(|r| {
                        (
                            r.path.clone(),
                            r.score,
                            r.signals.iter().map(|s| s.id.clone()).collect(),
                        )
                    })
                    .collect()
            };

            assert_eq!(
                a.recommendation(),
                b.recommendation(),
                "nondeterministic recommendation for {}",
                path.display()
            );
            assert_eq!(
                ids(&a),
                ids(&b),
                "nondeterministic per-file signal set for {}",
                path.display()
            );
        }
    }
}
