//! False-positive evaluation harness (§11.1). Known-benign and
//! synthetic-suspicious fixtures under `fixtures/`, checked against the
//! engine's output. Grow it by adding files or `.app` dirs under
//! `fixtures/benign/` or `fixtures/suspicious/` — no code changes, but a
//! new or changed fixture requires regenerating the golden snapshot below
//! (`UPDATE_GOLDEN=1 cargo test -p nav-core --test fp_harness`) and
//! committing the result.
//!
//! Guards against: a rule change pushing a benign sample over the alert
//! threshold, making scoring nondeterministic, or (via the golden snapshot)
//! silently changing a fixture's score, recommendation, or fired rule ids.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Only the macOS-gated golden-snapshot test uses BTreeMap; an unconditional
// import is dead code off-macOS and trips clippy's `-D warnings`.
#[cfg(target_os = "macos")]
use std::collections::BTreeMap;

use nav_core::{scan_target, Recommendation, ScanCompleteness, TargetScan};

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

/// Sorted, deduplicated union of rule ids fired anywhere in a target scan —
/// for a single-file target this is just that file's signals; for a
/// directory/`.app` target it's the union across every scanned member.
fn fired_rule_ids(scan: &TargetScan) -> Vec<String> {
    let mut ids: Vec<String> = scan
        .results
        .iter()
        .flat_map(|r| r.signals.iter().map(|s| s.id.clone()))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// `sub/filename` — the golden file's key and the metrics report's label for
/// a fixture.
fn fixture_key(sub: &str, path: &Path) -> String {
    format!("{sub}/{}", path.file_name().unwrap().to_string_lossy())
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

/// Per-fixture and aggregate scan metrics, reported for visibility (§11.1:
/// "track more than pass/fail: final score, matched rule IDs, runtime,
/// memory, files traversed"). Nothing here is asserted — runtime is
/// environment-dependent and would flake CI; the golden-snapshot test below
/// is the actual pass/fail gate on score/recommendation/rule_ids. Run with
/// `cargo test -p nav-core --test fp_harness report_fixture_metrics -- --nocapture`
/// to see the table.
///
/// TODO(§11.1): peak memory isn't tracked. A global-allocator hook would
/// double as a per-fixture counter, but cargo's test harness runs every
/// `#[test]` fn as a thread in one shared process with one allocator
/// instance, so counts would mix in whatever else is allocating
/// concurrently — a misattributed number is worse than an honestly absent
/// one, so this is deferred rather than faked.
#[test]
fn report_fixture_metrics() {
    let mut total_files = 0usize;
    let mut total_runtime = Duration::ZERO;

    println!();
    println!("{:-<95}", "");
    println!(
        "{:<40} {:>7} {:>7} {:>10}  rule_ids",
        "fixture", "score", "files", "runtime"
    );
    println!("{:-<95}", "");

    for sub in ["benign", "suspicious"] {
        for path in list_fixtures(sub) {
            let start = Instant::now();
            let result = scan(&path);
            let elapsed = start.elapsed();

            let files_traversed = result.results.len() + result.skipped.len();
            let score = result.worst().map(|r| r.score).unwrap_or(0);
            let rule_ids = fired_rule_ids(&result);

            total_files += files_traversed;
            total_runtime += elapsed;

            println!(
                "{:<40} {:>7} {:>7} {:>8.2}ms  {}",
                fixture_key(sub, &path),
                score,
                files_traversed,
                elapsed.as_secs_f64() * 1000.0,
                if rule_ids.is_empty() {
                    "-".to_string()
                } else {
                    rule_ids.join(",")
                },
            );
        }
    }

    println!("{:-<95}", "");
    println!(
        "total: files_traversed={total_files} runtime={:.2}ms memory=not yet tracked (see TODO above)",
        total_runtime.as_secs_f64() * 1000.0
    );
    println!();
}

/// The quantitative Phase 0a acceptance gate (§11.1, NAV-015). Turns "low
/// false-positive rate is the primary success metric" (§1, §12 go/no-go) from
/// a stated priority into a measured, asserted number, and reports the rest of
/// the corpus shape (detection coverage, verdict mix, completeness, runtime
/// percentiles) alongside it. Two things are asserted, both corpus-size
/// independent:
///   * benign false-positive rate is exactly 0 — no known-good fixture alerts;
///   * suspicious signal coverage is 100% — every deliberately-suspicious
///     fixture produces at least one signal (a silent miss is a gate failure).
///
/// Runtime percentiles are reported, never asserted (environment-dependent,
/// would flake CI). Peak memory stays honestly untracked — see the TODO on
/// `report_fixture_metrics`; a misattributed number is worse than an absent one.
#[test]
fn false_positive_gate_and_corpus_metrics() {
    let mut benign_total = 0usize;
    let mut benign_alerts = 0usize;
    let mut suspicious_total = 0usize;
    let mut suspicious_with_signal = 0usize;
    let mut high_risk = 0usize;
    let mut notify = 0usize;
    let mut incomplete = 0usize;
    let mut runtimes: Vec<Duration> = Vec::new();

    for sub in ["benign", "suspicious"] {
        for path in list_fixtures(sub) {
            let start = Instant::now();
            let result = scan(&path);
            runtimes.push(start.elapsed());

            let alerted = result.recommendation() != Recommendation::NoAction;
            let has_signal = result.results.iter().any(|r| !r.signals.is_empty());
            // "Couldn't fully examine it" is tracked separately from the verdict
            // (§11.8): the worst member's completeness, or budget coverage.
            let complete = result.coverage_complete()
                && result
                    .worst()
                    .is_none_or(|r| r.completeness == ScanCompleteness::Complete);
            if !complete {
                incomplete += 1;
            }

            match sub {
                "benign" => {
                    benign_total += 1;
                    if alerted {
                        benign_alerts += 1;
                    }
                }
                _ => {
                    suspicious_total += 1;
                    if has_signal {
                        suspicious_with_signal += 1;
                    }
                    match result.recommendation() {
                        Recommendation::NotifyAndSuggestQuarantine => high_risk += 1,
                        Recommendation::Notify => notify += 1,
                        Recommendation::NoAction => {}
                    }
                }
            }
        }
    }

    let fp_rate = benign_alerts as f64 / benign_total.max(1) as f64;
    let coverage = suspicious_with_signal as f64 / suspicious_total.max(1) as f64;
    let (p50, p95) = runtime_percentiles(&mut runtimes);

    println!();
    println!("{:-<72}", "");
    println!("Phase 0a false-positive acceptance gate (§11.1)");
    println!("{:-<72}", "");
    println!("benign fixtures:        {benign_total}");
    println!("benign alerts:          {benign_alerts}");
    println!(
        "false-positive rate:    {:.1}%   (gate: 0%)",
        fp_rate * 100.0
    );
    println!("suspicious fixtures:    {suspicious_total}");
    println!(
        "  with >=1 signal:      {suspicious_with_signal}  ({:.1}% coverage, gate: 100%)",
        coverage * 100.0
    );
    println!("  high-risk (quarant.): {high_risk}");
    println!("  notify:               {notify}");
    println!(
        "partial/indeterminate:  {incomplete} of {} fixtures",
        benign_total + suspicious_total
    );
    println!(
        "runtime per fixture:    p50={:.2}ms  p95={:.2}ms",
        p50.as_secs_f64() * 1000.0,
        p95.as_secs_f64() * 1000.0
    );
    println!("peak memory:            not tracked (see report_fixture_metrics TODO)");
    println!("{:-<72}", "");
    println!();

    assert_eq!(
        benign_alerts,
        0,
        "false-positive gate: {benign_alerts} of {benign_total} benign fixtures alerted \
         (FP rate {:.1}%). Low false-positive rate is Phase 0a's primary success metric \
         (§1/§12) — a benign sample crossing the alert threshold fails the gate.",
        fp_rate * 100.0
    );
    assert_eq!(
        suspicious_with_signal, suspicious_total,
        "coverage gate: only {suspicious_with_signal} of {suspicious_total} suspicious fixtures \
         produced a signal — a deliberately-suspicious sample was scored silently clean."
    );
}

/// (p50, p95) of `runtimes`, sorted in place. Nearest-rank, clamped — reported
/// only, so exactness past that doesn't matter.
fn runtime_percentiles(runtimes: &mut [Duration]) -> (Duration, Duration) {
    if runtimes.is_empty() {
        return (Duration::ZERO, Duration::ZERO);
    }
    runtimes.sort_unstable();
    let pick = |pct: f64| {
        let idx = ((pct * runtimes.len() as f64).ceil() as usize)
            .saturating_sub(1)
            .min(runtimes.len() - 1);
        runtimes[idx]
    };
    (pick(0.50), pick(0.95))
}

/// The deterministic, platform-stable fields snapshotted per fixture for the
/// golden-file regression gate: everything the engine promises is stable
/// across a run on a given platform, and nothing that varies with wall-clock
/// time or engine version (see `ScanResult::evaluated_at`/`engine_version`,
/// deliberately excluded).
///
/// For a directory/`.app` target this is the target-level verdict — the
/// worst scanned member's score/recommendation, via
/// `TargetScan::recommendation`/`worst` — plus the sorted union of rule ids
/// fired across every scanned member. For a single-file target this
/// collapses to that one file's own score/recommendation/signals.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct FixtureSnapshot {
    score: i32,
    recommendation: Recommendation,
    rule_ids: Vec<String>,
}

#[cfg(target_os = "macos")]
impl FixtureSnapshot {
    fn of(scan: &TargetScan) -> Self {
        Self {
            score: scan.worst().map(|r| r.score).unwrap_or(0),
            recommendation: scan.recommendation(),
            rule_ids: fired_rule_ids(scan),
        }
    }
}

#[cfg(target_os = "macos")]
fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("fp_snapshot.json")
}

/// Golden-snapshot regression gate (§11.1). Compares every fixture's
/// [`FixtureSnapshot`] against a committed golden file and fails with a
/// per-fixture expected-vs-actual diff on any mismatch — this is what
/// catches a rule change silently altering a known-benign sample's score,
/// or introducing an unexpectedly high-severity signal.
///
/// Gated to macOS: off-macOS the codesign/spctl rules return
/// `RuleOutcome::NotApplicable` (scanner.md §5.2), so scans come back
/// `Partial` rather than `Complete`, and Mach-O/`.app`/`.pkg` fixtures would
/// snapshot differently than on the real target platform (roadmap.md §12
/// treats a golden-file format as Phase 0a scaffolding, on the assumption
/// it's evaluated where NAV actually runs). The three tests above stay
/// cross-platform since they don't depend on exact scores.
///
/// To regenerate after an intentional rule change, review the resulting
/// `git diff` before committing:
/// ```sh
/// UPDATE_GOLDEN=1 cargo test -p nav-core --test fp_harness
/// ```
#[cfg(target_os = "macos")]
#[test]
fn golden_snapshot_matches_known_fixtures() {
    let mut actual: BTreeMap<String, FixtureSnapshot> = BTreeMap::new();
    for sub in ["benign", "suspicious"] {
        for path in list_fixtures(sub) {
            let key = fixture_key(sub, &path);
            actual.insert(key, FixtureSnapshot::of(&scan(&path)));
        }
    }

    let path = golden_path();

    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        let json = serde_json::to_string_pretty(&actual).unwrap() + "\n";
        std::fs::write(&path, json)
            .unwrap_or_else(|e| panic!("failed to write golden file {}: {e}", path.display()));
        println!("wrote golden file: {}", path.display());
        return;
    }

    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read golden file {}: {e}\nGenerate it with: \
             UPDATE_GOLDEN=1 cargo test -p nav-core --test fp_harness",
            path.display()
        )
    });
    let expected: BTreeMap<String, FixtureSnapshot> = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse golden file {}: {e}", path.display()));

    let mut diffs = Vec::new();
    for (key, actual_snap) in &actual {
        match expected.get(key) {
            Some(expected_snap) if expected_snap == actual_snap => {}
            Some(expected_snap) => diffs.push(format!(
                "{key}:\n  expected: score={} recommendation={:?} rule_ids={:?}\n  actual:   score={} recommendation={:?} rule_ids={:?}",
                expected_snap.score,
                expected_snap.recommendation,
                expected_snap.rule_ids,
                actual_snap.score,
                actual_snap.recommendation,
                actual_snap.rule_ids,
            )),
            None => diffs.push(format!("{key}: new fixture, missing from golden file")),
        }
    }
    for key in expected.keys() {
        if !actual.contains_key(key) {
            diffs.push(format!(
                "{key}: present in golden file but no longer scanned (fixture renamed or removed?)"
            ));
        }
    }

    assert!(
        diffs.is_empty(),
        "golden snapshot mismatch — a rule change altered a known fixture's score, \
         recommendation, or fired rule ids, or a fixture was added/renamed/removed without \
         regenerating the golden file. If this is intended, regenerate with \
         `UPDATE_GOLDEN=1 cargo test -p nav-core --test fp_harness`, review the diff, and \
         commit the result.\n\n{}",
        diffs.join("\n\n")
    );
}
