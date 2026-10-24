//! Comparing two scans of the same corpus, keyed by path.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use nav_core::model::{Recommendation, ScanCompleteness, ScanResult};

const DEFAULT_LIST_CAP: usize = 200;

/// The compared projection of a [`ScanResult`]; ignores timestamps,
/// engine version and descriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub score: i32,
    pub recommendation: Recommendation,
    pub completeness: ScanCompleteness,
    /// Sorted `(signal id, weight)` multiset.
    pub signals: Vec<(String, i32)>,
}

impl Verdict {
    fn of(r: &ScanResult) -> Self {
        let mut signals: Vec<_> = r.signals.iter().map(|s| (s.id.clone(), s.weight)).collect();
        signals.sort();
        Self {
            score: r.score,
            recommendation: r.recommendation,
            completeness: r.completeness,
            signals,
        }
    }

    fn render(&self) -> String {
        let sigs: Vec<_> = self
            .signals
            .iter()
            .map(|(i, w)| format!("{i}:{w}"))
            .collect();
        format!(
            "{:>3} {} {} [{}]",
            self.score,
            rec_label(self.recommendation),
            comp_label(self.completeness),
            sigs.join(" ")
        )
    }
}

/// One path whose verdict differs (or is new and above no-action).
#[derive(Debug)]
pub struct Change {
    pub path: PathBuf,
    /// `None` for a path present only in NEW.
    pub base: Option<Verdict>,
    pub new: Verdict,
    pub rec_worse: bool,
    pub comp_worse: bool,
}

#[derive(Debug, Default)]
pub struct DiffReport {
    pub base_files: usize,
    pub new_files: usize,
    /// Paths NEW never reported (a crash, a skipped chunk); fails the gate.
    pub only_base: Vec<PathBuf>,
    /// Per target the walk budget cut short in both runs: `(target, paths
    /// missing from NEW, paths BASE scanned under it)`. Reported, not a failure.
    pub budget_cutoff: Vec<(PathBuf, usize, usize)>,
    pub only_new: usize,
    pub duplicates_base: usize,
    pub duplicates_new: usize,
    /// Per recommendation, `(base, new)` counts, indexed by [`rec_rank`].
    pub rec_counts: [(usize, usize); 3],
    /// Per completeness, `(base, new)` counts, indexed by [`comp_rank`].
    pub comp_counts: [(usize, usize); 3],
    /// `(rule id, base files, new files)` for rules whose count changed.
    pub rule_rows: Vec<(String, usize, usize)>,
    /// Worst first.
    pub changes: Vec<Change>,
}

/// Exit status for a failed gate; 1 is left for tool errors (`anyhow`).
pub const REGRESSION_EXIT: u8 = 2;

impl DiffReport {
    /// Paths whose recommendation or completeness got worse, including
    /// new-only paths above no-action.
    pub fn regressions(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| c.rec_worse || c.comp_worse)
            .count()
    }

    /// Whether the gate passes: something was scanned, nothing regressed,
    /// nothing went missing outside [`Self::budget_cutoff`].
    pub fn passed(&self) -> bool {
        self.base_files > 0 && self.regressions() == 0 && self.only_base.is_empty()
    }

    /// [`REGRESSION_EXIT`] unless [`passed`](Self::passed).
    pub fn exit_code(&self) -> ExitCode {
        if self.passed() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(REGRESSION_EXIT)
        }
    }
}

fn rec_rank(r: Recommendation) -> usize {
    match r {
        Recommendation::NoAction => 0,
        Recommendation::Notify => 1,
        Recommendation::NotifyAndSuggestQuarantine => 2,
    }
}

fn comp_rank(c: ScanCompleteness) -> usize {
    match c {
        ScanCompleteness::Complete => 0,
        ScanCompleteness::Partial => 1,
        ScanCompleteness::Indeterminate => 2,
    }
}

const REC_LABELS: [&str; 3] = ["no-action", "notify", "notify-and-suggest-quarantine"];
const COMP_LABELS: [&str; 3] = ["complete", "partial", "indeterminate"];

fn rec_label(r: Recommendation) -> &'static str {
    REC_LABELS[rec_rank(r)]
}

fn comp_label(c: ScanCompleteness) -> &'static str {
    COMP_LABELS[comp_rank(c)]
}

/// Keys results by path, keeping the last of any duplicates; returns the map
/// and the number of duplicate lines dropped.
fn index(results: &[ScanResult]) -> (BTreeMap<&PathBuf, Verdict>, usize) {
    let mut map = BTreeMap::new();
    let mut dups = 0;
    for r in results {
        if map.insert(&r.path, Verdict::of(r)).is_some() {
            dups += 1;
        }
    }
    (map, dups)
}

fn rule_counts(map: &BTreeMap<&PathBuf, Verdict>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for v in map.values() {
        let ids: BTreeSet<&str> = v.signals.iter().map(|(i, _)| i.as_str()).collect();
        for id in ids {
            *counts.entry(id.to_string()).or_insert(0) += 1;
        }
    }
    counts
}

/// Compares `base` against `new` by path. Pure; see the module docs for what
/// is compared.
pub fn diff(base: &[ScanResult], new: &[ScanResult]) -> DiffReport {
    let (b, duplicates_base) = index(base);
    let (n, duplicates_new) = index(new);
    let mut report = DiffReport {
        base_files: b.len(),
        new_files: n.len(),
        duplicates_base,
        duplicates_new,
        ..Default::default()
    };

    for v in b.values() {
        report.rec_counts[rec_rank(v.recommendation)].0 += 1;
        report.comp_counts[comp_rank(v.completeness)].0 += 1;
    }
    for v in n.values() {
        report.rec_counts[rec_rank(v.recommendation)].1 += 1;
        report.comp_counts[comp_rank(v.completeness)].1 += 1;
    }

    let (rb, rn) = (rule_counts(&b), rule_counts(&n));
    let ids: BTreeSet<&String> = rb.keys().chain(rn.keys()).collect();
    for id in ids {
        let (x, y) = (
            rb.get(id).copied().unwrap_or(0),
            rn.get(id).copied().unwrap_or(0),
        );
        if x != y {
            report.rule_rows.push((id.clone(), x, y));
        }
    }

    for (path, nv) in &n {
        match b.get(path) {
            Some(bv) if bv == nv => {}
            Some(bv) => report.changes.push(Change {
                path: (*path).clone(),
                base: Some(bv.clone()),
                new: nv.clone(),
                rec_worse: rec_rank(nv.recommendation) > rec_rank(bv.recommendation),
                comp_worse: nv.completeness > bv.completeness,
            }),
            None => {
                report.only_new += 1;
                if nv.recommendation != Recommendation::NoAction {
                    report.changes.push(Change {
                        path: (*path).clone(),
                        base: None,
                        new: nv.clone(),
                        rec_worse: true,
                        comp_worse: false,
                    });
                }
            }
        }
    }
    report.only_base = b
        .keys()
        .filter(|p| !n.contains_key(*p))
        .map(|p| (*p).clone())
        .collect();

    report.changes.sort_by(|x, y| {
        (y.rec_worse, y.comp_worse, y.new.score)
            .cmp(&(x.rec_worse, x.comp_worse, x.new.score))
            .then_with(|| x.path.cmp(&y.path))
    });
    report
}

/// Moves `only_base` paths under any of `stopped` (targets the walk budget
/// cut short in **both** runs) into `budget_cutoff`: there the set of files
/// reached depends on bytes read per file, so a missing file is not lost
/// coverage. Every other missing path still fails the gate.
pub fn excuse_budget_cutoffs(r: &mut DiffReport, base: &[ScanResult], stopped: &BTreeSet<PathBuf>) {
    let target_of = |p: &PathBuf| stopped.iter().find(|t| p.starts_with(t)).cloned();
    let mut missing: BTreeMap<PathBuf, usize> = BTreeMap::new();
    r.only_base.retain(|p| match target_of(p) {
        Some(t) => {
            *missing.entry(t).or_insert(0) += 1;
            false
        }
        None => true,
    });
    let mut scanned: BTreeMap<PathBuf, usize> = BTreeMap::new();
    for res in base {
        if let Some(t) = target_of(&res.path) {
            if missing.contains_key(&t) {
                *scanned.entry(t).or_insert(0) += 1;
            }
        }
    }
    r.budget_cutoff = missing
        .into_iter()
        .map(|(t, m)| {
            let of = scanned.get(&t).copied().unwrap_or(0);
            (t, m, of)
        })
        .collect();
}

/// Human-readable report; the changed-file list is capped at 200 lines
/// unless `all`.
pub fn render(r: &DiffReport, all: bool) -> String {
    let mut s = String::new();
    if r.base_files == 0 {
        let _ = writeln!(s, "FAIL: the base scan has no files; nothing was compared");
    }
    let _ = writeln!(
        s,
        "files: base {} new {} (only in base {}, only in new {})",
        r.base_files,
        r.new_files,
        r.only_base.len(),
        r.only_new
    );
    for (name, d) in [("base", r.duplicates_base), ("new", r.duplicates_new)] {
        if d > 0 {
            let _ = writeln!(s, "warning: {d} duplicate path(s) in {name}; kept the last");
        }
    }
    let _ = writeln!(s, "\nrecommendation (base -> new):");
    for (i, (b, n)) in r.rec_counts.iter().enumerate() {
        let _ = writeln!(s, "  {:<32} {b} -> {n}", REC_LABELS[i]);
    }
    let _ = writeln!(s, "\ncompleteness (base -> new):");
    for (i, (b, n)) in r.comp_counts.iter().enumerate() {
        let _ = writeln!(s, "  {:<32} {b} -> {n}", COMP_LABELS[i]);
    }
    if !r.rule_rows.is_empty() {
        let _ = writeln!(s, "\nfiles per rule, changed only (base -> new):");
        for (id, b, n) in &r.rule_rows {
            let _ = writeln!(s, "  {id:<40} {b} -> {n}");
        }
    }
    let _ = writeln!(
        s,
        "\nchanged files: {} ({} regression(s): recommendation or completeness worse)",
        r.changes.len(),
        r.regressions()
    );
    let cap = if all { usize::MAX } else { DEFAULT_LIST_CAP };
    if !r.budget_cutoff.is_empty() {
        let n: usize = r.budget_cutoff.iter().map(|(_, m, _)| m).sum();
        let _ = writeln!(
            s,
            "\nbudget cutoff moved: {n} file(s) not reached in new, under targets \
             the scan budget stopped in both runs (not a failure):"
        );
        for (t, m, of) in &r.budget_cutoff {
            let _ = writeln!(s, "  {m:>6} of {of:<6}  {}", t.display());
        }
    }
    if !r.only_base.is_empty() {
        let _ = writeln!(
            s,
            "\nmissing from new: {} (new build crashed or skipped them?)",
            r.only_base.len()
        );
        for p in r.only_base.iter().take(cap) {
            let _ = writeln!(s, "  {}", p.display());
        }
        if r.only_base.len() > cap {
            let _ = writeln!(s, "  ... {} more (use --all)", r.only_base.len() - cap);
        }
    }
    for c in r.changes.iter().take(cap) {
        let base = c
            .base
            .as_ref()
            .map_or_else(|| "(absent)".to_string(), Verdict::render);
        let _ = writeln!(s, "  {base} -> {}  {}", c.new.render(), c.path.display());
    }
    if r.changes.len() > cap {
        let _ = writeln!(s, "  ... {} more (use --all)", r.changes.len() - cap);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use nav_core::model::{EvidenceConfidence, MatchedSignal, SignalCategory};
    use std::time::SystemTime;

    fn sig(id: &str, weight: i32) -> MatchedSignal {
        MatchedSignal {
            id: id.into(),
            weight,
            description: format!("desc {weight}"),
            category: SignalCategory::Informational,
        }
    }

    fn res(
        path: &str,
        score: i32,
        rec: Recommendation,
        comp: ScanCompleteness,
        signals: &[(&str, i32)],
    ) -> ScanResult {
        ScanResult {
            path: path.into(),
            score,
            confidence: EvidenceConfidence::Low,
            completeness: comp,
            signals: signals.iter().map(|(i, w)| sig(i, *w)).collect(),
            recommendation: rec,
            engine_version: "e".into(),
            evaluated_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn clean(path: &str, score: i32) -> ScanResult {
        res(
            path,
            score,
            Recommendation::NoAction,
            ScanCompleteness::Complete,
            &[],
        )
    }

    #[test]
    fn unchanged_ignores_metadata() {
        let a = clean("/a", 1);
        let mut b = clean("/a", 1);
        b.engine_version = "other".into();
        b.evaluated_at = SystemTime::now();
        let r = diff(&[a], &[b]);
        assert!(r.changes.is_empty());
        assert_eq!(r.regressions(), 0);
        assert_eq!(r.exit_code(), ExitCode::SUCCESS);
    }

    #[test]
    fn score_change_is_listed_but_not_a_regression() {
        let r = diff(&[clean("/a", 1)], &[clean("/a", 4)]);
        assert_eq!(r.changes.len(), 1);
        assert_eq!(r.regressions(), 0);
        assert_eq!(r.exit_code(), ExitCode::SUCCESS);
    }

    #[test]
    fn worse_recommendation_is_a_regression() {
        let n = res(
            "/a",
            12,
            Recommendation::Notify,
            ScanCompleteness::Complete,
            &[],
        );
        let r = diff(&[clean("/a", 1)], &[n]);
        assert_eq!(r.regressions(), 1);
        assert_eq!(r.exit_code(), ExitCode::from(REGRESSION_EXIT));
        assert_eq!(r.rec_counts[1], (0, 1));
    }

    #[test]
    fn improved_recommendation_is_not_a_regression() {
        let b = res(
            "/a",
            12,
            Recommendation::Notify,
            ScanCompleteness::Complete,
            &[],
        );
        let r = diff(&[b], &[clean("/a", 1)]);
        assert_eq!(r.changes.len(), 1);
        assert_eq!(r.regressions(), 0);
    }

    #[test]
    fn new_only_notify_is_a_regression_but_new_only_clean_is_not() {
        let n = res(
            "/n",
            12,
            Recommendation::Notify,
            ScanCompleteness::Complete,
            &[],
        );
        let r = diff(&[], &[n, clean("/c", 0)]);
        assert_eq!(r.only_new, 2);
        assert_eq!(r.changes.len(), 1);
        assert_eq!(r.regressions(), 1);
        assert!(render(&r, false).contains("(absent)"));
    }

    #[test]
    fn only_in_base_fails_the_gate() {
        let r = diff(
            &[clean("/gone", 0), clean("/kept", 0)],
            &[clean("/kept", 0)],
        );
        assert_eq!(r.only_base, vec![PathBuf::from("/gone")]);
        assert_eq!(r.regressions(), 0);
        assert_eq!(r.exit_code(), ExitCode::from(REGRESSION_EXIT));
        assert!(render(&r, false).contains("missing from new: 1"));
    }

    #[test]
    fn completeness_change_is_detected_and_ranked_worse() {
        let n = res(
            "/a",
            1,
            Recommendation::NoAction,
            ScanCompleteness::Partial,
            &[],
        );
        let r = diff(&[clean("/a", 1)], &[n]);
        assert_eq!(r.changes.len(), 1);
        assert!(r.changes[0].comp_worse);
        assert_eq!(r.regressions(), 1);
        assert!(!r.passed());
        assert_eq!(r.comp_counts[1], (0, 1));
    }

    #[test]
    fn missing_files_under_a_budget_stopped_target_do_not_fail_the_gate() {
        let base = [clean("/A/X.app/a", 0), clean("/A/X.app/b", 0)];
        let mut r = diff(&base, &[clean("/A/X.app/a", 0)]);
        assert!(!r.passed());
        excuse_budget_cutoffs(&mut r, &base, &BTreeSet::from([PathBuf::from("/A/X.app")]));
        assert!(r.passed());
        assert_eq!(r.budget_cutoff, vec![(PathBuf::from("/A/X.app"), 1, 2)]);
        let text = render(&r, false);
        assert!(text.contains("budget cutoff moved: 1 file(s)"), "{text}");
        assert!(text.contains("1 of 2"), "{text}");
    }

    #[test]
    fn missing_files_elsewhere_still_fail_the_gate() {
        // `/A/X.app2` only shares a string prefix with the stopped target.
        let base = [clean("/A/X.app2/a", 0), clean("/B/c", 0)];
        let mut r = diff(&base, &[]);
        excuse_budget_cutoffs(&mut r, &base, &BTreeSet::from([PathBuf::from("/A/X.app")]));
        assert!(!r.passed());
        assert_eq!(r.only_base.len(), 2);
        assert!(r.budget_cutoff.is_empty());
    }

    #[test]
    fn empty_base_fails_the_gate() {
        let r = diff(&[], &[]);
        assert!(!r.passed());
        assert!(render(&r, false).contains("no files"));
    }

    #[test]
    fn signal_set_change_with_same_score() {
        let mk = |sigs: &[(&str, i32)]| {
            res(
                "/a",
                5,
                Recommendation::NoAction,
                ScanCompleteness::Complete,
                sigs,
            )
        };
        let r = diff(&[mk(&[("x", 2), ("y", 3)])], &[mk(&[("x", 3), ("z", 2)])]);
        assert_eq!(r.changes.len(), 1);
        assert_eq!(r.rule_rows, vec![("y".into(), 1, 0), ("z".into(), 0, 1)]);
        // Order of signals must not matter.
        let r = diff(&[mk(&[("x", 2), ("y", 3)])], &[mk(&[("y", 3), ("x", 2)])]);
        assert!(r.changes.is_empty());
    }

    #[test]
    fn duplicate_paths_keep_last_and_warn() {
        let r = diff(&[clean("/a", 1), clean("/a", 2)], &[clean("/a", 2)]);
        assert_eq!(r.base_files, 1);
        assert_eq!(r.duplicates_base, 1);
        assert!(r.changes.is_empty());
        assert!(render(&r, false).contains("duplicate"));
    }

    #[test]
    fn changes_sorted_worst_first_and_capped() {
        let notify = res(
            "/z",
            12,
            Recommendation::Notify,
            ScanCompleteness::Complete,
            &[],
        );
        let base: Vec<_> = (0..300).map(|i| clean(&format!("/f{i:03}"), 0)).collect();
        let mut new: Vec<_> = (0..300).map(|i| clean(&format!("/f{i:03}"), 1)).collect();
        new.push(notify);
        let r = diff(&base, &new);
        assert_eq!(r.changes[0].path, PathBuf::from("/z"));
        let capped = render(&r, false);
        assert!(capped.contains("more (use --all)"));
        assert!(!render(&r, true).contains("more (use --all)"));
    }
}
