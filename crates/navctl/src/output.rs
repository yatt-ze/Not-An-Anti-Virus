//! Human and `--json` rendering for `scan` / `rules test` / `rules list`.
//!
//! `--json` mirrors the human structure — both render the same
//! `nav_core::ScanResult` (§5.5), plus a top-level `schema_version` marking
//! the JSON as a versioned contract (§8), via the shared envelope in
//! `nav_core::presentation`.
//! `scan` prints one terse line per file, except a `.app` bundle, which gets
//! one line for the bundle (per-file lines with `--verbose`);
//! `rules test` prints the worst file's full breakdown plus a roll-up.
//! A disk image is mounted and rendered like a bundle (§6.2,
//! [`crate::diskimage`]).

use std::path::{Path, PathBuf};

use nav_core::model::lossy_path;
use std::process::ExitCode;

use nav_core::{
    not_walked_notes, scan_target_with_budget, with_schema_version, BudgetLimit, BudgetOutcome,
    CoverageGap, EvidenceConfidence, Recommendation, ScanBudget, ScanCompleteness, ScanResult,
    TargetKind, TargetScan, SCAN_JSON_SCHEMA_VERSION, UNINSPECTED_CONTAINER_ID,
};

use crate::diskimage::{self, ImageReport, ImageScan};
use crate::exit;

/// What to do with the named target after trying to mount it.
enum Prepared {
    /// Scan it the usual way; `Some(reason)` when it is a disk image that
    /// was not mounted.
    Plain(Option<String>),
    Image(ImageReport),
    Done(ExitCode),
}

/// `announce`: also print the not-mounted reason to stderr (human output;
/// `--json` carries it as a coverage gap instead).
fn prepare(path: &Path, budget: &ScanBudget, no_mount: bool, announce: bool) -> Prepared {
    if no_mount {
        return Prepared::Plain(Some("--no-mount".into()));
    }
    match diskimage::scan_image(path, budget) {
        ImageScan::NotImage => Prepared::Plain(None),
        ImageScan::Unmounted(reason) => {
            if announce {
                nav_core::safe_eprintln!(
                    "navctl: {}: disk image not mounted: {reason}",
                    path.display()
                );
            }
            Prepared::Plain(Some(reason))
        }
        ImageScan::Scanned(report) => Prepared::Image(report),
        ImageScan::Interrupted { signal, released } => {
            let mounts = if released {
                "scratch mounts detached"
            } else {
                "warning: scratch mounts may still be attached"
            };
            nav_core::safe_eprintln!("navctl: {}: scan interrupted; {mounts}", path.display());
            Prepared::Done(exit::code(128u8.saturating_add(signal as u8)))
        }
    }
}

pub fn run_scan(
    path: &Path,
    recursive: bool,
    json: bool,
    verbose: bool,
    budget: &ScanBudget,
    no_mount: bool,
) -> ExitCode {
    let unmounted = match prepare(path, budget, no_mount, !json) {
        Prepared::Plain(reason) => reason,
        Prepared::Image(report) => return render_image_scan(&report, json, verbose),
        Prepared::Done(code) => return code,
    };
    let mut scan = match scan_target_with_budget(path, recursive, budget) {
        Ok(s) => s,
        Err(e) => {
            nav_core::safe_eprintln!("navctl: {}: {e}", path.display());
            return exit::code(exit::OPERATIONAL_ERROR);
        }
    };
    note_unmounted(&mut scan, unmounted.as_deref());

    if scan.results.is_empty() {
        if let Some(note) = unreadable_note(&scan) {
            nav_core::safe_eprintln!("{note}");
        }
        if let Some(note) = budget_warning(&scan, path) {
            nav_core::safe_eprintln!("{note}");
        }
        print_not_walked(&scan, verbose || scan.kind != TargetKind::Bundle);
        if json {
            if let Err(e) = print_scan_summary_json(&scan, None) {
                return json_error(&e);
            }
        }
        nav_core::safe_eprintln!("navctl: no files found under {}", path.display());
        return exit::code(empty_scan_exit_code(&scan));
    }

    let bundle_line = !json && scan.kind == TargetKind::Bundle;
    for result in &scan.results {
        if json {
            match with_schema_version(result) {
                Ok(v) => nav_core::raw_println!("{v}"),
                Err(e) => return json_error(&e),
            }
        } else if !bundle_line || verbose {
            print_scan_summary(result);
        }
    }
    if bundle_line {
        nav_core::safe_println!("{}", bundle_summary_line(&scan));
    }
    if json && scan.kind != TargetKind::File {
        if let Err(e) = print_scan_summary_json(&scan, None) {
            return json_error(&e);
        }
    }
    // Budget-exhausted coverage goes to stderr too, and is folded into the
    // exit code below — a target cut short is not a clean target
    // (§8, §11.8/§11.12).
    if let Some(note) = budget_warning(&scan, path) {
        nav_core::safe_eprintln!("{note}");
    }
    if !json {
        for note in uninspected_notes(&scan.results) {
            nav_core::safe_eprintln!("{note}");
        }
    }
    if let Some(note) = unreadable_note(&scan) {
        nav_core::safe_eprintln!("{note}");
    }
    print_not_walked(&scan, verbose || scan.kind != TargetKind::Bundle);
    exit::code(exit::for_target(&scan))
}

pub fn run_rules_test(
    path: &Path,
    recursive: bool,
    json: bool,
    budget: &ScanBudget,
    no_mount: bool,
) -> ExitCode {
    if !path.exists() {
        nav_core::safe_eprintln!("navctl: {} does not exist", path.display());
        return exit::code(exit::OPERATIONAL_ERROR);
    }
    let unmounted = match prepare(path, budget, no_mount, !json) {
        Prepared::Plain(reason) => reason,
        Prepared::Image(report) => return render_image_rules_test(&report, json),
        Prepared::Done(code) => return code,
    };

    let mut scan = match scan_target_with_budget(path, recursive, budget) {
        Ok(s) => s,
        Err(e) => {
            nav_core::safe_eprintln!("navctl: {}: {e}", path.display());
            return exit::code(exit::OPERATIONAL_ERROR);
        }
    };
    note_unmounted(&mut scan, unmounted.as_deref());

    // Single-file target: one full breakdown.
    if scan.kind == TargetKind::File {
        let result = &scan.results[0];
        if json {
            match with_schema_version(result).and_then(|v| serde_json::to_string_pretty(&v)) {
                Ok(s) => nav_core::raw_println!("{s}"),
                Err(e) => return json_error(&e),
            }
        } else {
            print_rules_test(result);
        }
        return exit::code(exit::for_result(result));
    }

    if scan.results.is_empty() {
        // Nothing readable — "couldn't check", not "clean" (§10, §11.8).
        let notes: Vec<String> = unreadable_note(&scan)
            .into_iter()
            .chain(budget_warning(&scan, path))
            .collect();
        for note in &notes {
            nav_core::safe_eprintln!("{note}");
        }
        print_not_walked(&scan, true);
        // Unreadable directories and a budget stop are structured data
        // (§11.12), so `--json` gets the multi-target envelope (empty
        // `results`, `coverage_complete: false`). `print_rules_test_multi`
        // needs a non-empty `results` to pick a worst file from.
        if json && !notes.is_empty() {
            return match print_multi_json(&scan, None) {
                Ok(()) => exit::code(exit::INDETERMINATE),
                Err(e) => json_error(&e),
            };
        }
        nav_core::safe_eprintln!("navctl: no files to scan under {}", path.display());
        return exit::code(exit::INDETERMINATE);
    }

    if json {
        if let Err(e) = print_multi_json(&scan, None) {
            return json_error(&e);
        }
    } else {
        print_rules_test_multi(&scan, None);
    }

    exit::code(exit::for_target(&scan))
}

/// Records `reason` as a coverage gap on a single-file target that carries
/// the disk-image `uninspected-container` signal, so `--json` says why it was
/// not mounted (§6.2, §8).
fn note_unmounted(scan: &mut TargetScan, reason: Option<&str>) {
    let (Some(reason), [result]) = (reason, scan.results.as_mut_slice()) else {
        return;
    };
    let is_image = result
        .signals
        .iter()
        .any(|s| s.id == UNINSPECTED_CONTAINER_ID && s.description.starts_with("disk image ("));
    if is_image {
        result.coverage_gaps.push(CoverageGap::NotMounted {
            reason: reason.to_string(),
        });
    }
}

/// `navctl scan` for a mounted image: one line, member lines with
/// `--verbose`; with `--json`, one object per member then the summary.
fn render_image_scan(report: &ImageReport, json: bool, verbose: bool) -> ExitCode {
    let scan = &report.scan;
    for result in &scan.results {
        if json {
            match with_schema_version(result) {
                Ok(v) => nav_core::raw_println!("{v}"),
                Err(e) => return json_error(&e),
            }
        } else if verbose {
            print_scan_summary(result);
        }
    }
    if scan.results.is_empty() {
        nav_core::safe_eprintln!("navctl: no files found in {}", scan.root.display());
    } else if !json {
        nav_core::safe_println!("{}", image_summary_line(report));
    }
    if json {
        if let Err(e) = print_scan_summary_json(scan, Some(report)) {
            return json_error(&e);
        }
    }
    print_image_warnings(report, !json, verbose);
    exit::code(image_exit_code(report))
}

/// `navctl rules test` for a mounted image: the bundle breakdown, or the
/// multi-target JSON envelope.
fn render_image_rules_test(report: &ImageReport, json: bool) -> ExitCode {
    let scan = &report.scan;
    if json {
        if let Err(e) = print_multi_json(scan, Some(report)) {
            return json_error(&e);
        }
    } else if scan.results.is_empty() {
        nav_core::safe_eprintln!("navctl: no files found in {}", scan.root.display());
    } else {
        print_rules_test_multi(scan, Some(report));
    }
    print_image_warnings(report, false, true);
    exit::code(image_exit_code(report))
}

/// Stderr notes for a mounted image: mount gaps, budget, unreadable
/// directories, (with `nested`) uninspected members, and skipped entries
/// (internal links only with `all_links`).
fn print_image_warnings(report: &ImageReport, nested: bool, all_links: bool) {
    let scan = &report.scan;
    for gap in &report.gaps {
        nav_core::safe_eprintln!("navctl: partial coverage — {}: {gap}", scan.root.display());
    }
    if let Some(note) = budget_warning(scan, &scan.root) {
        nav_core::safe_eprintln!("{note}");
    }
    if nested {
        for note in uninspected_notes(&scan.results) {
            nav_core::safe_eprintln!("{note}");
        }
    }
    if let Some(note) = unreadable_note(scan) {
        nav_core::safe_eprintln!("{note}");
    }
    print_not_walked(scan, all_links);
}

/// [`not_walked_notes`] on stderr, one `navctl:` line each.
fn print_not_walked(scan: &TargetScan, all_links: bool) {
    for note in not_walked_notes(scan, all_links) {
        nav_core::safe_eprintln!("navctl: {note}");
    }
}

/// [`exit::for_target`], raised from clean to indeterminate by a mount gap
/// or an image with no files.
fn image_exit_code(report: &ImageReport) -> u8 {
    let code = exit::for_target(&report.scan);
    let incomplete = !report.gaps.is_empty() || report.scan.results.is_empty();
    if code == exit::CLEAN && incomplete {
        exit::INDETERMINATE
    } else {
        code
    }
}

/// One line for a mounted image, as [`bundle_summary_line`] for a bundle.
fn image_summary_line(report: &ImageReport) -> String {
    unit_summary_line(
        &report.scan,
        "disk image",
        report.gaps.is_empty(),
        |p: &Path| image_member(&report.scan.root, p),
    )
}

/// A member label `<image>!path` shortened to `<image file name>!path`.
fn image_member(image: &Path, label: &Path) -> String {
    let label = label.display().to_string();
    let full = image.display().to_string();
    let name = image
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| full.clone());
    match label.strip_prefix(&full) {
        Some(rest) => format!("{name}{rest}"),
        None => label,
    }
}

pub fn run_rules_list() -> ExitCode {
    for rule in nav_core::default_ruleset() {
        nav_core::safe_println!("{:<28} {:?}", rule.id(), rule.category());
    }
    exit::code(exit::CLEAN)
}

fn print_scan_summary(result: &ScanResult) {
    nav_core::safe_println!(
        "{}",
        summary_line(
            &result.path.display().to_string(),
            result.score,
            result.confidence,
            result.completeness,
            result.recommendation,
        )
    );
}

fn summary_line(
    path: &str,
    score: i32,
    confidence: EvidenceConfidence,
    completeness: ScanCompleteness,
    recommendation: Recommendation,
) -> String {
    format!(
        "{path}  score={:<4} confidence={:<6} completeness={:<13} -> {}",
        score,
        confidence_str(confidence),
        completeness_str(completeness),
        recommendation_str(recommendation, completeness),
    )
}

/// `worst`'s completeness, raised to `Partial` when it was `Complete` but
/// `scan`'s coverage (or, with `covered` false, something outside it) was
/// not. `worst` must be `scan.worst()`.
fn target_completeness(scan: &TargetScan, worst: &ScanResult, covered: bool) -> ScanCompleteness {
    match worst.completeness {
        ScanCompleteness::Complete if !(covered && scan.coverage_complete()) => {
            ScanCompleteness::Partial
        }
        c => c,
    }
}

/// One line for a bundle: the worst file's verdict plus a file-count suffix.
/// Precondition: `scan.results` is non-empty.
fn bundle_summary_line(scan: &TargetScan) -> String {
    unit_summary_line(scan, "bundle", true, |p: &Path| {
        display_relative(&scan.root, p)
    })
}

/// [`bundle_summary_line`] for any one-unit target: `unit` names it in the
/// suffix, `covered` false forces `Partial`, `member` renders the worst path.
fn unit_summary_line(
    scan: &TargetScan,
    unit: &str,
    covered: bool,
    member: impl Fn(&Path) -> String,
) -> String {
    let worst = scan.worst().expect("non-empty results");
    let completeness = target_completeness(scan, worst, covered);
    let line = summary_line(
        &scan.root.display().to_string(),
        worst.score,
        worst.confidence,
        completeness,
        worst.recommendation,
    );
    let n = scan.results.len();
    // `worst()` ranks by severity then score, so this holds for every member.
    let all_clean = worst.completeness == ScanCompleteness::Complete
        && worst.recommendation == Recommendation::NoAction
        && worst.score <= 0;
    if all_clean {
        return format!("{line}  ({unit}: {n} files)");
    }
    let star = if scan.primary.as_deref() == Some(worst.path.as_path()) {
        "*"
    } else {
        ""
    };
    format!(
        "{line}  ({unit}: {n} files; worst: {}{star})",
        member(&worst.path)
    )
}

/// One `<indent>- <gap>` line per `result.coverage_gaps` entry; none for a
/// `Complete` result.
fn gap_lines<'a>(result: &'a ScanResult, indent: &'a str) -> impl Iterator<Item = String> + 'a {
    result
        .coverage_gaps
        .iter()
        .map(move |gap| format!("{indent}- {gap}"))
}

fn print_rules_test(result: &ScanResult) {
    nav_core::safe_println!("Threat score:        {}", result.score);
    nav_core::safe_println!("Evidence confidence: {}", confidence_str(result.confidence));
    nav_core::safe_println!(
        "Scan completeness:   {}",
        completeness_str(result.completeness)
    );
    for line in gap_lines(result, "  ") {
        nav_core::safe_println!("{line}");
    }
    nav_core::safe_println!();

    if result.signals.is_empty() {
        nav_core::safe_println!("Signals matched: (none)");
    } else {
        nav_core::safe_println!("Signals matched:");
        for s in &result.signals {
            nav_core::safe_println!("  [{:+4}] {:<28} {}", s.weight, s.id, s.description);
        }
    }
    nav_core::safe_println!();
    nav_core::safe_println!(
        "Recommendation: {}",
        recommendation_str(result.recommendation, result.completeness)
    );
}

/// Directory / bundle breakdown: full detail for the worst file, a
/// one-line-per-file roll-up, then the target verdict (the worst file's —
/// scores are never summed).
fn print_rules_test_multi(scan: &TargetScan, image: Option<&ImageReport>) {
    let worst = scan.worst().expect("non-empty results");
    let member = |p: &Path| match image {
        Some(_) => image_member(&scan.root, p),
        None => display_relative(&scan.root, p),
    };

    if let Some(report) = image {
        nav_core::safe_println!("Disk image: {}", scan.root.display());
        nav_core::safe_println!("Volumes scanned: {}", report.volumes);
        nav_core::safe_println!("Files scanned: {}", scan.results.len());
        for gap in &report.gaps {
            nav_core::safe_println!("  [PARTIAL COVERAGE: {gap}]");
        }
    } else if scan.kind == TargetKind::Bundle {
        nav_core::safe_println!("Bundle: {}", scan.root.display());
        match &scan.primary {
            Some(p) => {
                nav_core::safe_println!("Main executable: {}", display_relative(&scan.root, p))
            }
            None => nav_core::safe_println!(
                "Main executable: (could not resolve — scanned all members)"
            ),
        }
        nav_core::safe_print!("Files scanned: {}", scan.results.len());
        if !scan.skipped.is_empty() {
            nav_core::safe_print!(" ({} signature manifest(s) not scored)", scan.skipped.len());
        }
        nav_core::safe_println!();
    } else {
        nav_core::safe_println!(
            "Target: {} ({} files scanned)",
            scan.root.display(),
            scan.results.len()
        );
    }
    if let Some(note) = budget_note(scan) {
        nav_core::safe_println!("{note}");
    }
    if let Some(note) = unreadable_coverage_note(scan) {
        nav_core::safe_println!("{note}");
    }
    for note in not_walked_notes(scan, true) {
        nav_core::safe_println!("  [{note}]");
    }
    nav_core::safe_println!();
    nav_core::safe_println!("Worst finding — {}", member(&worst.path));
    nav_core::safe_println!("  Threat score:        {}", worst.score);
    nav_core::safe_println!(
        "  Evidence confidence: {}",
        confidence_str(worst.confidence)
    );
    nav_core::safe_println!(
        "  Scan completeness:   {}",
        completeness_str(worst.completeness)
    );
    for line in gap_lines(worst, "    ") {
        nav_core::safe_println!("{line}");
    }
    if worst.signals.is_empty() {
        nav_core::safe_println!("  Signals matched: (none)");
    } else {
        nav_core::safe_println!("  Signals matched:");
        for s in &worst.signals {
            nav_core::safe_println!("    [{:+4}] {:<28} {}", s.weight, s.id, s.description);
        }
    }
    nav_core::safe_println!();

    nav_core::safe_println!("All files:");
    for result in &scan.results {
        let marker = if scan.primary.as_deref() == Some(result.path.as_path()) {
            "  *"
        } else {
            "   "
        };
        nav_core::safe_println!(
            "{marker} {:<48} score={:<4} completeness={:<13} -> {}",
            member(&result.path),
            result.score,
            completeness_str(result.completeness),
            recommendation_str(result.recommendation, result.completeness),
        );
        for line in gap_lines(result, "        ") {
            nav_core::safe_println!("{line}");
        }
    }
    if scan.primary.is_some() {
        nav_core::safe_println!("  (* = bundle main executable)");
    }
    nav_core::safe_println!();
    let covered = image.map_or(true, |r| r.gaps.is_empty());
    nav_core::safe_println!(
        "Recommendation: {}",
        recommendation_str(
            worst.recommendation,
            target_completeness(scan, worst, covered)
        )
    );
}

/// Report a JSON serialization failure as an operational error (§8).
fn json_error(e: &serde_json::Error) -> ExitCode {
    nav_core::safe_eprintln!("navctl: cannot serialize JSON output: {e}");
    exit::code(exit::OPERATIONAL_ERROR)
}

fn print_multi_json(
    scan: &TargetScan,
    image: Option<&ImageReport>,
) -> Result<(), serde_json::Error> {
    nav_core::raw_println!(
        "{}",
        serde_json::to_string_pretty(&multi_json(scan, image)?)?
    );
    Ok(())
}

/// Print the final `scan --json` line: [`scan_summary_json`] on one line.
fn print_scan_summary_json(
    scan: &TargetScan,
    image: Option<&ImageReport>,
) -> Result<(), serde_json::Error> {
    nav_core::raw_println!("{}", scan_summary_json(scan, image)?);
    Ok(())
}

/// The `scan --json` target summary: [`target_json`] plus `files`, the
/// number of per-file lines before it. Only this line has a top-level `kind` key.
fn scan_summary_json(
    scan: &TargetScan,
    image: Option<&ImageReport>,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut v = target_json(scan, image)?;
    if let serde_json::Value::Object(map) = &mut v {
        map.insert("files".into(), scan.results.len().into());
    }
    Ok(v)
}

/// The multi-target `rules test --json` envelope: [`target_json`] plus
/// `results`.
fn multi_json(
    scan: &TargetScan,
    image: Option<&ImageReport>,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut v = target_json(scan, image)?;
    if let serde_json::Value::Object(map) = &mut v {
        map.insert("results".into(), serde_json::to_value(&scan.results)?);
    }
    Ok(v)
}

/// Target-level coverage fields, without per-file results. An image adds
/// `volumes` and `mount_gaps`, which also clear `coverage_complete`.
fn target_json(
    scan: &TargetScan,
    image: Option<&ImageReport>,
) -> Result<serde_json::Value, serde_json::Error> {
    let kind = match (image, scan.kind) {
        (Some(_), _) => "disk-image",
        (None, TargetKind::Bundle) => "bundle",
        _ => "directory",
    };
    let gaps_ok = image.map_or(true, |r| r.gaps.is_empty());
    let paths = |ps: &[PathBuf]| ps.iter().map(lossy_path::to_value).collect::<Vec<_>>();
    let mut v = serde_json::json!({
        "schema_version": SCAN_JSON_SCHEMA_VERSION,
        "target": lossy_path::to_value(&scan.root),
        "kind": kind,
        "primary": scan.primary.as_ref().map(lossy_path::to_value),
        "skipped_resources": paths(&scan.skipped),
        "coverage_complete": scan.coverage_complete() && gaps_ok,
        "budget_limit": budget_limit_str(scan),
        "unreadable": paths(&scan.unreadable),
        "subdirs_not_entered": scan.not_walked.subdirs,
        "links_and_special_not_followed": scan.not_walked.links_and_special,
        "links_outside_target": scan.not_walked.links_outside,
        "recommendation": serde_json::to_value(scan.recommendation())?,
    });
    if let (Some(report), serde_json::Value::Object(map)) = (image, &mut v) {
        map.insert("volumes".into(), report.volumes.into());
        map.insert("mount_gaps".into(), report.gaps.clone().into());
    }
    Ok(v)
}

/// A human-readable warning when a scan budget cut the target short, or `None`
/// when the whole target was covered. Coverage that stops short is surfaced,
/// never silently dropped (§11.8).
fn budget_note(scan: &TargetScan) -> Option<String> {
    match scan.budget {
        BudgetOutcome::Within => None,
        BudgetOutcome::Exhausted(limit) => Some(format!(
            "  [PARTIAL COVERAGE: scan budget reached ({}) — more of this target was not scanned]",
            budget_limit_label(limit)
        )),
    }
}

/// Exit code for a `scan` target that scored no files: `INDETERMINATE` when
/// unreadable directories or a budget stop explain the emptiness ("couldn't
/// check", §10/§11.8), `OPERATIONAL_ERROR` otherwise (issue #29).
fn empty_scan_exit_code(scan: &TargetScan) -> u8 {
    if scan.coverage_complete() {
        exit::OPERATIONAL_ERROR
    } else {
        exit::INDETERMINATE
    }
}

/// The stderr partial-coverage warning for a budget stop, or `None` if the
/// scan fit its budget (§11.12).
fn budget_warning(scan: &TargetScan, path: &Path) -> Option<String> {
    match scan.budget {
        BudgetOutcome::Exhausted(limit) => Some(format!(
            "navctl: partial coverage — scan budget reached ({}); more of {} was not scanned",
            budget_limit_label(limit),
            path.display()
        )),
        BudgetOutcome::Within => None,
    }
}

/// A stderr warning naming directories that couldn't be read during
/// traversal, or `None` when there were none. Traversal continues past each
/// one (§11.8); their presence is what makes the target's coverage partial
/// (§11.12).
fn unreadable_note(scan: &TargetScan) -> Option<String> {
    if scan.unreadable.is_empty() {
        return None;
    }
    let paths = scan
        .unreadable
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "navctl: partial coverage — {} director(ies) could not be read under {}: {}",
        scan.unreadable.len(),
        scan.root.display(),
        paths
    ))
}

/// One stderr line per result carrying the `uninspected-container` signal
/// (§10, §11.8), so a human sees why a clean-looking score exits 3.
fn uninspected_notes(results: &[ScanResult]) -> Vec<String> {
    results
        .iter()
        .flat_map(|r| {
            r.signals
                .iter()
                .filter(|s| s.id == UNINSPECTED_CONTAINER_ID)
                .map(|s| format!("navctl: {}: {}", r.path.display(), s.description))
        })
        .collect()
}

/// Human-output counterpart to [`unreadable_note`], formatted like
/// [`budget_note`] for `rules test`'s multi-file breakdown.
fn unreadable_coverage_note(scan: &TargetScan) -> Option<String> {
    if scan.unreadable.is_empty() {
        return None;
    }
    let paths = scan
        .unreadable
        .iter()
        .map(|p| display_relative(&scan.root, p))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "  [PARTIAL COVERAGE: {} director(ies) could not be read under {}: {}]",
        scan.unreadable.len(),
        scan.root.display(),
        paths
    ))
}

/// Machine-readable budget-limit tag for `--json`, or `None` if within budget.
fn budget_limit_str(scan: &TargetScan) -> Option<&'static str> {
    match scan.budget {
        BudgetOutcome::Within => None,
        BudgetOutcome::Exhausted(limit) => Some(budget_limit_label(limit)),
    }
}

fn budget_limit_label(limit: BudgetLimit) -> &'static str {
    match limit {
        BudgetLimit::Files => "max-files",
        BudgetLimit::TotalBytes => "max-total-bytes",
        BudgetLimit::Depth => "max-depth",
        BudgetLimit::Entries => "max-entries",
    }
}

/// Render `path` relative to `root` when it sits under it, for compact output.
fn display_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

fn confidence_str(c: EvidenceConfidence) -> &'static str {
    match c {
        EvidenceConfidence::Low => "Low",
        EvidenceConfidence::Medium => "Medium",
        EvidenceConfidence::High => "High",
    }
}

fn completeness_str(c: ScanCompleteness) -> &'static str {
    match c {
        ScanCompleteness::Complete => "Complete",
        ScanCompleteness::Partial => "Partial",
        ScanCompleteness::Indeterminate => "Indeterminate",
    }
}

/// `NoAction` reads "clean" only when the scan was `Complete` (§10, §11.8).
fn recommendation_str(r: Recommendation, completeness: ScanCompleteness) -> &'static str {
    match r {
        Recommendation::NoAction if completeness == ScanCompleteness::Complete => {
            "no action (clean)"
        }
        Recommendation::NoAction => "no action (not fully checked)",
        Recommendation::Notify => "notify",
        Recommendation::NotifyAndSuggestQuarantine => {
            "notify + suggest quarantine (no auto-action without opt-in)"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::SystemTime;

    fn sample_result() -> ScanResult {
        ScanResult {
            path: PathBuf::from("/tmp/sample"),
            score: 0,
            confidence: EvidenceConfidence::Low,
            completeness: ScanCompleteness::Complete,
            coverage_gaps: Vec::new(),
            signals: Vec::new(),
            recommendation: Recommendation::NoAction,
            engine_version: "test".to_string(),
            evaluated_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn uninspected_notes_name_only_results_with_the_signal() {
        let mut flagged = sample_result();
        flagged.signals.push(nav_core::model::MatchedSignal {
            id: UNINSPECTED_CONTAINER_ID.to_string(),
            weight: 0,
            description: "disk image not inspected".to_string(),
            category: nav_core::model::SignalCategory::Informational,
        });
        let notes = uninspected_notes(&[sample_result(), flagged]);
        assert_eq!(
            notes,
            vec!["navctl: /tmp/sample: disk image not inspected".to_string()]
        );
    }

    #[test]
    fn with_schema_version_adds_field_alongside_existing_ones() {
        let value = with_schema_version(&sample_result()).unwrap();
        assert_eq!(value["schema_version"], SCAN_JSON_SCHEMA_VERSION);
        // Original fields still present — schema_version is additive.
        assert_eq!(value["score"], 0);
    }

    #[test]
    fn multi_json_carries_schema_version() {
        let scan = TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable: Vec::new(),
            not_walked: Default::default(),
            results: vec![sample_result()],
            budget: nav_core::BudgetOutcome::Within,
        };
        let value = multi_json(&scan, None).unwrap();
        assert_eq!(value["schema_version"], SCAN_JSON_SCHEMA_VERSION);
    }

    /// The scan summary has `files` and `kind` but no `results`.
    #[test]
    fn scan_summary_counts_files() {
        let mut scan = empty_scan(Vec::new());
        scan.results = vec![sample_result(), sample_result()];
        let value = scan_summary_json(&scan, None).unwrap();
        assert_eq!(value["files"], 2);
        assert_eq!(value["kind"], "directory");
        assert_eq!(value["schema_version"], SCAN_JSON_SCHEMA_VERSION);
        assert!(value.get("results").is_none());
    }

    /// A budget-exhausted target is never a clean exit, even when every file it
    /// managed to scan was individually complete and clean — "couldn't finish"
    /// is not "clean" at the target level (§8, §11.8/§11.12).
    #[test]
    fn partial_coverage_makes_the_target_exit_indeterminate() {
        let mk = |budget| TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable: Vec::new(),
            not_walked: Default::default(),
            results: vec![sample_result()], // complete + NoAction
            budget,
        };
        assert_eq!(
            exit::for_target(&mk(BudgetOutcome::Within)),
            exit::CLEAN,
            "a fully covered clean target exits clean"
        );
        assert_eq!(
            exit::for_target(&mk(BudgetOutcome::Exhausted(BudgetLimit::Files))),
            exit::INDETERMINATE,
            "a target cut short by the budget is indeterminate, not clean"
        );
    }

    fn empty_scan(unreadable: Vec<PathBuf>) -> TargetScan {
        TargetScan {
            root: PathBuf::from("/tmp"),
            kind: TargetKind::Directory,
            primary: None,
            skipped: Vec::new(),
            unreadable,
            not_walked: Default::default(),
            results: Vec::new(),
            budget: nav_core::BudgetOutcome::Within,
        }
    }

    /// #32 follow-up: a target whose only content is unreadable subdirectories
    /// (the Phase 0b B3 TCC case) is "couldn't check," not a tool failure —
    /// distinct from a target that is genuinely empty (issue #29, unchanged).
    #[test]
    fn empty_scan_exit_code_is_indeterminate_only_when_unreadable_explains_it() {
        assert_eq!(
            empty_scan_exit_code(&empty_scan(Vec::new())),
            exit::OPERATIONAL_ERROR,
            "a genuinely empty, fully-readable target is still issue #29's exit 4"
        );
        assert_eq!(
            empty_scan_exit_code(&empty_scan(vec![PathBuf::from("/tmp/locked")])),
            exit::INDETERMINATE,
            "unreadable subdirectories explain the emptiness — couldn't check, not a failure"
        );
        let mut stopped = empty_scan(Vec::new());
        stopped.budget = nav_core::BudgetOutcome::Exhausted(BudgetLimit::Files);
        assert_eq!(
            empty_scan_exit_code(&stopped),
            exit::INDETERMINATE,
            "a budget stop before any file is partial coverage, not a failure (§11.12)"
        );
    }

    /// `multi_json` must stay safe on an empty-results scan — it backs the
    /// `rules test --json` branch for a target whose only content is
    /// unreadable subdirectories, which never reaches `print_rules_test_multi`
    /// (whose `worst().expect(..)` would panic on empty `results`).
    #[test]
    fn multi_json_on_empty_results_reports_incomplete_coverage() {
        let scan = empty_scan(vec![PathBuf::from("/tmp/locked")]);
        let value = multi_json(&scan, None).unwrap();
        assert_eq!(value["results"], serde_json::json!([]));
        assert_eq!(value["coverage_complete"], false);
        assert_eq!(value["unreadable"], serde_json::json!(["/tmp/locked"]));
    }

    /// Non-UTF-8 paths in every path-bearing field give valid JSON.
    #[cfg(unix)]
    #[test]
    fn multi_json_serializes_non_utf8_paths_lossily() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let bad = |s: &[u8]| PathBuf::from(OsStr::from_bytes(s));
        let mut result = sample_result();
        result.path = bad(b"/tmp/r\xff");
        let scan = TargetScan {
            root: bad(b"/tmp/root\xff"),
            kind: TargetKind::Bundle,
            primary: Some(bad(b"/tmp/root\xff/p\xfe")),
            skipped: vec![bad(b"/tmp/s\xfe")],
            unreadable: vec![bad(b"/tmp/u\xff\xfe")],
            not_walked: Default::default(),
            results: vec![result],
            budget: nav_core::BudgetOutcome::Within,
        };
        let text =
            serde_json::to_string_pretty(&multi_json(&scan, None).expect("serializes")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["target"], "/tmp/root\u{FFFD}");
        assert_eq!(v["primary"], "/tmp/root\u{FFFD}/p\u{FFFD}");
        assert_eq!(
            v["skipped_resources"],
            serde_json::json!(["/tmp/s\u{FFFD}"])
        );
        assert_eq!(
            v["unreadable"],
            serde_json::json!(["/tmp/u\u{FFFD}\u{FFFD}"])
        );
        assert_eq!(v["results"][0]["path"], "/tmp/r\u{FFFD}");
    }

    fn member(path: &str, score: i32, completeness: ScanCompleteness) -> ScanResult {
        let mut r = sample_result();
        r.path = PathBuf::from(path);
        r.score = score;
        r.completeness = completeness;
        if score >= 40 {
            r.recommendation = Recommendation::Notify;
        }
        r
    }

    fn bundle(results: Vec<ScanResult>, budget: BudgetOutcome) -> TargetScan {
        TargetScan {
            root: PathBuf::from("/Apps/X.app"),
            kind: TargetKind::Bundle,
            primary: Some(PathBuf::from("/Apps/X.app/Contents/MacOS/X")),
            skipped: Vec::new(),
            unreadable: Vec::new(),
            not_walked: Default::default(),
            results,
            budget,
        }
    }

    const MAIN: &str = "/Apps/X.app/Contents/MacOS/X";
    const EVIL: &str = "/Apps/X.app/Contents/Resources/evil.sh";

    #[test]
    fn no_action_is_clean_only_when_complete() {
        let label = |c| recommendation_str(Recommendation::NoAction, c);
        assert_eq!(label(ScanCompleteness::Complete), "no action (clean)");
        for c in [ScanCompleteness::Partial, ScanCompleteness::Indeterminate] {
            assert_eq!(label(c), "no action (not fully checked)");
        }
        assert_eq!(
            recommendation_str(Recommendation::Notify, ScanCompleteness::Partial),
            "notify"
        );
    }

    #[test]
    fn partial_and_indeterminate_summary_lines_are_not_clean() {
        for c in [ScanCompleteness::Partial, ScanCompleteness::Indeterminate] {
            let line = summary_line(
                "/tmp/x",
                0,
                EvidenceConfidence::Low,
                c,
                Recommendation::NoAction,
            );
            assert!(line.ends_with("-> no action (not fully checked)"), "{line}");
            assert!(!line.contains("(clean)"), "{line}");
        }
    }

    #[test]
    fn bundle_line_with_incomplete_coverage_is_not_clean() {
        let scan = bundle(
            vec![member(MAIN, 0, ScanCompleteness::Complete)],
            BudgetOutcome::Exhausted(BudgetLimit::Files),
        );
        let line = bundle_summary_line(&scan);
        assert!(line.contains("not fully checked"), "{line}");
        assert!(!line.contains("(clean)"), "{line}");
        let worst = scan.worst().unwrap();
        assert_eq!(
            target_completeness(&scan, worst, true),
            ScanCompleteness::Partial
        );
        assert_eq!(
            recommendation_str(
                worst.recommendation,
                target_completeness(&scan, worst, true)
            ),
            "no action (not fully checked)"
        );
    }

    #[test]
    fn bundle_line_clean_and_complete_has_no_worst() {
        let scan = bundle(
            vec![
                member(MAIN, 0, ScanCompleteness::Complete),
                member(EVIL, 0, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&scan);
        assert!(line.starts_with("/Apps/X.app  score="), "{line}");
        assert!(line.ends_with("(bundle: 2 files)"), "{line}");
        assert!(line.contains("completeness=Complete"), "{line}");
        assert!(line.contains("no action (clean)"), "{line}");
        assert!(!line.contains("worst:"), "{line}");
    }

    #[test]
    fn bundle_line_names_the_worst_file() {
        let scan = bundle(
            vec![
                member(MAIN, 0, ScanCompleteness::Complete),
                member(EVIL, 40, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&scan);
        assert!(line.contains("score=40"), "{line}");
        assert!(line.contains("-> notify"), "{line}");
        assert!(
            line.ends_with("worst: Contents/Resources/evil.sh)"),
            "{line}"
        );
    }

    #[test]
    fn bundle_line_marks_the_main_executable() {
        let scan = bundle(
            vec![
                member(MAIN, 40, ScanCompleteness::Complete),
                member(EVIL, 0, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Within,
        );
        assert!(
            bundle_summary_line(&scan).contains("worst: Contents/MacOS/X*)"),
            "{}",
            bundle_summary_line(&scan)
        );
    }

    #[test]
    fn bundle_line_reports_a_clean_partial_member() {
        let scan = bundle(
            vec![
                member(MAIN, 0, ScanCompleteness::Complete),
                member(EVIL, 0, ScanCompleteness::Partial),
            ],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&scan);
        assert!(line.contains("completeness=Partial"), "{line}");
        assert!(line.contains("worst: Contents/Resources/evil.sh"), "{line}");
    }

    #[test]
    fn bundle_line_is_partial_when_the_budget_cut_the_scan_short() {
        let scan = bundle(
            vec![
                member(MAIN, 0, ScanCompleteness::Complete),
                member(EVIL, 0, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Exhausted(BudgetLimit::Files),
        );
        let line = bundle_summary_line(&scan);
        assert!(line.contains("completeness=Partial"), "{line}");
        assert!(!line.contains("completeness=Complete"), "{line}");
        assert!(!line.contains("worst:"), "{line}");
    }

    #[test]
    fn bundle_line_with_negative_scores_has_no_worst() {
        let scan = bundle(
            vec![
                member(MAIN, -3, ScanCompleteness::Complete),
                member(EVIL, 0, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&scan);
        assert!(line.ends_with("(bundle: 2 files)"), "{line}");
        assert!(!line.contains("worst:"), "{line}");

        let single = bundle(
            vec![member(MAIN, -3, ScanCompleteness::Complete)],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&single);
        assert!(line.contains("score=-3"), "{line}");
        assert!(!line.contains("worst:"), "{line}");
    }

    #[test]
    fn bundle_line_names_a_low_nonzero_score() {
        let scan = bundle(
            vec![
                member(MAIN, 0, ScanCompleteness::Complete),
                member(EVIL, 3, ScanCompleteness::Complete),
            ],
            BudgetOutcome::Within,
        );
        let line = bundle_summary_line(&scan);
        assert!(line.contains("worst: Contents/Resources/evil.sh"), "{line}");
    }

    /// Guards the per-file format against drift.
    #[test]
    fn summary_line_matches_the_per_file_format() {
        let r = sample_result();
        assert_eq!(
            summary_line(
                &r.path.display().to_string(),
                r.score,
                r.confidence,
                r.completeness,
                r.recommendation
            ),
            "/tmp/sample  score=0    confidence=Low    completeness=Complete      -> no action (clean)"
        );
    }
}
