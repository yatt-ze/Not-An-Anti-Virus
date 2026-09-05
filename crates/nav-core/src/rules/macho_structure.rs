//! Mach-O structural/entitlement anomaly detection (§5.2, NAV-007).
//!
//! Purely structural: reads what `macho::parse` already recovered (load
//! paths, code-signature presence, embedded entitlements) and scores two
//! narrow anomalies — a dylib/rpath load path into a writable/transient
//! location, and a handful of specific "exempt me from platform protections"
//! entitlements. Each is corroboration-only (§5.1): summed weight is capped
//! well under the high-severity threshold, so this rule alone can never push
//! a verdict past `Notify`.

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::macho::{self, MachOImage};
use crate::model::{MatchedSignal, SignalCategory};
use crate::plist::{self, PlistValue};

/// Weight for at least one dylib/rpath load path in a writable/transient
/// location. Flat, not per-path — the anomaly is "loads from somewhere an
/// attacker can write," not "N such paths is N times worse."
const TRANSIENT_LOCATION_WEIGHT: i32 = 15;
/// Per-entitlement weight when the binary carries a real code signature.
const ENTITLEMENT_WEIGHT_SIGNED: i32 = 10;
/// Per-entitlement weight when there's no code signature at all — an
/// unsigned/ad-hoc binary asking for these exemptions is more notable than a
/// signed one (README's "suspicious entitlements on unsigned binaries").
const ENTITLEMENT_WEIGHT_UNSIGNED: i32 = 18;
/// Ceiling on this rule's single signal — comfortably in `Notify` range,
/// never near the §5.1 high-severity threshold on its own.
const MAX_WEIGHT: i32 = 30;

/// Entitlement keys that exempt a binary from a platform protection —
/// meaningful on their own regardless of what else the binary does.
const SUSPICIOUS_ENTITLEMENTS: &[&str] = &[
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-executable-page-protection",
    "com.apple.security.get-task-allow",
];

pub struct MachOStructureRule;

impl Default for MachOStructureRule {
    fn default() -> Self {
        MachOStructureRule
    }
}

impl Rule for MachOStructureRule {
    fn id(&self) -> &'static str {
        "macho-loader-anomaly"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::StaticSuspicion
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;
        if !macho::is_macho_magic(content) {
            return Ok(None);
        }
        // Recognized Mach-O magic that the parser couldn't walk within its
        // bounds (truncated header, malformed load commands) — "couldn't
        // check," not "clean" (§10/§11.8).
        let image = macho::parse(content).ok_or(RuleOutcome::NotApplicable)?;

        let mut findings: Vec<(i32, String)> = Vec::new();

        let bad_paths: Vec<&str> = image
            .dylibs
            .iter()
            .chain(image.rpaths.iter())
            .map(String::as_str)
            .filter(|p| is_writable_or_transient(p))
            .collect();
        if !bad_paths.is_empty() {
            findings.push((
                TRANSIENT_LOCATION_WEIGHT,
                format!(
                    "loads from a writable/transient location: {}",
                    bad_paths.join(", ")
                ),
            ));
        }

        match entitlements_finding(&image, ctx.truncated) {
            Ok(Some(f)) => findings.push(f),
            Ok(None) => {}
            // Couldn't determine entitlements (truncated signature region,
            // malformed blob). Only fatal to this evaluation if it was our
            // only shot at a finding — a real path anomaly already found
            // stands on its own.
            Err(outcome) if findings.is_empty() => return Err(outcome),
            Err(_) => {}
        }

        if findings.is_empty() {
            return Ok(None);
        }

        let weight = findings
            .iter()
            .map(|(w, _)| *w)
            .sum::<i32>()
            .min(MAX_WEIGHT);
        let description = findings
            .iter()
            .map(|(_, d)| d.as_str())
            .collect::<Vec<_>>()
            .join("; ");

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight,
            description,
            category: self.category(),
        }))
    }
}

/// Score the binary's entitlements, if any were recovered. `Ok(None)` covers
/// "no code signature at all" (entitlements live inside one, so there's
/// nothing to examine), "signed and we held the whole file but found no
/// entitlements blob" (a determined fact), and "signed, entitlements
/// present, none of them suspicious." `Err(NotApplicable)` only when the read
/// was `truncated` and signed with no entitlements recovered — the signature
/// (near EOF) is exactly what an 8 MiB capture loses first, so that
/// combination can't be told apart from "truncated past a real entitlements
/// blob" (§10/§11.8) and must not be read as a clean bill of health.
fn entitlements_finding(
    image: &MachOImage,
    truncated: bool,
) -> Result<Option<(i32, String)>, RuleOutcome> {
    let Some(xml) = &image.entitlements else {
        return if image.has_code_signature && truncated {
            Err(RuleOutcome::NotApplicable)
        } else {
            Ok(None)
        };
    };
    let Some(parsed) = plist::parse(xml) else {
        return Err(RuleOutcome::NotApplicable); // malformed entitlements blob
    };

    let bad = suspicious_entitlements(&parsed);
    if bad.is_empty() {
        return Ok(None);
    }

    let weight_each = if image.has_code_signature {
        ENTITLEMENT_WEIGHT_SIGNED
    } else {
        ENTITLEMENT_WEIGHT_UNSIGNED
    };
    Ok(Some((
        weight_each * bad.len() as i32,
        format!("requests suspicious entitlement(s): {}", bad.join(", ")),
    )))
}

/// Which of [`SUSPICIOUS_ENTITLEMENTS`] are set `true` in `plist`.
fn suspicious_entitlements(plist: &PlistValue) -> Vec<&'static str> {
    SUSPICIOUS_ENTITLEMENTS
        .iter()
        .copied()
        .filter(|key| plist.get(key).and_then(PlistValue::as_bool) == Some(true))
        .collect()
}

/// True if `path` is a load path worth flagging: an absolute path into a
/// transient/user-writable location, or one with a hidden directory
/// component. The `@executable_path`/`@loader_path`/`@rpath` relative forms
/// (the normal way an app references its own bundled libraries) and Apple
/// system locations are never flagged.
fn is_writable_or_transient(path: &str) -> bool {
    if path.starts_with("@executable_path")
        || path.starts_with("@loader_path")
        || path.starts_with("@rpath")
    {
        return false;
    }
    if !path.starts_with('/') {
        return false; // not an absolute path this heuristic can judge
    }

    const SYSTEM_PREFIXES: &[&str] = &["/System/", "/usr/lib/", "/Library/"];
    if SYSTEM_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return false;
    }

    const TRANSIENT_PREFIXES: &[&str] = &[
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/private/var/tmp/",
        "/Users/Shared/",
    ];
    if TRANSIENT_PREFIXES.iter().any(|p| path.starts_with(p)) || path.starts_with("/Users/") {
        return true;
    }

    path.split('/')
        .any(|c| c.len() > 1 && c.starts_with('.') && c != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContentSource, ScanContext};
    use crate::macho::tests_support::synth_macho_64_full;
    use std::path::PathBuf;

    fn ctx_for(content: Vec<u8>) -> ScanContext {
        ctx_for_truncated(content, false)
    }

    fn ctx_for_truncated(content: Vec<u8>, truncated: bool) -> ScanContext {
        ScanContext {
            path: PathBuf::from("test-binary"),
            content: Some(content),
            truncated,
            file_len: None,
            identity: None,
            source: ContentSource::File,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn non_macho_content_does_not_apply() {
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(b"just some text, not a binary".to_vec())),
            Ok(None)
        ));
    }

    #[test]
    fn unreadable_content_is_not_applicable() {
        let c = ScanContext {
            path: PathBuf::from("x"),
            content: None,
            truncated: false,
            file_len: None,
            identity: None,
            source: ContentSource::File,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
        };
        assert!(matches!(
            MachOStructureRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    #[test]
    fn normal_dylibs_and_rpaths_score_nothing() {
        let (image, _, _) = synth_macho_64_full(
            b"code",
            &[
                "/usr/lib/libSystem.B.dylib",
                "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
            ],
            &["@executable_path/../Frameworks", "@rpath/libFoo.dylib"],
            true,
            None,
        );
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(image)),
            Ok(None)
        ));
    }

    #[test]
    fn rpath_into_tmp_is_flagged() {
        let (image, _, _) = synth_macho_64_full(b"code", &[], &["/tmp/evil-rpath"], false, None);
        let sig = MachOStructureRule
            .evaluate(&ctx_for(image))
            .unwrap()
            .expect("should fire");
        assert!(sig.description.contains("writable/transient"));
        assert!(sig.weight > 0 && sig.weight <= MAX_WEIGHT);
        assert_eq!(sig.category, SignalCategory::StaticSuspicion);
    }

    #[test]
    fn dylib_under_users_home_is_flagged() {
        let (image, _, _) = synth_macho_64_full(
            b"code",
            &["/Users/victim/Library/Caches/evil.dylib"],
            &[],
            false,
            None,
        );
        assert!(MachOStructureRule
            .evaluate(&ctx_for(image))
            .unwrap()
            .is_some());
    }

    #[test]
    fn hidden_directory_component_is_flagged() {
        let (image, _, _) =
            synth_macho_64_full(b"code", &[], &["/opt/app/.cache/lib"], false, None);
        assert!(MachOStructureRule
            .evaluate(&ctx_for(image))
            .unwrap()
            .is_some());
    }

    #[test]
    fn disable_library_validation_entitlement_is_flagged() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;
        let (image, _, _) = synth_macho_64_full(b"code", &[], &[], true, Some(xml));
        let sig = MachOStructureRule
            .evaluate(&ctx_for(image))
            .unwrap()
            .expect("should fire");
        assert!(sig.description.contains("disable-library-validation"));
    }

    #[test]
    fn entitlements_without_suspicious_keys_score_nothing() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.app-sandbox</key><true/>
        </dict></plist>"#;
        let (image, _, _) = synth_macho_64_full(b"code", &[], &[], true, Some(xml));
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(image)),
            Ok(None)
        ));
    }

    #[test]
    fn unsigned_binary_has_no_entitlements_to_examine() {
        // No LC_CODE_SIGNATURE at all — entitlements live inside one, so
        // this is a determined "nothing to examine," not a gap.
        let (image, _, _) = synth_macho_64_full(b"code", &[], &[], false, None);
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(image)),
            Ok(None)
        ));
    }

    #[test]
    fn signed_with_unrecoverable_entitlements_is_not_applicable() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;
        let (mut image, _, sig_off) = synth_macho_64_full(b"code", &[], &[], true, Some(xml));
        // Truncate away the signature blob — same shape as an 8 MiB capture
        // cutting off the code signature near EOF — and mark the read as
        // truncated, which is what actually makes this ambiguous.
        image.truncate(sig_off + 4);
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for_truncated(image, true)),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    #[test]
    fn a_real_path_finding_survives_an_unrecoverable_entitlements_gap() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;
        let (mut image, _, sig_off) =
            synth_macho_64_full(b"code", &[], &["/tmp/evil"], true, Some(xml));
        image.truncate(sig_off + 4);
        let sig = MachOStructureRule
            .evaluate(&ctx_for_truncated(image, true))
            .unwrap()
            .expect("the rpath finding must still surface");
        assert!(sig.description.contains("writable/transient"));
    }

    #[test]
    fn signed_with_no_entitlements_blob_in_a_complete_read_scores_nothing() {
        // Whole file held (not truncated) and genuinely no entitlements blob
        // in the SuperBlob — a determined fact, not a gap.
        let (image, _, _) = synth_macho_64_full(b"code", &[], &[], true, None);
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(image)),
            Ok(None)
        ));
    }

    #[test]
    fn is_writable_or_transient_examples() {
        assert!(is_writable_or_transient("/tmp/evil"));
        assert!(is_writable_or_transient("/private/tmp/evil"));
        assert!(is_writable_or_transient("/var/tmp/evil"));
        assert!(is_writable_or_transient("/Users/Shared/evil"));
        assert!(is_writable_or_transient("/Users/alice/evil"));
        assert!(is_writable_or_transient("/opt/app/.hidden/lib"));

        assert!(!is_writable_or_transient("@executable_path/../Frameworks"));
        assert!(!is_writable_or_transient("@loader_path/lib.dylib"));
        assert!(!is_writable_or_transient("@rpath/lib.dylib"));
        assert!(!is_writable_or_transient("/System/Library/x"));
        assert!(!is_writable_or_transient("/usr/lib/libSystem.B.dylib"));
        assert!(!is_writable_or_transient("/Library/Frameworks/x"));
        assert!(!is_writable_or_transient("libFoo.dylib")); // relative, not judged
    }

    #[test]
    fn malformed_macho_that_wont_parse_is_not_applicable() {
        // Valid magic, nothing else — recognized as Mach-O but unwalkable.
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(vec![0xCF, 0xFA, 0xED, 0xFE])),
            Err(RuleOutcome::NotApplicable)
        ));
    }
}

/// Regenerates the fp-harness fixtures this rule's coverage depends on.
/// Not part of the normal test run: `GENERATE_MACHO_FIXTURES=1 cargo test -p
/// nav-core rules::macho_structure::fixture_gen -- --ignored --nocapture`
/// rebuilds them from `macho::tests_support`'s synthetic builder after a
/// deliberate change; review the resulting `git diff` before committing.
#[cfg(test)]
mod fixture_gen {
    use crate::macho::tests_support::synth_macho_64_full;
    use std::path::Path;

    #[test]
    #[ignore]
    fn generate_fixtures() {
        if std::env::var("GENERATE_MACHO_FIXTURES").as_deref() != Ok("1") {
            return;
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");

        // Benign: ordinary system/@-relative loader paths, a real signature
        // with an unrelated, non-suspicious entitlement.
        let benign_entitlements = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.app-sandbox</key><true/>
</dict></plist>"#;
        let (benign, _, _) = synth_macho_64_full(
            b"\x55\x48\x89\xe5\x90benign machine code padding to look real",
            &[
                "/usr/lib/libSystem.B.dylib",
                "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
            ],
            &[
                "@executable_path/../Frameworks",
                "@loader_path/../Frameworks",
            ],
            true,
            Some(benign_entitlements),
        );
        std::fs::write(root.join("benign/macho_normal_loader"), benign).unwrap();

        // Suspicious: an rpath into /tmp plus a disable-library-validation
        // entitlement — both anomalies this rule looks for.
        let bad_entitlements = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>"#;
        let (suspicious, _, _) = synth_macho_64_full(
            b"\x55\x48\x89\xe5\x90suspicious machine code padding to look real",
            &["/usr/lib/libSystem.B.dylib"],
            &["/tmp/evil-rpath"],
            true,
            Some(bad_entitlements),
        );
        std::fs::write(
            root.join("suspicious/macho_tmp_rpath_disable_lib_validation"),
            suspicious,
        )
        .unwrap();
    }
}
