//! Mach-O structural/entitlement anomaly detection (§5.2, NAV-007).
//!
//! Purely structural: reads what `macho::parse` already recovered (load
//! paths, code-signature presence, embedded entitlements, CodeDirectory
//! flags) and scores two narrow anomalies — a dylib/rpath load path into a
//! writable/transient location, and a handful of specific "exempt me from
//! platform protections" entitlements, weighted higher when the binary is
//! only ad-hoc signed rather than under a real identity. Each is
//! corroboration-only (§5.1): summed weight is capped well under the
//! high-severity threshold, so this rule alone can never push a verdict past
//! `Notify`.

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::macho::{self, MachOImage, CS_ADHOC};
use crate::model::{MatchedSignal, SignalCategory};
use crate::plist::{self, PlistValue};

/// Weight for at least one dylib/rpath load path in a writable/transient
/// location. Flat, not per-path — the anomaly is "loads from somewhere an
/// attacker can write," not "N such paths is N times worse."
const TRANSIENT_LOCATION_WEIGHT: i32 = 15;
/// Per-entitlement weight for a real (non-ad-hoc) signing identity, and the
/// safe default when the CodeDirectory's flags couldn't be determined.
const ENTITLEMENT_WEIGHT_SIGNED: i32 = 10;
/// Per-entitlement weight when the CodeDirectory's flags carry `CS_ADHOC` — an
/// ad-hoc-signed binary asking for these exemptions is more notable than one
/// under a real identity (README's "suspicious entitlements on unsigned
/// binaries").
const ENTITLEMENT_WEIGHT_ADHOC: i32 = 18;
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
        if !macho::is_macho_magic(content, ctx.truncated) {
            return Ok(None);
        }
        // Recognized Mach-O magic that the parser couldn't walk within its
        // bounds (truncated header, malformed load commands, or a fat container
        // with no walkable slice) — "couldn't check," not "clean" (§10/§11.8).
        let (images, skipped_slices) = macho::parse_all_slices(content, ctx.truncated);
        if images.is_empty() {
            return Err(RuleOutcome::NotApplicable);
        }

        // Judge a fat binary on all its slices: a malicious arm64 slice must
        // not disappear behind a clean x86_64 one (§5.2). Load-path anomalies
        // are unioned across slices; each slice's entitlements are scored on
        // its own signed/unsigned status. `skipped_slices > 0` means at least
        // one *declared* arch couldn't be walked at all — a deliberately
        // malformed slice must not hide behind the rest coming back clean.
        let mut bad_paths: Vec<&str> = Vec::new();
        let mut findings: Vec<(i32, String)> = Vec::new();
        let mut entitlements_gap = false;

        for image in &images {
            for p in image
                .dylibs
                .iter()
                .chain(image.rpaths.iter())
                .map(String::as_str)
            {
                if is_writable_or_transient(p) && !bad_paths.contains(&p) {
                    bad_paths.push(p);
                }
            }
            match entitlements_finding(image, ctx.truncated) {
                Ok(Some(f)) => findings.push(f),
                Ok(None) => {}
                // Couldn't determine this slice's entitlements (truncated
                // signature region, malformed blob). Only fatal if nothing
                // else scores — a real finding stands on its own.
                Err(_) => entitlements_gap = true,
            }
        }

        if !bad_paths.is_empty() {
            findings.insert(
                0,
                (
                    TRANSIENT_LOCATION_WEIGHT,
                    format!(
                        "loads from a writable/transient location: {}",
                        bad_paths.join(", ")
                    ),
                ),
            );
        }

        if findings.is_empty() {
            return if entitlements_gap || skipped_slices > 0 {
                Err(RuleOutcome::NotApplicable)
            } else {
                Ok(None)
            };
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

    // Ad-hoc vs. a real signing identity, not signed vs. unsigned: entitlements
    // only ever come from inside a code signature, so `has_code_signature` is
    // always true here. Unknown flags (no CodeDirectory recovered) fall back
    // to the lower, real-identity weight rather than assuming the worse case.
    let is_adhoc = image
        .code_directory_flags
        .is_some_and(|flags| flags & CS_ADHOC != 0);
    let weight_each = if is_adhoc {
        ENTITLEMENT_WEIGHT_ADHOC
    } else {
        ENTITLEMENT_WEIGHT_SIGNED
    };
    let description = if is_adhoc {
        format!(
            "requests suspicious entitlement(s) on an ad-hoc-signed binary: {}",
            bad.join(", ")
        )
    } else {
        format!("requests suspicious entitlement(s): {}", bad.join(", "))
    };
    Ok(Some((weight_each * bad.len() as i32, description)))
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

    if super::TRANSIENT_PREFIXES
        .iter()
        .any(|p| path.starts_with(p))
        || path.starts_with("/Users/")
    {
        return true;
    }

    path.split('/')
        .any(|c| c.len() > 1 && c.starts_with('.') && c != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContentSource, ScanContext};
    use crate::macho::tests_support::{
        synth_fat, synth_fat_with_bogus_arches, synth_macho_64_full,
        synth_macho_64_full_with_cd_flags,
    };
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
    fn adhoc_signed_disable_lib_validation_weighs_more_than_identity_signed() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;

        let (adhoc, _, _) =
            synth_macho_64_full_with_cd_flags(b"code", &[], &[], true, Some(xml), Some(CS_ADHOC));
        let adhoc_sig = MachOStructureRule
            .evaluate(&ctx_for(adhoc))
            .unwrap()
            .expect("should fire");
        assert_eq!(adhoc_sig.weight, ENTITLEMENT_WEIGHT_ADHOC);
        assert!(adhoc_sig.description.contains("ad-hoc"));

        let (identity, _, _) = synth_macho_64_full_with_cd_flags(
            b"code",
            &[],
            &[],
            true,
            Some(xml),
            Some(0x10000), // no CS_ADHOC bit — a real identity, e.g. runtime-enabled
        );
        let identity_sig = MachOStructureRule
            .evaluate(&ctx_for(identity))
            .unwrap()
            .expect("should fire");
        assert_eq!(identity_sig.weight, ENTITLEMENT_WEIGHT_SIGNED);
        assert!(!identity_sig.description.contains("ad-hoc"));

        let (unknown, _, _) = synth_macho_64_full(b"code", &[], &[], true, Some(xml));
        let unknown_sig = MachOStructureRule
            .evaluate(&ctx_for(unknown))
            .unwrap()
            .expect("should fire");
        assert_eq!(
            unknown_sig.weight, ENTITLEMENT_WEIGHT_SIGNED,
            "an unrecoverable CodeDirectory must not assume the worse case"
        );
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
        assert!(is_writable_or_transient(
            "/private/var/folders/xy/abc/T/libevil.dylib"
        ));
        assert!(is_writable_or_transient(
            "/var/folders/xy/abc/T/libevil.dylib"
        ));

        assert!(!is_writable_or_transient("@executable_path/../Frameworks"));
        assert!(!is_writable_or_transient("@loader_path/lib.dylib"));
        assert!(!is_writable_or_transient("@rpath/lib.dylib"));
        assert!(!is_writable_or_transient("/System/Library/x"));
        assert!(!is_writable_or_transient("/usr/lib/libSystem.B.dylib"));
        assert!(!is_writable_or_transient("/Library/Frameworks/x"));
        assert!(!is_writable_or_transient("libFoo.dylib")); // relative, not judged
    }

    #[test]
    fn a_malicious_fat_slice_is_not_hidden_behind_a_clean_slice() {
        // Slice 1: ordinary system/@-relative loader paths, nothing to flag.
        let (clean, _, _) = synth_macho_64_full(
            b"clean",
            &["/usr/lib/libSystem.B.dylib"],
            &["@rpath/libFoo.dylib"],
            true,
            None,
        );
        // Slice 2: an rpath into /tmp — the evasion is putting this second.
        let (evil, _, _) = synth_macho_64_full(b"evil", &[], &["/tmp/evil-rpath"], false, None);
        let fat = synth_fat(&[&clean, &evil]);

        let sig = MachOStructureRule
            .evaluate(&ctx_for(fat))
            .unwrap()
            .expect("the malicious second slice must still fire");
        assert!(sig.description.contains("writable/transient"));
        assert!(sig.description.contains("/tmp/evil-rpath"));
    }

    #[test]
    fn malformed_macho_that_wont_parse_is_not_applicable() {
        // Valid magic, nothing else — recognized as Mach-O but unwalkable.
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(vec![0xCF, 0xFA, 0xED, 0xFE])),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    #[test]
    fn two_clean_fat_slices_score_nothing() {
        let (a, _, _) =
            synth_macho_64_full(b"aaaa", &["/usr/lib/libSystem.B.dylib"], &[], false, None);
        let (b, _, _) =
            synth_macho_64_full(b"bbbb", &["/usr/lib/libSystem.B.dylib"], &[], false, None);
        let fat = synth_fat(&[&a, &b]);
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(fat)),
            Ok(None)
        ));
    }

    #[test]
    fn an_unwalkable_slice_alongside_a_clean_one_is_not_applicable() {
        // A malformed-on-purpose slice (bad magic) must not hide behind a
        // clean slice reading as scored-fine (§38).
        let (clean, _, _) =
            synth_macho_64_full(b"clean", &["/usr/lib/libSystem.B.dylib"], &[], false, None);
        let garbage: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0];
        let fat = synth_fat(&[&clean, garbage]);
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(fat)),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    #[test]
    fn an_unwalkable_slice_does_not_hide_a_real_finding_in_the_good_slice() {
        // Same shape as above, but the walkable slice has its own anomaly —
        // that finding must still stand even though a sibling slice was
        // unwalkable.
        let (clean, _, _) = synth_macho_64_full(b"clean", &[], &["/tmp/evil-rpath"], false, None);
        let garbage: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0];
        let fat = synth_fat(&[&clean, garbage]);
        let sig = MachOStructureRule
            .evaluate(&ctx_for(fat))
            .unwrap()
            .expect("the good slice's finding must still surface");
        assert!(sig.description.contains("writable/transient"));
    }

    #[test]
    fn many_bogus_arches_alongside_one_clean_slice_is_not_applicable() {
        // §46: a fat binary shaped like the verified regression — 24 bogus
        // arch entries plus one real, clean slice. It must count as Mach-O
        // (evasion would be scoring it as if it weren't), and the 24
        // unwalkable declared arches must degrade the result to
        // NotApplicable rather than let the clean slice read as fine.
        let (real, _, _) =
            synth_macho_64_full(b"clean", &["/usr/lib/libSystem.B.dylib"], &[], false, None);
        let fat = synth_fat_with_bogus_arches(&real, 24);
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(fat)),
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
    use crate::macho::tests_support::{
        synth_fat, synth_fat_with_bogus_arches_aligned, synth_macho_64_full,
        synth_macho_64_full_with_cd_flags,
    };
    use crate::macho::CS_ADHOC;
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

        // Suspicious: an LC_LOAD_DYLIB into per-user $TMPDIR
        // (/private/var/folders/…), unsigned — the §39 gap this rule now covers.
        let (tmpdir_dylib, _, _) = synth_macho_64_full(
            b"\x55\x48\x89\xe5\x90tmpdir dylib machine code padding to look real",
            &[
                "/private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/libupdate.dylib",
                "/usr/lib/libSystem.B.dylib",
            ],
            &[],
            false,
            None,
        );
        std::fs::write(root.join("suspicious/macho_tmpdir_dylib"), tmpdir_dylib).unwrap();

        // Suspicious: ad-hoc signed (CS_ADHOC) with disable-library-validation
        // — the higher of the two entitlement weights (§37). Benign system
        // dylibs only, so the entitlement is the sole anomaly.
        let adhoc_entitlements = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>"#;
        let (adhoc, _, _) = synth_macho_64_full_with_cd_flags(
            b"\x55\x48\x89\xe5\x90adhoc machine code padding to look real",
            &["/usr/lib/libSystem.B.dylib"],
            &[],
            true,
            Some(adhoc_entitlements),
            Some(CS_ADHOC),
        );
        std::fs::write(
            root.join("suspicious/macho_adhoc_disable_lib_validation"),
            adhoc,
        )
        .unwrap();

        // Suspicious: a fat binary with one clean slice and one malformed
        // (bad-magic) slice — the malformed slice must degrade the scan to
        // NotApplicable/Partial rather than let the clean slice look fine on
        // its own (§38). The clean slice carries an `osascript` string so the
        // cross-platform suspicious-strings rule still fires on Ubuntu, where
        // the codesign-backed rules don't run.
        let (clean_slice, _, _) = synth_macho_64_full(
            b"\x55\x48\x89\xe5\x90 shells out via osascript for testing",
            &["/usr/lib/libSystem.B.dylib"],
            &[],
            false,
            None,
        );
        let malformed_slice: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let fat = synth_fat(&[&clean_slice, malformed_slice]);
        std::fs::write(root.join("suspicious/macho_fat_malformed_slice"), fat).unwrap();

        // Suspicious: a fat binary shaped like the §46 regression — 24 bogus
        // arch entries (the kernel runs binaries like this; an arch-count cap
        // alone must not be the discriminator) alongside one real, clean
        // slice. The 24 unwalkable declared arches must degrade the scan to
        // Partial rather than let the clean slice score fine. The slice
        // carries an `osascript` string so suspicious-strings still fires on
        // Ubuntu CI, where the codesign-backed rules don't run. This fixture
        // is only ever parsed, never executed, so the bogus regions are
        // packed tight (16-byte alignment) instead of the real 16 KiB the
        // kernel requires — keeps the checked-in file a few KiB instead of ~400KB.
        let (many_arches_slice, _, _) = synth_macho_64_full(
            b"\x55\x48\x89\xe5\x90 shells out via osascript for testing",
            &["/usr/lib/libSystem.B.dylib"],
            &[],
            false,
            None,
        );
        let many_arches = synth_fat_with_bogus_arches_aligned(&many_arches_slice, 24, 16);
        std::fs::write(root.join("suspicious/macho_fat_many_arches"), many_arches).unwrap();
    }
}
