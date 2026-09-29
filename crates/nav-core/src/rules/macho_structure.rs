//! Mach-O structural/entitlement anomaly detection (§5.2, NAV-007).
//!
//! Purely structural: reads what `ctx.macho()` (an offset-based scan, §5.2,
//! #45) already recovered — load paths, code-signature presence, embedded
//! entitlements, CodeDirectory flags — and scores two narrow anomalies: a
//! dylib/rpath load path into a writable/transient location, and a handful
//! of specific "exempt me from platform protections" entitlements, most
//! weighted higher when the binary is only ad-hoc signed rather than under a
//! real identity (`EntitlementPolicy::WeightedByIdentity`); `get-task-allow`
//! is the exception — Xcode Debug builds are always ad-hoc and always request it, so
//! it only scores on a confirmed identity-signed binary
//! (`EntitlementPolicy::IdentityOnly`, #37). Each anomaly is
//! corroboration-only (§5.1): summed weight is capped well under the
//! high-severity threshold, so this rule alone can never push a verdict past
//! `Notify`.

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::macho::{MachOImage, CS_ADHOC};
use crate::model::{MatchedSignal, SignalCategory};
use crate::plist::{self, PlistValue};
use std::collections::HashMap;

/// Weight for at least one dylib/rpath load path in a writable/transient
/// location. Flat, not per-path — the anomaly is "loads from somewhere an
/// attacker can write," not "N such paths is N times worse."
const TRANSIENT_LOCATION_WEIGHT: i32 = 15;
/// Weight when every flagged path is an absolute path into another user's
/// home (`/Users/<name>/…`, not `Shared`, no hidden component): almost always
/// a leaked build directory, and not writable by an arbitrary attacker (§5.2).
const USER_HOME_PATH_WEIGHT: i32 = 5;
/// Per-entitlement weight for a real (non-ad-hoc) signing identity, and the
/// safe default when the CodeDirectory's flags couldn't be determined.
const ENTITLEMENT_WEIGHT_SIGNED: i32 = 10;
/// Per-entitlement weight when the CodeDirectory's flags carry `CS_ADHOC` — an
/// ad-hoc-signed binary asking for these exemptions is more notable than one
/// under a real identity (README's "suspicious entitlements on unsigned
/// binaries").
const ENTITLEMENT_WEIGHT_ADHOC: i32 = 18;
/// Ceiling on the combined contribution of all entitlements weighted at
/// `ENTITLEMENT_WEIGHT_SIGNED`: under a real identity they only corroborate
/// (§5.2). Ad-hoc-weighted entitlements are not capped by it.
const SIGNED_ENTITLEMENTS_CAP: i32 = ENTITLEMENT_WEIGHT_SIGNED;
/// Ceiling on this rule's single signal — comfortably in `Notify` range,
/// never near the §5.1 high-severity threshold on its own.
const MAX_WEIGHT: i32 = 30;

/// Which weight a requested entitlement carries. `AdHoc` outranks `Signed`
/// when slices of a fat binary disagree.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EntitlementBucket {
    Signed,
    AdHoc,
}

impl EntitlementBucket {
    fn weight(self) -> i32 {
        match self {
            Self::Signed => ENTITLEMENT_WEIGHT_SIGNED,
            Self::AdHoc => ENTITLEMENT_WEIGHT_ADHOC,
        }
    }
}

/// When a suspicious entitlement contributes to the score.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EntitlementPolicy {
    /// Always contributes, weighted by ad-hoc-vs-identity like the rest of
    /// this rule (`ENTITLEMENT_WEIGHT_ADHOC`/`ENTITLEMENT_WEIGHT_SIGNED`).
    WeightedByIdentity,
    /// Only contributes on a confirmed identity-signed binary (`CS_ADHOC`
    /// known absent) — see `get-task-allow`'s entry below.
    IdentityOnly,
}

/// An entitlement key that exempts a binary from a platform protection,
/// meaningful on its own regardless of what else the binary does, together
/// with when it's scored.
struct SuspiciousEntitlement {
    key: &'static str,
    policy: EntitlementPolicy,
}

/// `com.apple.security.get-task-allow` only scores on an identity-signed
/// binary: Xcode adds it to *every* Debug build, and Xcode Debug builds are
/// always ad-hoc signed ("Sign to Run Locally") — so on an ad-hoc binary it's
/// the ordinary dev-build state, not an anomaly. Notarization rejects it on
/// a real identity, so there it's still meaningful (#37).
const SUSPICIOUS_ENTITLEMENTS: &[SuspiciousEntitlement] = &[
    SuspiciousEntitlement {
        key: "com.apple.security.cs.disable-library-validation",
        policy: EntitlementPolicy::WeightedByIdentity,
    },
    SuspiciousEntitlement {
        key: "com.apple.security.cs.allow-dyld-environment-variables",
        policy: EntitlementPolicy::WeightedByIdentity,
    },
    SuspiciousEntitlement {
        key: "com.apple.security.cs.disable-executable-page-protection",
        policy: EntitlementPolicy::WeightedByIdentity,
    },
    SuspiciousEntitlement {
        key: "com.apple.security.get-task-allow",
        policy: EntitlementPolicy::IdentityOnly,
    },
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
        self.evaluate_with(ctx, || super::codesign::verifies_apple_anchor(ctx))
    }

    /// Covered when the content is determined not to be Mach-O at all (a
    /// header-level fact, never past the prefix), or when every slice and
    /// every held code signature was read by offset (§5.2, #45).
    fn covers_truncation(&self, ctx: &ScanContext) -> bool {
        let scan = ctx.macho();
        !scan.is_macho || scan.fully_examined()
    }
}

impl MachOStructureRule {
    /// `evaluate` with the Apple-anchor check injected. `anchored` runs at most
    /// once, and only when two or more entitlements sit at the signed weight.
    fn evaluate_with(
        &self,
        ctx: &ScanContext,
        anchored: impl FnOnce() -> bool,
    ) -> Result<Option<MatchedSignal>, RuleOutcome> {
        if ctx.content.is_none() {
            return Err(RuleOutcome::NotApplicable);
        }
        let scan = ctx.macho();
        if !scan.is_macho {
            return Ok(None);
        }
        // Recognized Mach-O magic that the parser couldn't walk within its
        // bounds (malformed load commands, or a fat container with no
        // walkable slice) — "couldn't check," not "clean" (§10/§11.8).
        let images = &scan.images;
        if images.is_empty() {
            return Err(RuleOutcome::NotApplicable);
        }
        let skipped_slices = scan.skipped_slices;

        // Judge a fat binary on all its slices: a malicious arm64 slice must
        // not disappear behind a clean x86_64 one (§5.2). Load-path anomalies
        // and suspicious entitlement keys are each unioned across slices —
        // one signal per distinct bad path / entitlement key, not one per
        // slice that requests it — so a universal binary carrying the same
        // anomaly in every slice doesn't inflate the score or repeat the
        // text (§5.2). A key requested by more than one slice is weighted by
        // the worst (most ad-hoc) of those slices. `skipped_slices > 0` means
        // at least one *declared* arch couldn't be walked at all — a
        // deliberately malformed slice must not hide behind the rest coming
        // back clean.
        let mut bad_paths: Vec<&str> = Vec::new();
        let mut home_paths: Vec<&str> = Vec::new();
        let mut path_weight = 0;
        let mut entitlement_buckets: HashMap<&'static str, EntitlementBucket> = HashMap::new();
        let mut entitlements_gap = false;

        for image in images {
            for p in image
                .dylibs
                .iter()
                .chain(image.rpaths.iter())
                .map(String::as_str)
            {
                if let Some(w) = load_path_weight(p) {
                    path_weight = path_weight.max(w);
                    let list = if w == USER_HOME_PATH_WEIGHT {
                        &mut home_paths
                    } else {
                        &mut bad_paths
                    };
                    if !list.contains(&p) {
                        list.push(p);
                    }
                }
            }
            match entitlements_finding(image) {
                Ok(Some(contributing)) => {
                    for (key, bucket) in contributing {
                        entitlement_buckets
                            .entry(key)
                            .and_modify(|b| *b = (*b).max(bucket))
                            .or_insert(bucket);
                    }
                }
                Ok(None) => {}
                // Couldn't determine this slice's entitlements (truncated
                // signature region, malformed blob). Only fatal if nothing
                // else scores — a real finding stands on its own.
                Err(_) => entitlements_gap = true,
            }
        }

        let mut findings: Vec<(i32, String)> = Vec::new();
        if !bad_paths.is_empty() || !home_paths.is_empty() {
            let mut parts = Vec::new();
            if !bad_paths.is_empty() {
                parts.push(format!(
                    "loads from a writable/transient location: {}",
                    bad_paths.join(", ")
                ));
            }
            if !home_paths.is_empty() {
                parts.push(format!(
                    "loads from another user's home directory (likely a leaked build path): {}",
                    home_paths.join(", ")
                ));
            }
            findings.push((path_weight, parts.join("; ")));
        }
        if !entitlement_buckets.is_empty() {
            // List in SUSPICIOUS_ENTITLEMENTS's fixed order for a deterministic
            // description regardless of slice/HashMap iteration order.
            let keys: Vec<&'static str> = SUSPICIOUS_ENTITLEMENTS
                .iter()
                .map(|ent| ent.key)
                .filter(|key| entitlement_buckets.contains_key(key))
                .collect();
            let signed_keys = entitlement_buckets
                .values()
                .filter(|&&b| b == EntitlementBucket::Signed)
                .count();
            let cap_signed = signed_keys >= 2 && anchored();
            let weight = entitlements_weight(entitlement_buckets.values().copied(), cap_signed);
            let any_adhoc = entitlement_buckets
                .values()
                .any(|&b| b == EntitlementBucket::AdHoc);
            let description = if any_adhoc {
                format!(
                    "requests suspicious entitlement(s) on an ad-hoc-signed binary: {}",
                    keys.join(", ")
                )
            } else {
                format!("requests suspicious entitlement(s): {}", keys.join(", "))
            };
            findings.push((weight, description));
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

/// Combined weight of the requested entitlements: ad-hoc ones count in full;
/// signed ones sum, capped at `SIGNED_ENTITLEMENTS_CAP` in total only when
/// `cap_signed` (the signature verified to an Apple anchor, §5.2).
fn entitlements_weight(buckets: impl Iterator<Item = EntitlementBucket>, cap_signed: bool) -> i32 {
    let (adhoc, signed) = buckets.fold((0, 0), |(a, s), b| match b {
        EntitlementBucket::AdHoc => (a + b.weight(), s),
        EntitlementBucket::Signed => (a, s + b.weight()),
    });
    adhoc
        + if cap_signed {
            signed.min(SIGNED_ENTITLEMENTS_CAP)
        } else {
            signed
        }
}

/// Score this slice's entitlements, if any were recovered — the suspicious
/// keys it requests, each with its own ad-hoc/identity weight; the caller
/// unions these across a fat binary's slices rather than scoring each slice
/// separately (§5.2). `Ok(None)` covers "no code signature at all"
/// (entitlements live inside one, so there's nothing to examine), "signed
/// and we held the whole file but found no entitlements blob" (a determined
/// fact), and "signed, entitlements present, none of them suspicious."
/// `Err(NotApplicable)` only when the slice is signed and its
/// `LC_CODE_SIGNATURE` region is undetermined (unread, or read but
/// unparseable, §5.2, #45, #55): that can't be told apart from a real
/// entitlements blob (§10/§11.8). A region past an authoritative EOF is
/// determined: no entitlements.
fn entitlements_finding(
    image: &MachOImage,
) -> Result<Option<Vec<(&'static str, EntitlementBucket)>>, RuleOutcome> {
    let Some(xml) = &image.entitlements else {
        return if image.has_code_signature && !image.signature_region.is_determined() {
            Err(RuleOutcome::NotApplicable)
        } else {
            Ok(None)
        };
    };
    let Some(parsed) = plist::parse(xml) else {
        return Err(RuleOutcome::NotApplicable); // malformed entitlements blob
    };

    // Ad-hoc vs. a real signing identity, not signed vs. unsigned: entitlements
    // only ever come from inside a code signature, so `has_code_signature` is
    // always true here. The CS_ADHOC bit is self-declared by the signer, so a
    // slice also counts as ad-hoc when it has no non-empty CMS blob — a real
    // identity signature carries certificate data there, a hand ad-hoc one
    // has the wrapper but empty, a linker signature has none (#37). `None`
    // means no CodeDirectory could be recovered at all.
    let is_adhoc_known = image
        .code_directory_flags
        .map(|flags| flags & CS_ADHOC != 0 || !image.has_cms_signature);
    let is_adhoc = is_adhoc_known.unwrap_or(false); // unknown falls back to the real-identity weight

    let mut contributing: Vec<(&'static str, EntitlementBucket)> = Vec::new();
    for ent in SUSPICIOUS_ENTITLEMENTS {
        if parsed.get(ent.key).and_then(PlistValue::as_bool) != Some(true) {
            continue;
        }
        match ent.policy {
            EntitlementPolicy::WeightedByIdentity => {
                let bucket = if is_adhoc {
                    EntitlementBucket::AdHoc
                } else {
                    EntitlementBucket::Signed
                };
                contributing.push((ent.key, bucket));
            }
            // Ad-hoc or unknown flags: not identity-confirmed, so this
            // entitlement contributes nothing and isn't listed.
            EntitlementPolicy::IdentityOnly if is_adhoc_known == Some(false) => {
                contributing.push((ent.key, EntitlementBucket::Signed));
            }
            EntitlementPolicy::IdentityOnly => {}
        }
    }

    if contributing.is_empty() {
        Ok(None)
    } else {
        Ok(Some(contributing))
    }
}

/// Weight of a flagged load path, `None` if it isn't flagged: an absolute
/// path into a transient/user-writable location, or one with a hidden
/// directory component. `@executable_path`/`@loader_path`/`@rpath` forms,
/// relative paths and Apple system locations are never flagged. The path is
/// judged after `normalize_load_path`; only a plain-ASCII, non-`Shared`
/// `/Users/<name>/…` path with no hidden component and no `..` in its
/// original form scores `USER_HOME_PATH_WEIGHT`, everything else flagged
/// scores `TRANSIENT_LOCATION_WEIGHT` (§5.2). The `..` check stays because
/// dyld resolves `..` after symlinks, which lexical normalization can't see.
fn load_path_weight(path: &str) -> Option<i32> {
    if !path.starts_with('/') {
        return None; // `@…` forms and relative paths aren't judged
    }
    let n = normalize_load_path(path);

    const SYSTEM_PREFIXES: &[&str] = &["/system/", "/usr/lib/", "/library/"];
    if SYSTEM_PREFIXES.iter().any(|p| n.starts_with(p)) {
        return None;
    }
    let hidden = n.split('/').any(|c| c.len() > 1 && c.starts_with('.'));
    let transient = super::TRANSIENT_PREFIXES.iter().any(|p| {
        n.as_bytes()
            .get(..p.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(p.as_bytes()))
    });
    let home = n.strip_prefix("/users/");
    if !(transient || hidden || home.is_some()) {
        return None;
    }
    let plain_other_user = home.is_some_and(|rest| {
        let user = rest.split('/').next().unwrap_or("");
        user != "shared"
            && !user.is_empty()
            && user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    });
    let demotable =
        plain_other_user && !transient && !hidden && !path.split('/').any(|c| c == "..");
    Some(if demotable {
        USER_HOME_PATH_WEIGHT
    } else {
        TRANSIENT_LOCATION_WEIGHT
    })
}

/// Lexical form of an absolute path for location checks: repeated `/`
/// collapsed, `.` dropped, `..` resolved (clamped at the root), a leading
/// `/System/Volumes/Data` (the firmlinked data volume) removed, and ASCII
/// lowercased (APFS is case-insensitive by default). Scoped to this rule;
/// the original string is kept for messages.
fn normalize_load_path(path: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(c.to_ascii_lowercase()),
        }
    }
    if parts.len() > 3 && parts[..3] == ["system", "volumes", "data"] {
        parts.drain(..3);
    }
    format!("/{}", parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContentSource, ScanContext, MAX_CONTENT_BYTES};
    use crate::macho::tests_support::{
        synth_fat, synth_fat_with_bogus_arches, synth_macho_64_full,
        synth_macho_64_full_with_cd_flags, synth_macho_64_full_with_cds_and_cms,
    };
    use crate::macho::MAX_SIGNATURE_BYTES;
    use crate::test_support::write_temp_file;
    use std::path::PathBuf;

    fn flagged(path: &str) -> bool {
        load_path_weight(path).is_some()
    }

    fn ctx_for(content: Vec<u8>) -> ScanContext {
        ctx_for_truncated(content, false)
    }

    fn ctx_for_truncated(content: Vec<u8>, truncated: bool) -> ScanContext {
        // `file_len` must match `content` for these in-memory-only fixtures:
        // `ctx.macho()` reads through `ByteSource::source_len`, not `content`
        // directly, so an unset length would make every offset look
        // out-of-bounds.
        let file_len = Some(content.len() as u64);
        ScanContext {
            path: PathBuf::from("test-binary"),
            content: Some(content),
            truncated,
            file_len,
            identity: None,
            source: ContentSource::File,
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
            stream_failures: std::sync::Mutex::new(Vec::new()),
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
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
            stream_failures: std::sync::Mutex::new(Vec::new()),
        };
        assert!(matches!(
            MachOStructureRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// A stale, much larger `file_len` with no file handle to serve bytes
    /// past `content` (the shape a real object shrinking after load takes)
    /// must not make `ctx.macho()` read a real magic in `content` as "not
    /// Mach-O": it's still recognized, just unwalkable, so `covers_truncation`
    /// must not claim coverage over a scan that couldn't finish (§10/§11.8).
    #[test]
    fn stale_file_len_with_no_handle_is_undetermined_not_covered() {
        let c = ScanContext {
            path: PathBuf::from("app"),
            content: Some(b"\xfe\xed\xfa\xcf".to_vec()), // MH_MAGIC_64
            truncated: true,
            file_len: Some(u64::MAX),
            identity: None,
            source: ContentSource::File,
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
            stream_failures: std::sync::Mutex::new(Vec::new()),
        };
        assert!(
            c.macho().is_macho,
            "the magic in content must be recognized"
        );
        assert!(!c.macho().fully_examined());
        assert!(!MachOStructureRule.covers_truncation(&c));
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
    fn load_path_weights_by_location() {
        let w = |p: &str| {
            let (image, _, _) = synth_macho_64_full(b"code", &[], &[p], false, None);
            MachOStructureRule
                .evaluate(&ctx_for(image))
                .unwrap()
                .map(|s| s.weight)
        };
        assert_eq!(w("/Users/builder/proj/lib"), Some(USER_HOME_PATH_WEIGHT));
        assert_eq!(w("/Users/Shared/x"), Some(TRANSIENT_LOCATION_WEIGHT));
        assert_eq!(w("/Users/shared/x"), Some(TRANSIENT_LOCATION_WEIGHT));
        assert_eq!(w("/Users/x/.hidden/lib"), Some(TRANSIENT_LOCATION_WEIGHT));
        assert_eq!(w("/tmp/x"), Some(TRANSIENT_LOCATION_WEIGHT));
        assert_eq!(w("/var/folders/zz/T/x"), Some(TRANSIENT_LOCATION_WEIGHT));
        assert_eq!(w("/opt/app/.cache/lib"), Some(TRANSIENT_LOCATION_WEIGHT));
        assert_eq!(
            w("/Users/x/../Shared/evil.dylib"),
            Some(TRANSIENT_LOCATION_WEIGHT)
        );
        assert_eq!(w("/Users/x/../../tmp/e"), Some(TRANSIENT_LOCATION_WEIGHT));
        for bypass in [
            "/Users//Shared/libevil.dylib",
            "/Users/./Shared/libevil.dylib",
            "/USERS/SHARED/x",
            "/TMP/x",
            "//tmp/x",
            "/private//tmp/x",
            "/System/Volumes/Data/Users/Shared/evil.dylib",
            "/Library/../tmp/evil.dylib",
            "/System/../private/tmp/e.dylib",
            "/Users/\u{17f}hared/x",
            "/Users/b\u{fc}ilder/x",
        ] {
            assert_eq!(w(bypass), Some(TRANSIENT_LOCATION_WEIGHT), "{bypass}");
        }
        assert_eq!(w("/Users//builder/./proj"), Some(USER_HOME_PATH_WEIGHT));
        assert_eq!(w("/usr/lib/x"), None);
        assert_eq!(w("/System/Library/x"), None);
        assert_eq!(w("/System/Volumes/Data/Library/x"), None);
    }

    #[test]
    fn description_names_the_kind_of_path() {
        let desc = |dylibs: &[&str], rpaths: &[&str]| {
            let (image, _, _) = synth_macho_64_full(b"code", dylibs, rpaths, false, None);
            MachOStructureRule
                .evaluate(&ctx_for(image))
                .unwrap()
                .expect("should fire")
                .description
        };
        let home = desc(&[], &["/Users/builder/work/lib"]);
        assert!(home.contains("another user's home directory (likely a leaked build path)"));
        assert!(home.contains("/Users/builder/work/lib"));
        assert!(!home.contains("writable/transient"));

        let tmp = desc(&[], &["/tmp/x"]);
        assert!(tmp.contains("writable/transient location: /tmp/x"));
        assert!(!tmp.contains("another user's home"));

        let mixed = desc(&["/Users/builder/l.dylib"], &["/tmp/x"]);
        assert!(mixed.contains("writable/transient location: /tmp/x"));
        assert!(mixed.contains(
            "another user's home directory (likely a leaked build path): /Users/builder/l.dylib"
        ));
    }

    #[test]
    fn a_tmp_path_alongside_a_home_path_keeps_the_higher_weight() {
        let (image, _, _) = synth_macho_64_full(
            b"code",
            &["/Users/builder/lib.dylib"],
            &["/tmp/x"],
            false,
            None,
        );
        let sig = MachOStructureRule
            .evaluate(&ctx_for(image))
            .unwrap()
            .expect("should fire");
        assert_eq!(sig.weight, TRANSIENT_LOCATION_WEIGHT);
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

        // CS_ADHOC clear, but no non-empty CMS blob backing the signature —
        // the ad-hoc bit alone isn't the whole story; a signer that never
        // attached a real identity is still ad-hoc (#37).
        let (claimed_identity, _, _) = synth_macho_64_full_with_cds_and_cms(
            b"code",
            &[],
            &[],
            true,
            Some(xml),
            &[(0, 0)], // slot 0, flags=0 — no CS_ADHOC bit, but no CMS blob either
            None,
        );
        let claimed_identity_sig = MachOStructureRule
            .evaluate(&ctx_for(claimed_identity))
            .unwrap()
            .expect("should fire");
        assert_eq!(
            claimed_identity_sig.weight, ENTITLEMENT_WEIGHT_ADHOC,
            "flags=0 with no CMS blob must still read as ad-hoc"
        );
        assert!(claimed_identity_sig.description.contains("ad-hoc"));

        // CS_ADHOC clear AND a non-empty CMS blob: a genuine identity signature.
        let (identity, _, _) = synth_macho_64_full_with_cds_and_cms(
            b"code",
            &[],
            &[],
            true,
            Some(xml),
            &[(0, 0)],
            Some(4),
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

    const THREE_ENTITLEMENTS: &[u8] = br#"<?xml version="1.0"?><plist version="1.0"><dict>
        <key>com.apple.security.cs.disable-library-validation</key><true/>
        <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
        <key>com.apple.security.cs.disable-executable-page-protection</key><true/>
    </dict></plist>"#;

    #[test]
    fn anchored_real_identity_entitlements_are_capped_in_total() {
        let (image, _, _) = synth_macho_64_full_with_cds_and_cms(
            b"code",
            &[],
            &[],
            true,
            Some(THREE_ENTITLEMENTS),
            &[(0, 0)],
            Some(4),
        );
        let sig = MachOStructureRule
            .evaluate_with(&ctx_for(image), || true)
            .unwrap()
            .expect("should fire");
        assert_eq!(sig.weight, SIGNED_ENTITLEMENTS_CAP);
        assert!(sig.description.contains("disable-library-validation"));
        assert!(sig.description.contains("allow-dyld-environment-variables"));
        assert!(sig
            .description
            .contains("disable-executable-page-protection"));
    }

    #[test]
    fn unanchored_or_unknown_identity_entitlements_are_not_capped() {
        // A CMS blob that doesn't verify to an Apple anchor (e.g. self-signed).
        let (cms, _, _) = synth_macho_64_full_with_cds_and_cms(
            b"code",
            &[],
            &[],
            true,
            Some(THREE_ENTITLEMENTS),
            &[(0, 0)],
            Some(4),
        );
        let sig = MachOStructureRule
            .evaluate_with(&ctx_for(cms), || false)
            .unwrap()
            .expect("should fire");
        assert_eq!(sig.weight, 3 * ENTITLEMENT_WEIGHT_SIGNED);

        // Unknown CodeDirectory flags and no CMS: uncapped through the real
        // check too (no verifiable file here, so it can't say "anchored").
        let (unknown, _, _) =
            synth_macho_64_full(b"code", &[], &[], true, Some(THREE_ENTITLEMENTS));
        let sig = MachOStructureRule
            .evaluate(&ctx_for(unknown))
            .unwrap()
            .expect("should fire");
        assert_eq!(sig.weight, 3 * ENTITLEMENT_WEIGHT_SIGNED);
    }

    #[test]
    fn anchor_check_runs_only_when_the_cap_could_matter() {
        let one = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;
        let (image, _, _) = synth_macho_64_full(b"code", &[], &[], true, Some(one));
        let _ = MachOStructureRule.evaluate_with(&ctx_for(image), || {
            panic!("a single signed entitlement must not trigger the anchor check")
        });
    }

    #[test]
    fn adhoc_entitlements_are_not_subject_to_the_signed_cap() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
            <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
        </dict></plist>"#;
        let (image, _, _) =
            synth_macho_64_full_with_cd_flags(b"code", &[], &[], true, Some(xml), Some(CS_ADHOC));
        let sig = MachOStructureRule
            .evaluate(&ctx_for(image))
            .unwrap()
            .expect("should fire");
        // 2 x 18 = 36, clamped by the rule-wide MAX_WEIGHT.
        assert_eq!(sig.weight, MAX_WEIGHT);
    }

    #[test]
    fn mixed_fat_binary_caps_only_the_signed_weighted_keys() {
        let adhoc_xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;
        let signed_xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
            <key>com.apple.security.cs.disable-executable-page-protection</key><true/>
        </dict></plist>"#;
        let (adhoc, _, _) = synth_macho_64_full_with_cd_flags(
            b"aaaa",
            &[],
            &[],
            true,
            Some(adhoc_xml),
            Some(CS_ADHOC),
        );
        let (signed, _, _) = synth_macho_64_full_with_cds_and_cms(
            b"bbbb",
            &[],
            &[],
            true,
            Some(signed_xml),
            &[(0, 0)],
            Some(4),
        );
        let fat = synth_fat(&[&adhoc, &signed]);
        let sig = MachOStructureRule
            .evaluate_with(&ctx_for(fat), || true)
            .unwrap()
            .expect("should fire");
        assert_eq!(
            sig.weight,
            ENTITLEMENT_WEIGHT_ADHOC + SIGNED_ENTITLEMENTS_CAP
        );
    }

    #[test]
    fn get_task_allow_on_an_adhoc_binary_scores_nothing() {
        // Xcode adds get-task-allow to every Debug build, and Debug builds
        // are always ad-hoc signed ("Sign to Run Locally") — the ordinary
        // dev-build state, not an anomaly (#37).
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.get-task-allow</key><true/>
        </dict></plist>"#;
        let (image, _, _) =
            synth_macho_64_full_with_cd_flags(b"code", &[], &[], true, Some(xml), Some(CS_ADHOC));
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(image)),
            Ok(None)
        ));
    }

    #[test]
    fn get_task_allow_on_an_identity_signed_binary_is_flagged() {
        // Notarization rejects get-task-allow on a real identity, so there
        // it's still meaningful.
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.get-task-allow</key><true/>
        </dict></plist>"#;
        let (image, _, _) = synth_macho_64_full_with_cds_and_cms(
            b"code",
            &[],
            &[],
            true,
            Some(xml),
            &[(0, 0)], // slot 0, flags=0 — no CS_ADHOC bit
            Some(4),   // and a non-empty CMS blob — a confirmed real identity
        );
        let sig = MachOStructureRule
            .evaluate(&ctx_for(image))
            .unwrap()
            .expect("should fire");
        assert_eq!(sig.weight, ENTITLEMENT_WEIGHT_SIGNED);
        assert!(sig.description.contains("get-task-allow"));
    }

    #[test]
    fn get_task_allow_alongside_an_adhoc_weighted_entitlement_is_excluded_from_the_finding() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
            <key>com.apple.security.get-task-allow</key><true/>
        </dict></plist>"#;
        let (image, _, _) =
            synth_macho_64_full_with_cd_flags(b"code", &[], &[], true, Some(xml), Some(CS_ADHOC));
        let sig = MachOStructureRule
            .evaluate(&ctx_for(image))
            .unwrap()
            .expect("should fire");
        assert_eq!(
            sig.weight, ENTITLEMENT_WEIGHT_ADHOC,
            "only the ad-hoc-weighted entitlement should contribute"
        );
        assert!(sig.description.contains("disable-library-validation"));
        assert!(!sig.description.contains("get-task-allow"));
    }

    #[test]
    fn get_task_allow_with_unknown_flags_scores_nothing() {
        // No CodeDirectory recovered at all: not confirmed identity-signed,
        // so get-task-allow must not assume the worse case either.
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.get-task-allow</key><true/>
        </dict></plist>"#;
        let (image, _, _) = synth_macho_64_full(b"code", &[], &[], true, Some(xml));
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(image)),
            Ok(None)
        ));
    }

    #[test]
    fn get_task_allow_scores_nothing_when_flags_are_zero_with_no_cms_blob() {
        // flags=0 (no CS_ADHOC) but no CMS blob backing it reads as ad-hoc
        // under the new rule, not a confirmed identity — get-task-allow must
        // not score here either (#37).
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.get-task-allow</key><true/>
        </dict></plist>"#;
        let (image, _, _) = synth_macho_64_full_with_cds_and_cms(
            b"code",
            &[],
            &[],
            true,
            Some(xml),
            &[(0, 0)],
            None,
        );
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(image)),
            Ok(None)
        ));
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
        let full_len = image.len() as u64;
        image.truncate(sig_off + 4);
        let mut ctx = ctx_for_truncated(image, true);
        ctx.file_len = Some(full_len); // the real file is longer than the capture
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx),
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
    fn flagged_examples() {
        assert!(flagged("/tmp/evil"));
        assert!(flagged("/private/tmp/evil"));
        assert!(flagged("/var/tmp/evil"));
        assert!(flagged("/Users/Shared/evil"));
        assert!(flagged("/Users/alice/evil"));
        assert!(flagged("/opt/app/.hidden/lib"));
        assert!(flagged("/private/var/folders/xy/abc/T/libevil.dylib"));
        assert!(flagged("/var/folders/xy/abc/T/libevil.dylib"));

        assert!(!flagged("@executable_path/../Frameworks"));
        assert!(!flagged("@loader_path/lib.dylib"));
        assert!(!flagged("@rpath/lib.dylib"));
        assert!(!flagged("/System/Library/x"));
        assert!(!flagged("/usr/lib/libSystem.B.dylib"));
        assert!(!flagged("/Library/Frameworks/x"));
        assert!(!flagged("libFoo.dylib")); // relative, not judged
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
    fn same_entitlement_in_two_ad_hoc_slices_is_unioned_not_repeated() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;
        let (a, _, _) =
            synth_macho_64_full_with_cd_flags(b"aaaa", &[], &[], true, Some(xml), Some(CS_ADHOC));
        let (b, _, _) =
            synth_macho_64_full_with_cd_flags(b"bbbb", &[], &[], true, Some(xml), Some(CS_ADHOC));
        let fat = synth_fat(&[&a, &b]);

        let sig = MachOStructureRule
            .evaluate(&ctx_for(fat))
            .unwrap()
            .expect("should fire");
        assert_eq!(sig.weight, ENTITLEMENT_WEIGHT_ADHOC);
        assert_eq!(
            sig.description
                .matches("disable-library-validation")
                .count(),
            1,
            "the key must be listed once, not once per slice"
        );
    }

    #[test]
    fn same_entitlement_ad_hoc_in_one_slice_and_identity_in_another_takes_the_worse_weight() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;
        let (adhoc, _, _) =
            synth_macho_64_full_with_cd_flags(b"aaaa", &[], &[], true, Some(xml), Some(CS_ADHOC));
        let (identity, _, _) = synth_macho_64_full_with_cds_and_cms(
            b"bbbb",
            &[],
            &[],
            true,
            Some(xml),
            &[(0, 0)], // slot 0, flags=0
            Some(4),   // non-empty CMS blob — a confirmed real identity
        );
        let fat = synth_fat(&[&adhoc, &identity]);

        let sig = MachOStructureRule
            .evaluate(&ctx_for(fat))
            .unwrap()
            .expect("should fire");
        assert_eq!(
            sig.weight, ENTITLEMENT_WEIGHT_ADHOC,
            "a key requested by both an ad-hoc and an identity slice takes the worse weight"
        );
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
        // clean slice reading as scored-fine (#38).
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
        // #46: a fat binary shaped like the verified regression — 24 bogus
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

    /// A thin Mach-O whose code signature (entitlements + ad-hoc CD flags)
    /// sits past the 8 MiB prefix must still be examined by offset: the rule
    /// reports the entitlement, and `covers_truncation` confirms the scan was
    /// complete despite `ctx.truncated` (§5.2, #45).
    #[test]
    fn signature_past_8mib_is_examined_by_offset() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;
        let padding = vec![0u8; MAX_CONTENT_BYTES + 4096];
        let (bytes, _, sig_off) =
            synth_macho_64_full_with_cd_flags(&padding, &[], &[], true, Some(xml), Some(CS_ADHOC));
        assert!(
            sig_off > MAX_CONTENT_BYTES,
            "fixture must actually place the signature past the prefix"
        );

        let path = write_temp_file("sig-past-prefix", &bytes);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);

        let sig = MachOStructureRule
            .evaluate(&ctx)
            .unwrap()
            .expect("the entitlement past the prefix must still be reported");
        assert!(sig.description.contains("disable-library-validation"));
        assert!(MachOStructureRule.covers_truncation(&ctx));

        let _ = std::fs::remove_file(&path);
    }

    /// A fat binary whose second slice (and the dylib load path inside it)
    /// lies entirely past the 8 MiB prefix must still be judged on that
    /// slice, not just the first (§5.2, #45).
    #[test]
    fn a_fat_slice_past_8mib_loading_from_tmp_is_reported() {
        let padding = vec![0u8; MAX_CONTENT_BYTES + 4096];
        let (first, _, _) = synth_macho_64_full(&padding, &[], &[], false, None);
        let (second, _, _) = synth_macho_64_full(b"evil", &["/tmp/evil.dylib"], &[], false, None);
        let fat = synth_fat(&[&first, &second]);

        let path = write_temp_file("fat-slice-past-prefix", &fat);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);

        let sig = MachOStructureRule
            .evaluate(&ctx)
            .unwrap()
            .expect("the second slice's dylib load must still be reported");
        assert!(sig.description.contains("/tmp/evil.dylib"));
        assert!(MachOStructureRule.covers_truncation(&ctx));

        let _ = std::fs::remove_file(&path);
    }

    /// A fat header whose declared slices lie past the 8 MiB prefix, on a
    /// file that shrank out from under the loaded context (an I/O error on
    /// every slice-magic read): the scan must report `is_macho: true` with
    /// both slices skipped as undetermined, never "not Mach-O" — and the
    /// rule must not claim `covers_truncation` over a scan it couldn't
    /// finish (§10/§11.8, §5.2).
    #[test]
    fn fat_header_whose_slices_become_unreadable_is_undetermined_not_clean() {
        // Both slices placed well past the 8 MiB prefix (unlike `synth_fat`,
        // which would put the first slice early enough to be read straight
        // out of `content`, unaffected by the file shrinking below) — every
        // slice-magic read must go through the file handle.
        let (a, _, _) = synth_macho_64_full(b"aa", &[], &[], false, None);
        let (b, _, _) = synth_macho_64_full(b"bb", &[], &[], false, None);
        let a_off = MAX_CONTENT_BYTES + 4096;
        let b_off = a_off + a.len() + 4096;

        let mut fat = Vec::new();
        fat.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]); // FAT_MAGIC
        fat.extend_from_slice(&2u32.to_be_bytes()); // nfat_arch
        fat.extend_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
        fat.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        fat.extend_from_slice(&(a_off as u32).to_be_bytes()); // offset
        fat.extend_from_slice(&(a.len() as u32).to_be_bytes()); // size
        fat.extend_from_slice(&0u32.to_be_bytes()); // align
        fat.extend_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
        fat.extend_from_slice(&1u32.to_be_bytes()); // cpusubtype
        fat.extend_from_slice(&(b_off as u32).to_be_bytes()); // offset
        fat.extend_from_slice(&(b.len() as u32).to_be_bytes()); // size
        fat.extend_from_slice(&0u32.to_be_bytes()); // align
        fat.resize(a_off, 0);
        fat.extend_from_slice(&a);
        fat.resize(b_off, 0);
        fat.extend_from_slice(&b);

        let path = write_temp_file("fat-slices-become-unreadable", &fat);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);

        // Shrink the file out from under the already-loaded context: the fat
        // header itself was captured in `content` and still parses, but a
        // slice-magic read past the 8 MiB prefix now hits real EOF instead
        // of finding the slice.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(8)
            .unwrap();

        let scan = ctx.macho();
        assert!(
            scan.is_macho,
            "an unreadable slice must not read as not Mach-O"
        );
        assert!(scan.images.is_empty());
        assert_eq!(scan.skipped_slices, 2);
        assert!(!MachOStructureRule.covers_truncation(&ctx));
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx),
            Err(RuleOutcome::NotApplicable)
        ));

        let _ = std::fs::remove_file(&path);
    }

    /// A truncated embedded/container member (extraction stopped at a
    /// budget) whose fat table declares a slice past the captured bytes:
    /// unlike a real file's EOF, `source_len` here is only how much was
    /// captured, not the member's true size, so this must read as
    /// `NotApplicable`, not `Ok(None)` (§10/§11.8, §5.2).
    #[test]
    fn truncated_embedded_fat_header_whose_slice_lies_beyond_the_capture_is_not_applicable() {
        let (real, _, _) = synth_macho_64_full(b"real", &[], &[], false, None);
        let fat = synth_fat(&[&real]);
        let header_and_table_len = 8 + 20; // fat_header + one fat_arch entry
        let captured = fat[..header_and_table_len].to_vec();

        let ctx = ScanContext::from_embedded_bytes("x.pkg!member", captured, true);
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// As above, for a thin slice: a truncated embedded member whose header
    /// declares load commands running past the captured bytes must not be
    /// read as if the missing tail (an `LC_LOAD_DYLIB`, say) were simply
    /// absent (§10/§11.8, §5.2).
    #[test]
    fn truncated_embedded_thin_header_whose_load_commands_run_past_the_capture_is_not_applicable() {
        let (full, _, _) = synth_macho_64_full(b"x", &["/tmp/evil.dylib"], &[], false, None);
        let captured = full[..40].to_vec(); // header plus a few bytes, well short of sizeofcmds

        let ctx = ScanContext::from_embedded_bytes("x.pkg!member", captured, true);
        assert!(!MachOStructureRule.covers_truncation(&ctx));
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// A signed Mach-O whose `LC_CODE_SIGNATURE` datasize runs 1000 bytes
    /// past the end of the bytes.
    fn signature_past_eof_bytes() -> Vec<u8> {
        let (mut image, _, sig_off) = synth_macho_64_full(b"code", &[], &[], true, None);
        let lc_off = image
            .windows(4)
            .position(|w| w == 0x1du32.to_le_bytes())
            .expect("LC_CODE_SIGNATURE present");
        let huge = (image.len() - sig_off) as u32 + 1000;
        image[lc_off + 12..lc_off + 16].copy_from_slice(&huge.to_le_bytes());
        image
    }

    /// A complete small Mach-O whose signature is declared past its own EOF
    /// has nothing to read: determined, no entitlements, coverage kept.
    #[test]
    fn signature_declared_past_an_authoritative_eof_is_determined() {
        let ctx = ctx_for(signature_past_eof_bytes());
        assert!(MachOStructureRule.covers_truncation(&ctx));
        assert!(matches!(MachOStructureRule.evaluate(&ctx), Ok(None)));
    }

    /// A complete Mach-O whose signature region is read but whose SuperBlob
    /// can't be walked is undetermined, not clean.
    #[test]
    fn unwalkable_signature_superblob_is_not_applicable() {
        use crate::macho::tests_support::{synth_macho_64_bad_superblob, SuperBlobFault};
        for fault in [
            SuperBlobFault::BadMagic,
            SuperBlobFault::TooManyBlobs,
            SuperBlobFault::ShortRegion,
            SuperBlobFault::IndexPastRegion,
            SuperBlobFault::BlobOffsetOutside,
        ] {
            let ctx = ctx_for(synth_macho_64_bad_superblob(fault));
            assert!(
                matches!(
                    MachOStructureRule.evaluate(&ctx),
                    Err(RuleOutcome::NotApplicable)
                ),
                "{fault:?}"
            );
        }
    }

    /// A valid signed Mach-O with no entitlements is still clean.
    #[test]
    fn valid_signature_without_entitlements_is_clean() {
        let (bytes, _, _) = synth_macho_64_full(b"code", &[], &[], true, None);
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx_for(bytes)),
            Ok(None)
        ));
    }

    /// The same bytes as a truncated embedded member: the true length is
    /// unknown, so the region is undetermined.
    #[test]
    fn signature_declared_past_a_truncated_embedded_capture_is_not_applicable() {
        let ctx =
            ScanContext::from_embedded_bytes("x.pkg!member", signature_past_eof_bytes(), true);
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// A signature whose declared `datasize` exceeds `MAX_SIGNATURE_BYTES`
    /// must not be read at all: `covers_truncation` is false, and — with no
    /// other finding — the rule reports `NotApplicable` rather than a clean
    /// bill of health (§5.2, #45).
    #[test]
    fn signature_declaring_more_than_the_signature_cap_is_not_read() {
        let padding = vec![0u8; MAX_CONTENT_BYTES + 4096];
        let (mut bytes, _, _) =
            synth_macho_64_full_with_cd_flags(&padding, &[], &[], true, None, Some(CS_ADHOC));
        let lc_off = bytes
            .windows(4)
            .position(|w| w == [0x1d, 0, 0, 0]) // LC_CODE_SIGNATURE, little-endian
            .expect("LC_CODE_SIGNATURE present");
        let huge_datasize = (MAX_SIGNATURE_BYTES as u32) + 1;
        bytes[lc_off + 12..lc_off + 16].copy_from_slice(&huge_datasize.to_le_bytes());

        let path = write_temp_file("signature-over-cap", &bytes);
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);

        assert!(!MachOStructureRule.covers_truncation(&ctx));
        assert!(matches!(
            MachOStructureRule.evaluate(&ctx),
            Err(RuleOutcome::NotApplicable)
        ));

        let _ = std::fs::remove_file(&path);
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
        synth_fat, synth_fat_with_bogus_arches_aligned, synth_macho_64_duplicate_code_signature,
        synth_macho_64_full, synth_macho_64_full_with_cd_flags,
        synth_macho_64_full_with_cds_and_cms,
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

        // Benign: an ad-hoc "Sign to Run Locally" Xcode Debug build shape —
        // CS_ADHOC CodeDirectory flags, app-sandbox + get-task-allow
        // entitlements (Xcode adds get-task-allow to every Debug build),
        // benign system dylibs only. get-task-allow must not score on an
        // ad-hoc binary (#37) — Xcode Debug builds are always ad-hoc-signed.
        let adhoc_debug_entitlements = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.app-sandbox</key><true/>
    <key>com.apple.security.get-task-allow</key><true/>
</dict></plist>"#;
        let (adhoc_debug, _, _) = synth_macho_64_full_with_cd_flags(
            b"\x55\x48\x89\xe5\x90adhoc debug build machine code padding to look real",
            &["/usr/lib/libSystem.B.dylib"],
            &[],
            true,
            Some(adhoc_debug_entitlements),
            Some(CS_ADHOC),
        );
        std::fs::write(
            root.join("benign/macho_adhoc_debug_get_task_allow"),
            adhoc_debug,
        )
        .unwrap();

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
        // (/private/var/folders/…), unsigned — the #39 gap this rule now covers.
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
        // — the higher of the two entitlement weights (#37). Benign system
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
        // its own (#38). The clean slice carries an `osascript` string so the
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

        // Suspicious: a fat binary shaped like the #46 regression — 24 bogus
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

        // Suspicious: thin, two LC_CODE_SIGNATURE commands — the first
        // carrying a real ad-hoc signature with disable-library-validation,
        // the second pointing at zero-length data. `parse_thin` must reject
        // this as malformed rather than let the second command silently
        // erase the first's facts (#37); an `osascript` string keeps
        // suspicious-strings firing on Ubuntu CI, where this rule reads back
        // as NotApplicable (no walkable image) and the completeness gate is
        // what pins this fixture's `partial` golden entry.
        let duplicate_cs_entitlements = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>"#;
        let duplicate_cs = synth_macho_64_duplicate_code_signature(
            b"\x55\x48\x89\xe5\x90 shells out via osascript for testing",
            Some(duplicate_cs_entitlements),
            Some(CS_ADHOC),
        );
        std::fs::write(
            root.join("suspicious/macho_duplicate_code_signature"),
            duplicate_cs,
        )
        .unwrap();

        // Suspicious: a CodeDirectory with flags=0 (no CS_ADHOC bit) and no
        // CMS blob at all — a signer that never attached a real identity.
        // The CS_ADHOC bit is self-declared, so this must still read as
        // ad-hoc rather than as an unrecognized "identity" (#37). An
        // `osascript` string keeps suspicious-strings firing on Ubuntu CI.
        let identity_claim_entitlements = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>"#;
        let (identity_claim, _, _) = synth_macho_64_full_with_cds_and_cms(
            b"\x55\x48\x89\xe5\x90 shells out via osascript for testing",
            &["/usr/lib/libSystem.B.dylib"],
            &[],
            true,
            Some(identity_claim_entitlements),
            &[(0, 0)], // slot 0, flags=0
            None,      // no CMS blob
        );
        std::fs::write(
            root.join("suspicious/macho_identity_claim_without_cms"),
            identity_claim,
        )
        .unwrap();

        // Suspicious: an identity-looking signature (non-empty CMS blob, no
        // CS_ADHOC) that doesn't verify to an Apple anchor, with JVM-style
        // entitlements. A self-signed certificate looks like this; only an
        // Apple-anchored identity earns the cap (§5.2).
        let jvm_entitlements = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.security.cs.disable-library-validation</key><true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <key>com.apple.security.cs.allow-jit</key><true/>
</dict></plist>"#;
        let (jvm, _, _) = synth_macho_64_full_with_cds_and_cms(
            b"\x55\x48\x89\xe5\x90jvm-like machine code padding to look real",
            &["/usr/lib/libSystem.B.dylib"],
            &[],
            true,
            Some(jvm_entitlements),
            &[(0, 0)],
            Some(4),
        );
        std::fs::write(
            root.join("suspicious/macho_unanchored_identity_jvm_entitlements"),
            jvm,
        )
        .unwrap();

        // Benign: unsigned, with LC_RPATHs into a leaked build directory under
        // another user's home (Steam's libavif shape). Corroboration-only (§5.2).
        let (leaked, _, _) = synth_macho_64_full(
            b"\x55\x48\x89\xe5\x90leaked build rpath machine code padding to look real",
            &["/usr/lib/libSystem.B.dylib"],
            &["/Users/builder/work/build/lib"],
            false,
            None,
        );
        std::fs::write(root.join("benign/macho_leaked_build_rpath"), leaked).unwrap();
    }
}
