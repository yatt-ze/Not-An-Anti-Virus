//! Bundle-level signals (§5.8): judgements about an `.app` as a whole, made
//! from what each member's own scan already learned. Pure over
//! [`MemberFacts`]; `target.rs` collects the facts and applies the findings.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use crate::model::{MatchedSignal, SignalCategory};

/// Weight when the main executable's signer differs from the bundle's.
const MISMATCH_WEIGHT: i32 = 4;
/// Weight when the main executable also carries no real identity.
const MISMATCH_WEAK_WEIGHT: i32 = 6;
/// Added when the main executable lacks hardened runtime and most siblings have it.
const NO_RUNTIME_BONUS: i32 = 2;
/// Weight for a load command that reaches into `Contents/Resources/`.
const LOAD_FROM_RESOURCES_WEIGHT: i32 = 6;
/// Most `@rpath/` expansions checked per member; past it the load check is a gap.
const MAX_RPATH_LOOKUPS: usize = 4096;
/// Most that bundle signals may add to one member, so a self-signed main
/// executable (+5 from `unanchored-signing-identity`) stays under Notify (§5.1).
const MAX_PER_MEMBER: i32 = 8;
/// Fewest other Mach-O members with a signing summary for a signer majority to mean anything.
const MIN_SIBLINGS: usize = 3;

pub(crate) const MISMATCH_ID: &str = "bundle-signer-mismatch";
pub(crate) const LOAD_FROM_RESOURCES_ID: &str = "bundle-load-from-resources";

/// How a file is signed, as `codesign -dv` and the signer check classify it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigningKind {
    Unsigned,
    /// Hand-applied ad-hoc.
    AdHoc,
    /// Ad-hoc applied by the linker.
    LinkerSigned,
    /// A real identity that does not chain to an Apple anchor.
    SelfSigned,
    /// Any other real identity, Apple's included.
    Signed,
}

impl SigningKind {
    fn lacks_identity(self) -> bool {
        self != SigningKind::Signed
    }

    fn is_adhoc(self) -> bool {
        matches!(self, SigningKind::AdHoc | SigningKind::LinkerSigned)
    }
}

/// The parts of a file's `codesign -dv` report the bundle signals use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SigningSummary {
    pub(crate) kind: SigningKind,
    pub(crate) team_id: Option<String>,
    /// CodeDirectory flags carry the hardened-runtime bit.
    pub(crate) hardened: bool,
}

/// What one scanned member contributes to the bundle signals.
#[derive(Debug, Clone, Default)]
pub(crate) struct MemberFacts {
    pub(crate) is_macho: bool,
    /// `None` when `codesign` did not run or did not apply.
    pub(crate) signing: Option<SigningSummary>,
    /// Load paths of every slice.
    pub(crate) dylibs: Vec<String>,
    /// `LC_RPATH` entries of every slice, in load-command order.
    pub(crate) rpaths: Vec<String>,
}

/// A scanned member: its path under the bundle root and its facts.
pub(crate) struct Member {
    pub(crate) rel: PathBuf,
    pub(crate) facts: MemberFacts,
}

pub(crate) enum Finding {
    Signal(MatchedSignal),
    /// The check could not run; reported as a coverage gap, never as clean.
    NotApplicable(&'static str),
}

/// Findings per member index. `main` is the index of the main executable.
pub(crate) fn findings(members: &[Member], main: Option<usize>) -> Vec<(usize, Finding)> {
    let mut out = Vec::new();
    if let Some(m) = main {
        match signer_mismatch(members, m) {
            Mismatch::Clean => {}
            Mismatch::Unchecked => out.push((m, Finding::NotApplicable(MISMATCH_ID))),
            Mismatch::Fires(signal) => out.push((m, Finding::Signal(signal))),
        }
    }
    // Folded: dyld resolves against a case-insensitive volume by default.
    let by_rel: HashMap<String, usize> = members
        .iter()
        .enumerate()
        .map(|(i, m)| (fold(&m.rel), i))
        .collect();
    for (i, member) in members.iter().enumerate() {
        if in_nested_app(&member.rel) {
            continue;
        }
        match load_target(members, i, main, &by_rel) {
            Ok(Some(t)) => out.push((i, Finding::Signal(load_signal(&members[t].facts)))),
            Ok(None) => {}
            Err(()) => out.push((i, Finding::NotApplicable(LOAD_FROM_RESOURCES_ID))),
        }
    }
    cap_per_member(&mut out);
    out
}

/// Trim later signals so each member's bundle signals sum to at most
/// [`MAX_PER_MEMBER`]; one trimmed to nothing is dropped.
fn cap_per_member(out: &mut Vec<(usize, Finding)>) {
    let mut added: HashMap<usize, i32> = HashMap::new();
    out.retain_mut(|(i, finding)| {
        let Finding::Signal(signal) = finding else {
            return true;
        };
        let sum = added.entry(*i).or_default();
        signal.weight = signal.weight.min(MAX_PER_MEMBER - *sum);
        *sum += signal.weight.max(0);
        signal.weight > 0
    });
}

enum Mismatch {
    Clean,
    Unchecked,
    Fires(MatchedSignal),
}

/// `bundle-signer-mismatch` for the main executable at `main`.
fn signer_mismatch(members: &[Member], main: usize) -> Mismatch {
    let main_facts = &members[main].facts;
    if !main_facts.is_macho {
        return Mismatch::Clean;
    }
    let siblings: Vec<&SigningSummary> = members
        .iter()
        .enumerate()
        .filter(|(i, m)| *i != main && m.facts.is_macho && !in_nested_app(&m.rel))
        .filter_map(|(_, m)| m.facts.signing.as_ref())
        .collect();
    let Some(team) = majority_team(&siblings) else {
        return Mismatch::Clean;
    };
    let Some(signing) = main_facts.signing.as_ref() else {
        return Mismatch::Unchecked;
    };
    match trusted_team(signing) {
        Some(t) if t == team => return Mismatch::Clean,
        // A real identity whose Team ID couldn't be read: not comparable.
        None if signing.kind == SigningKind::Signed => return Mismatch::Unchecked,
        _ => {}
    }
    let weak = signing.kind.lacks_identity();
    let mut weight = if weak {
        MISMATCH_WEAK_WEIGHT
    } else {
        MISMATCH_WEIGHT
    };
    let mut description = format!(
        "main executable is not signed by the Team ID that signed most of the app's other code ({})",
        if weak {
            "it carries no Apple-anchored identity"
        } else {
            "it has a different signer"
        }
    );
    let hardened = siblings.iter().filter(|s| s.hardened).count();
    if !signing.hardened && hardened * 2 > siblings.len() {
        weight += NO_RUNTIME_BONUS;
        description.push_str("; it also lacks the hardened runtime most of that code has");
    }
    Mismatch::Fires(MatchedSignal {
        id: MISMATCH_ID.to_string(),
        weight,
        description,
        category: SignalCategory::ProvenanceConcern,
    })
}

/// `summary`'s Team ID, only for a real (Apple-anchored) identity:
/// `codesign -dv` prints the CodeDirectory's claim unverified.
fn trusted_team(summary: &SigningSummary) -> Option<&str> {
    (summary.kind == SigningKind::Signed)
        .then_some(summary.team_id.as_deref())
        .flatten()
}

/// The Team ID shared by at least 2/3 of `siblings`, if there are enough of them.
fn majority_team<'a>(siblings: &[&'a SigningSummary]) -> Option<&'a str> {
    if siblings.len() < MIN_SIBLINGS {
        return None;
    }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for team in siblings.iter().filter_map(|s| trusted_team(s)) {
        *counts.entry(team).or_default() += 1;
    }
    counts
        .into_iter()
        .find(|&(_, n)| n * 3 >= siblings.len() * 2)
        .map(|(team, _)| team)
}

fn load_signal(target: &MemberFacts) -> MatchedSignal {
    let mut description =
        "loads a library from the app's Resources directory (outside any framework)".to_string();
    match target.signing.as_ref().map(|s| s.kind) {
        Some(SigningKind::Unsigned) => description.push_str("; the library is unsigned"),
        Some(kind) if kind.is_adhoc() => description.push_str("; the library is ad-hoc signed"),
        _ => {}
    }
    MatchedSignal {
        id: LOAD_FROM_RESOURCES_ID.to_string(),
        weight: LOAD_FROM_RESOURCES_WEIGHT,
        description,
        category: SignalCategory::StaticSuspicion,
    }
}

/// Index of the plain-Resources member that one of `member`'s loads reaches.
/// Each load resolves to the first bundle file dyld's search order finds.
/// `Err` when nothing fired and the `@rpath/` expansions passed
/// [`MAX_RPATH_LOOKUPS`]; non-`@rpath` loads are still checked past the cap.
fn load_target(
    members: &[Member],
    i: usize,
    main: Option<usize>,
    by_rel: &HashMap<String, usize>,
) -> Result<Option<usize>, ()> {
    let member = &members[i];
    let main = main.map(|m| &members[m]);
    let main_rel = main.map(|m| m.rel.as_path());
    // dyld searches the loader's own rpaths, then those of the images that
    // loaded it; the main executable stands in for that chain.
    let mut rpath_owners = vec![member];
    rpath_owners.extend(main.filter(|m| !std::ptr::eq(*m, member)));
    let mut lookups = 0;
    let mut capped = false;
    for load in &member.facts.dylibs {
        let found = match load.strip_prefix("@rpath/") {
            None => resolve_load(load, &member.rel, main_rel)
                .and_then(|rel| by_rel.get(&fold(&rel)).copied()),
            Some(_) if capped => None,
            Some(rest) => {
                let mut found = None;
                'search: for owner in &rpath_owners {
                    for rpath in &owner.facts.rpaths {
                        lookups += 1;
                        if lookups > MAX_RPATH_LOOKUPS {
                            capped = true;
                            break 'search;
                        }
                        let expanded = format!("{rpath}/{rest}");
                        let hit = resolve_load(&expanded, &owner.rel, main_rel)
                            .and_then(|rel| by_rel.get(&fold(&rel)).copied());
                        if hit.is_some() {
                            found = hit;
                            break 'search;
                        }
                    }
                }
                found
            }
        };
        if let Some(t) = found.filter(|&t| in_plain_resources(&members[t].rel)) {
            return Ok(Some(t));
        }
    }
    if capped {
        Err(())
    } else {
        Ok(None)
    }
}

/// Resolve an `@loader_path/` or `@executable_path/` load path to a path
/// under the bundle root, lexically. `None` for any other form, or if it
/// leaves the bundle.
fn resolve_load(load: &str, member_rel: &Path, main_rel: Option<&Path>) -> Option<PathBuf> {
    let (base, rest) = match load.strip_prefix("@loader_path/") {
        Some(rest) => (member_rel.parent()?, rest),
        None => (main_rel?.parent()?, load.strip_prefix("@executable_path/")?),
    };
    let mut resolved = PathBuf::new();
    for component in base.join(rest).components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            Component::ParentDir => {
                if !resolved.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(resolved)
}

fn has_suffix_component(rel: &Path, suffix: &str) -> bool {
    rel.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| s.to_ascii_lowercase().ends_with(suffix))
    })
}

fn in_nested_app(rel: &Path) -> bool {
    has_suffix_component(rel, ".app")
}

/// Under `Contents/Resources/` and not inside a `*.framework/`.
fn in_plain_resources(rel: &Path) -> bool {
    fold(rel).starts_with("contents/resources/") && !has_suffix_component(rel, ".framework")
}

/// `rel` ASCII-lowercased, for comparing paths as a case-insensitive volume does.
fn fold(rel: &Path) -> String {
    rel.to_string_lossy().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "AAAAAAAAAA";
    const OTHER: &str = "BBBBBBBBBB";
    const MAIN: &str = "Contents/MacOS/App";

    fn summary(kind: SigningKind, team: Option<&str>, hardened: bool) -> SigningSummary {
        SigningSummary {
            kind,
            team_id: team.map(str::to_string),
            hardened,
        }
    }

    fn dev(team: &str, hardened: bool) -> SigningSummary {
        summary(SigningKind::Signed, Some(team), hardened)
    }

    fn adhoc(hardened: bool) -> SigningSummary {
        summary(SigningKind::AdHoc, None, hardened)
    }

    fn member(rel: &str, signing: Option<SigningSummary>, dylibs: &[&str]) -> Member {
        Member {
            rel: rel.into(),
            facts: MemberFacts {
                is_macho: true,
                signing,
                dylibs: dylibs.iter().map(|s| s.to_string()).collect(),
                rpaths: Vec::new(),
            },
        }
    }

    /// A main executable plus `n` frameworks signed by `team`.
    fn bundle(main: Option<SigningSummary>, n: usize, hardened: bool) -> Vec<Member> {
        let mut v = vec![member(MAIN, main, &[])];
        for i in 0..n {
            v.push(member(
                &format!("Contents/Frameworks/F{i}.framework/Versions/A/F{i}"),
                Some(dev(TEAM, hardened)),
                &[],
            ));
        }
        v
    }

    fn mismatch_weight(members: &[Member]) -> Option<i32> {
        findings(members, Some(0))
            .into_iter()
            .find_map(|(i, f)| match f {
                Finding::Signal(s) if i == 0 && s.id == MISMATCH_ID => Some(s.weight),
                _ => None,
            })
    }

    #[test]
    fn matching_main_is_clean() {
        assert_eq!(
            mismatch_weight(&bundle(Some(dev(TEAM, true)), 4, true)),
            None
        );
    }

    #[test]
    fn other_team_scores_base() {
        let b = bundle(Some(dev(OTHER, true)), 4, true);
        assert_eq!(mismatch_weight(&b), Some(MISMATCH_WEIGHT));
    }

    #[test]
    fn identityless_main_scores_more() {
        for kind in [
            SigningKind::Unsigned,
            SigningKind::AdHoc,
            SigningKind::LinkerSigned,
            SigningKind::SelfSigned,
        ] {
            let b = bundle(Some(summary(kind, None, true)), 4, true);
            assert_eq!(mismatch_weight(&b), Some(MISMATCH_WEAK_WEIGHT), "{kind:?}");
        }
    }

    #[test]
    fn missing_runtime_adds_two_and_caps_at_eight() {
        assert_eq!(
            mismatch_weight(&bundle(Some(adhoc(false)), 4, true)),
            Some(8)
        );
        let b = bundle(Some(dev(OTHER, false)), 4, true);
        assert_eq!(mismatch_weight(&b), Some(6));
    }

    #[test]
    fn runtime_bonus_needs_a_hardened_majority() {
        let b = bundle(Some(adhoc(false)), 4, false);
        assert_eq!(mismatch_weight(&b), Some(MISMATCH_WEAK_WEIGHT));
    }

    #[test]
    fn too_few_siblings_is_clean() {
        assert_eq!(mismatch_weight(&bundle(Some(adhoc(false)), 2, true)), None);
    }

    #[test]
    fn no_team_majority_is_clean() {
        let mut b = bundle(Some(adhoc(false)), 0, true);
        for (i, team) in [TEAM, OTHER, "CCCCCCCCCC"].iter().enumerate() {
            b.push(member(
                &format!("Contents/Frameworks/L{i}.dylib"),
                Some(dev(team, true)),
                &[],
            ));
        }
        assert_eq!(mismatch_weight(&b), None);
    }

    #[test]
    fn two_thirds_is_a_majority() {
        let mut b = bundle(Some(dev(OTHER, true)), 4, true);
        for (i, team) in ["CCCCCCCCCC", "DDDDDDDDDD"].iter().enumerate() {
            b.push(member(
                &format!("Contents/Frameworks/x{i}.dylib"),
                Some(dev(team, true)),
                &[],
            ));
        }
        assert_eq!(mismatch_weight(&b), Some(MISMATCH_WEIGHT));
    }

    #[test]
    fn members_without_a_summary_do_not_count() {
        let mut b = bundle(Some(adhoc(false)), 3, true);
        for i in 0..5 {
            b.push(member(
                &format!("Contents/Frameworks/n{i}.dylib"),
                None,
                &[],
            ));
        }
        assert_eq!(mismatch_weight(&b), Some(8));
    }

    #[test]
    fn nested_app_members_are_not_siblings() {
        let mut b = bundle(Some(adhoc(false)), 0, true);
        for i in 0..4 {
            b.push(member(
                &format!("Contents/Helpers/H.app/Contents/MacOS/h{i}"),
                Some(dev(TEAM, true)),
                &[],
            ));
        }
        assert_eq!(mismatch_weight(&b), None);
    }

    #[test]
    fn script_main_is_clean() {
        let mut b = bundle(None, 4, true);
        b[0].facts.is_macho = false;
        assert!(findings(&b, Some(0)).is_empty());
    }

    #[test]
    fn unchecked_main_is_not_applicable() {
        let f = findings(&bundle(None, 4, true), Some(0));
        assert!(matches!(
            f.as_slice(),
            [(0, Finding::NotApplicable(MISMATCH_ID))]
        ));
    }

    /// With `unanchored-signing-identity` (+5) a self-signed main executable
    /// carrying the strongest mismatch must stay under Notify (§5.1).
    #[test]
    fn self_signed_main_stays_below_notify() {
        use crate::model::Recommendation;
        let main = summary(SigningKind::SelfSigned, None, false);
        let Some((_, Finding::Signal(mismatch))) = findings(&bundle(Some(main), 4, true), Some(0))
            .into_iter()
            .next()
        else {
            panic!("no finding");
        };
        assert_eq!(mismatch.weight, 8);
        let unanchored = MatchedSignal {
            id: "unanchored-signing-identity".into(),
            weight: 5,
            description: String::new(),
            category: SignalCategory::ProvenanceConcern,
        };
        let (score, rec) = crate::scan::score_signals(&[unanchored, mismatch]);
        assert_eq!(score, 13);
        assert_eq!(rec, Recommendation::NoAction);
    }

    /// A self-signed main executable that also loads from Resources gets no
    /// more than the cap in total, so it still stays under Notify.
    #[test]
    fn combined_signals_are_capped() {
        use crate::model::Recommendation;
        let main = summary(SigningKind::SelfSigned, None, true);
        let mut members = bundle(Some(main), 4, true);
        members[0].facts.dylibs = vec!["@executable_path/../Resources/libX.dylib".into()];
        members.push(member(
            "Contents/Resources/libX.dylib",
            Some(adhoc(false)),
            &[],
        ));
        let mut signals: Vec<MatchedSignal> = findings(&members, Some(0))
            .into_iter()
            .filter_map(|(i, f)| match f {
                Finding::Signal(s) if i == 0 => Some(s),
                _ => None,
            })
            .collect();
        assert_eq!(signals.len(), 2);
        assert_eq!(
            signals.iter().map(|s| s.weight).sum::<i32>(),
            MAX_PER_MEMBER
        );
        signals.push(MatchedSignal {
            id: "unanchored-signing-identity".into(),
            weight: 5,
            description: String::new(),
            category: SignalCategory::ProvenanceConcern,
        });
        assert_eq!(
            crate::scan::score_signals(&signals).1,
            Recommendation::NoAction
        );
    }

    /// Once the cap is spent, a further signal is dropped, not kept at 0.
    #[test]
    fn spent_cap_drops_signal() {
        let main = summary(SigningKind::SelfSigned, None, false);
        let mut members = bundle(Some(main), 4, true);
        members[0].facts.dylibs = vec!["@executable_path/../Resources/libX.dylib".into()];
        members.push(member("Contents/Resources/libX.dylib", None, &[]));
        let f = findings(&members, Some(0));
        assert!(
            matches!(f.as_slice(), [(0, Finding::Signal(s))] if s.id == MISMATCH_ID && s.weight == 8)
        );
    }

    /// A Team ID claimed by a signature without a real identity is not trusted.
    #[test]
    fn forged_team_still_mismatches() {
        let main = summary(SigningKind::SelfSigned, Some(TEAM), true);
        assert_eq!(mismatch_weight(&bundle(Some(main), 4, true)), Some(6));
    }

    #[test]
    fn signed_main_without_team_unchecked() {
        let main = summary(SigningKind::Signed, None, true);
        let f = findings(&bundle(Some(main), 4, true), Some(0));
        assert!(matches!(
            f.as_slice(),
            [(0, Finding::NotApplicable(MISMATCH_ID))]
        ));
    }

    /// dyld resolves on a case-insensitive volume, so the check does too.
    #[test]
    fn resources_match_ignores_case() {
        let mut members = bundle(Some(dev(TEAM, true)), 4, true);
        members[0].facts.dylibs = vec!["@executable_path/../resources/LIBX.dylib".into()];
        members.push(member("Contents/Resources/libX.dylib", None, &[]));
        assert_eq!(load_findings(&members).len(), 1);
    }

    fn load_findings(members: &[Member]) -> Vec<(usize, String)> {
        findings(members, Some(0))
            .into_iter()
            .filter_map(|(i, f)| match f {
                Finding::Signal(s) if s.id == LOAD_FROM_RESOURCES_ID => Some((i, s.description)),
                _ => None,
            })
            .collect()
    }

    /// Main (index 0), a loading member (1), then `extra` ad-hoc members.
    fn loading(loader: &str, load: &str, extra: &[&str]) -> Vec<Member> {
        let mut v = vec![member(MAIN, None, &[]), member(loader, None, &[load])];
        v.extend(extra.iter().map(|p| {
            member(
                p,
                Some(summary(SigningKind::LinkerSigned, None, false)),
                &[],
            )
        }));
        v
    }

    /// A framework binary loading a dylib out of the app's Resources.
    #[test]
    fn framework_loading_a_resources_dylib_fires() {
        let b = loading(
            "Contents/Frameworks/X.framework/Versions/A/X",
            "@loader_path/../../../../Resources/libCon.dylib",
            &["Contents/Resources/libCon.dylib"],
        );
        let f = load_findings(&b);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, 1);
        assert!(f[0].1.contains("ad-hoc"));
    }

    /// A framework's own Resources directory is not the app's.
    #[test]
    fn load_inside_a_framework_is_clean() {
        let b = loading(
            "Contents/Resources/Breakpad.framework/Versions/A/Breakpad",
            "@loader_path/Resources/libx.dylib",
            &["Contents/Resources/Breakpad.framework/Versions/A/Resources/libx.dylib"],
        );
        assert!(load_findings(&b).is_empty());
    }

    /// A load path to a file the bundle does not hold proves nothing.
    #[test]
    fn missing_target_is_clean() {
        let b = loading(
            "Contents/Frameworks/V.dylib",
            "@executable_path/../Resources/breakpadUtilities.dylib",
            &[],
        );
        assert!(load_findings(&b).is_empty());
    }

    #[test]
    fn executable_path_resolves_against_the_main_executable() {
        let b = loading(
            "Contents/Frameworks/deep/V.dylib",
            "@executable_path/../Resources/lib.dylib",
            &["Contents/Resources/lib.dylib"],
        );
        assert_eq!(load_findings(&b).len(), 1);
    }

    #[test]
    fn paths_leaving_the_bundle_or_nested_apps_are_ignored() {
        let b = loading(
            "Contents/MacOS/x",
            "@loader_path/../../../Contents/Resources/lib.dylib",
            &["Contents/Resources/lib.dylib"],
        );
        assert!(load_findings(&b).is_empty());
        let b = loading(
            "Contents/Helpers/H.app/Contents/MacOS/h",
            "@loader_path/../Resources/lib.dylib",
            &["Contents/Helpers/H.app/Contents/Resources/lib.dylib"],
        );
        assert!(load_findings(&b).is_empty());
    }

    #[test]
    fn other_load_forms_are_ignored() {
        for load in ["/usr/lib/libz.dylib", "@rpath/lib.dylib", "lib.dylib"] {
            let b = loading("Contents/MacOS/x", load, &["Contents/Resources/lib.dylib"]);
            assert!(load_findings(&b).is_empty(), "{load}");
        }
    }

    /// `loading` with the loader (index 1) given `rpaths`.
    fn with_rpaths(loader: &str, load: &str, rpaths: &[&str], extra: &[&str]) -> Vec<Member> {
        let mut b = loading(loader, load, extra);
        b[1].facts.rpaths = rpaths.iter().map(|s| s.to_string()).collect();
        b
    }

    /// An absolute rpath is skipped; a trailing slash is harmless.
    #[test]
    fn rpath_reaches_resources() {
        let b = with_rpaths(
            "Contents/Frameworks/V.dylib",
            "@rpath/lib.dylib",
            &["/usr/lib/swift", "@loader_path/../Resources/"],
            &["Contents/Resources/lib.dylib"],
        );
        let f = load_findings(&b);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, 1);
    }

    /// A loader with no rpaths uses main's; `@loader_path` there is main's directory.
    #[test]
    fn main_rpaths_fallback() {
        let mut b = loading(
            "Contents/Frameworks/V.dylib",
            "@rpath/lib.dylib",
            &["Contents/Resources/lib.dylib"],
        );
        b[0].facts.rpaths = vec!["@loader_path/../Resources".to_string()];
        let f = load_findings(&b);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, 1);
    }

    /// dyld takes the first rpath that has the file, so the Frameworks copy wins.
    #[test]
    fn first_rpath_hit_wins() {
        let b = with_rpaths(
            "Contents/Frameworks/V.dylib",
            "@rpath/lib.dylib",
            &["@loader_path/../Frameworks", "@loader_path/../Resources"],
            &[
                "Contents/Frameworks/lib.dylib",
                "Contents/Resources/lib.dylib",
            ],
        );
        assert!(load_findings(&b).is_empty());
    }

    /// `@executable_path` in an rpath entry resolves against main.
    #[test]
    fn executable_path_rpath() {
        let b = with_rpaths(
            "Contents/Frameworks/V.dylib",
            "@rpath/lib.dylib",
            &["@executable_path/../Resources"],
            &["Contents/Resources/lib.dylib"],
        );
        assert_eq!(load_findings(&b).len(), 1);
    }

    /// An rpath that leaves the bundle resolves to nothing.
    #[test]
    fn escaping_rpath_ignored() {
        let b = with_rpaths(
            "Contents/Frameworks/V.dylib",
            "@rpath/lib.dylib",
            &["@loader_path/../../../../Resources"],
            &["Contents/Resources/lib.dylib"],
        );
        assert!(load_findings(&b).is_empty());
    }

    /// Past [`MAX_RPATH_LOOKUPS`] the check is a gap, not clean and not a signal.
    #[test]
    fn rpath_cap_is_gap() {
        let mut b = loading("Contents/Frameworks/V.dylib", "@rpath/lib.dylib", &[]);
        b[1].facts.rpaths = vec!["@loader_path/x".to_string(); MAX_RPATH_LOOKUPS + 1];
        let all = findings(&b, Some(0));
        assert!(all.iter().any(|(i, f)| *i == 1
            && matches!(f, Finding::NotApplicable(id) if *id == LOAD_FROM_RESOURCES_ID)));
        assert!(load_findings(&b).is_empty());
    }

    /// Hitting the cap still checks the member's direct loads.
    #[test]
    fn cap_keeps_direct_loads() {
        let mut b = loading(
            "Contents/MacOS/x",
            "@rpath/lib.dylib",
            &["Contents/Resources/lib.dylib"],
        );
        b[1].facts.rpaths = vec!["@loader_path/x".to_string(); MAX_RPATH_LOOKUPS + 1];
        b[1].facts
            .dylibs
            .push("@loader_path/../Resources/lib.dylib".into());
        assert_eq!(load_findings(&b).len(), 1);
    }
}
