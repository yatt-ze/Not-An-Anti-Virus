//! Password phish plus credential targets in one file (§5.2, #305): a prompt
//! or check for the user's password together with names from at least two
//! credential-store groups (keychain, browser, wallet, messaging, notes).
//! Runs on the `suspicious-strings` scan, so the file is read once.

use super::codesign::{apple_own_check, AnchorCheck};
use super::strings::{can_stream, scan_hits};
use super::zip_member::scored_through_members;
use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::model::{MatchedSignal, SignalCategory};

/// Distinct target groups a file must name, besides the phish trait.
const MIN_GROUPS: usize = 2;

const TRAIT_NOTES: [&str; 3] = [
    "hidden-answer password dialog",
    "dscl authonly password check",
    "password piped to sudo -S",
];
const HIDDEN_ANSWER: usize = 0;
const DSCL_AUTHONLY: usize = 1;
const ECHO_SUDO: usize = 2;

const GROUP_NAMES: [&str; 5] = ["keychain", "browser", "wallet", "messaging", "notes"];

struct Needle {
    text: &'static [u8],
    /// Index into `TRAIT_NOTES` when `is_trait`, else into `GROUP_NAMES`.
    index: usize,
    is_trait: bool,
    /// Byte before the needle must not be alphanumeric (`tdata/` vs `metadata/`).
    left_bounded: bool,
}

const fn group(text: &'static str, index: usize) -> Needle {
    Needle {
        text: text.as_bytes(),
        index,
        is_trait: false,
        left_bounded: false,
    }
}

const NEEDLES: &[Needle] = &[
    Needle {
        text: b"with hidden answer",
        index: HIDDEN_ANSWER,
        is_trait: true,
        left_bounded: false,
    },
    group("login.keychain", 0),
    group("dump-keychain", 0),
    group("find-generic-password", 0),
    group("Chrome Safe Storage", 1),
    group("Chromium Safe Storage", 1),
    group("Login Data", 1),
    group("logins.json", 1),
    group("key4.db", 1),
    group("Cookies.binarycookies", 1),
    group("cookies.sqlite", 1),
    group("nkbihfbeogaejgnflmanmhepkdgfifhl", 2),
    group("bfnaelmomeimhlpmgjnjophhpkkoljpa", 2),
    group("hnfanknocfeofbddgcijnmhnfnkdnaad", 2),
    group("Exodus/exodus.wallet", 2),
    group("Electrum/wallets", 2),
    group("atomic/Local Storage", 2),
    group("Ledger Live", 2),
    group("Telegram Desktop/tdata", 3),
    Needle {
        text: b"tdata/",
        index: 3,
        is_trait: false,
        left_bounded: true,
    },
    group("NoteStore.sqlite", 4),
];

/// Bytes that start a needle, `dscl` or `echo`.
const STARTS: [bool; 256] = {
    let mut t = [false; 256];
    let mut i = 0;
    while i < NEEDLES.len() {
        t[NEEDLES[i].text[0] as usize] = true;
        i += 1;
    }
    t[b'd' as usize] = true;
    t[b'e' as usize] = true;
    t
};

/// Which phish traits and target groups a file has shown so far.
#[derive(Clone, Default)]
pub(super) struct PhishHits {
    traits: [bool; TRAIT_NOTES.len()],
    groups: [bool; GROUP_NAMES.len()],
}

impl PhishHits {
    fn matched(&self) -> bool {
        self.traits.iter().any(|&t| t) && self.groups.iter().filter(|&&g| g).count() >= MIN_GROUPS
    }
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while b.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

/// `dscl (.|/Local/Default) [-]authonly` at the start of `rest`. Not
/// `/Search`, which admin scripts use.
fn dscl_authonly(rest: &[u8]) -> bool {
    let Some(after) = rest.strip_prefix(b"dscl") else {
        return false;
    };
    let i = skip_ws(after, 0);
    if i == 0 {
        return false;
    }
    let node = &after[i..];
    let node_len = if node.starts_with(b"/Local/Default") {
        14
    } else if node.starts_with(b".") {
        1
    } else {
        return false;
    };
    let tail = &node[node_len..];
    let j = skip_ws(tail, 0);
    if j == 0 {
        return false;
    }
    let tail = &tail[j..];
    tail.strip_prefix(b"-")
        .unwrap_or(tail)
        .starts_with(b"authonly")
}

/// `echo <≤40 non-pipe bytes> | sudo -S` at the start of `rest`.
fn echo_sudo(rest: &[u8]) -> bool {
    let Some(after) = rest.strip_prefix(b"echo") else {
        return false;
    };
    let start = skip_ws(after, 0);
    if start == 0 {
        return false;
    }
    let body = &after[start..];
    let Some(pipe) = body
        .iter()
        .take(41)
        .position(|&b| b == b'|' || b == b'\n')
        .filter(|&p| body[p] == b'|')
    else {
        return false;
    };
    let tail = &body[pipe + 1..];
    let Some(tail) = tail[skip_ws(tail, 0)..].strip_prefix(b"sudo") else {
        return false;
    };
    let j = skip_ws(tail, 0);
    j > 0 && tail[j..].starts_with(b"-S")
}

/// Records every trait and group name found in `bytes`. A match cut by a
/// window edge is found whole in the next window's overlap.
pub(super) fn scan(bytes: &[u8], hits: &mut PhishHits) {
    if hits.matched() && hits.traits.iter().all(|&t| t) {
        return;
    }
    for i in 0..bytes.len() {
        let b = bytes[i];
        if !STARTS[b as usize] {
            continue;
        }
        let rest = &bytes[i..];
        if b == b'd' && dscl_authonly(rest) {
            hits.traits[DSCL_AUTHONLY] = true;
        } else if b == b'e' && echo_sudo(rest) {
            hits.traits[ECHO_SUDO] = true;
        }
        for n in NEEDLES {
            if n.text[0] != b || !rest.starts_with(n.text) {
                continue;
            }
            if n.left_bounded && i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
                continue;
            }
            if n.is_trait {
                hits.traits[n.index] = true;
            } else {
                hits.groups[n.index] = true;
            }
        }
    }
}

pub struct CredentialPhishRule;

impl Rule for CredentialPhishRule {
    fn id(&self) -> &'static str {
        "credential-phish"
    }

    /// Shares `suspicious-strings`' category, so alone it cannot reach high
    /// severity (§5.1).
    fn category(&self) -> SignalCategory {
        SignalCategory::StaticSuspicion
    }

    /// Fires on a phish trait plus at least two target groups in one file,
    /// unless Apple itself signed it. Not capped for Mach-O (§5.2).
    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        if scored_through_members(ctx) {
            return Ok(None);
        }
        let (hits, ok) = scan_hits(ctx).ok_or(RuleOutcome::NotApplicable)?;
        if !ok {
            ctx.mark_incomplete(self.id());
        }
        let hits = &hits.phish;
        if !hits.matched() {
            return if *ok {
                Ok(None)
            } else {
                Err(RuleOutcome::NotApplicable)
            };
        }
        // Only a match pays for the codesign spawn. An unchecked exclusion
        // (allowance, non-macOS, embedded) still reports the match.
        match apple_own_check(ctx) {
            AnchorCheck::Verified => return Ok(None),
            AnchorCheck::Skipped => ctx.mark_incomplete(self.id()),
            AnchorCheck::NotVerified => {}
        }
        let list = |names: &[&str], flags: &[bool]| {
            names
                .iter()
                .zip(flags)
                .filter(|(_, &f)| f)
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        };
        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight: crate::scan::MEDIUM_SCORE_THRESHOLD,
            description: format!(
                "asks for the user's password ({}) and names credential stores ({})",
                list(&TRAIT_NOTES, &hits.traits),
                list(&GROUP_NAMES, &hits.groups)
            ),
            category: self.category(),
        }))
    }

    /// Same coverage as `suspicious-strings`: the shared scan streams the
    /// whole file when it can.
    fn covers_truncation(&self, ctx: &ScanContext) -> bool {
        can_stream(ctx) && !ctx.marked_incomplete(self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{MAX_CONTENT_BYTES, STREAM_CHUNK};
    use crate::test_support::{sparse_temp_file, write_at, write_temp_file};

    fn eval(name: &str, body: &[u8]) -> Option<MatchedSignal> {
        let ctx = ScanContext::from_embedded_bytes(name, body.to_vec(), false);
        CredentialPhishRule.evaluate(&ctx).expect("applicable")
    }

    const TARGETS: &str = "~/Library/Keychains/login.keychain-db Chrome Safe Storage";

    fn hit(trait_text: &str) -> bool {
        eval("x.sh", format!("{trait_text}\n{TARGETS}\n").as_bytes()).is_some()
    }

    /// Each phish trait fires with two groups.
    #[test]
    fn each_trait_fires() {
        assert!(hit("display dialog \"Password\" with hidden answer"));
        assert!(hit("dscl . authonly $U $P"));
        assert!(hit("dscl . -authonly $U $P"));
        assert!(hit("dscl /Local/Default -authonly $U $P"));
        assert!(hit("echo \"$PW\" | sudo -S true"));
        assert!(hit("echo $PW|sudo  -S -p '' ls"));
    }

    /// `/Search` and other near misses are not phish traits.
    #[test]
    fn near_misses_do_not_fire() {
        assert!(!hit("dscl /Search -authonly $U $P"));
        assert!(!hit("dscl . read /Users/x"));
        assert!(!hit("echo hi | sudo ls"));
        assert!(!hit("echo hi\nsudo -S x"));
        assert!(!hit(&format!("echo {} | sudo -S x", "a".repeat(60))));
        assert!(!hit("hidden answer without the lead"));
    }

    /// One target group, or targets without a trait, is not enough.
    #[test]
    fn needs_two_groups() {
        let phish = "display dialog \"x\" with hidden answer\n";
        let one = format!("{phish}login.keychain\ndump-keychain\n");
        let two = format!("{phish}login.keychain\nlogins.json\n");
        assert!(eval("x.sh", one.as_bytes()).is_none());
        assert!(eval("x.sh", two.as_bytes()).is_some());
        assert!(eval("x.sh", TARGETS.as_bytes()).is_none());
    }

    /// Every group counts, and a match weighs exactly the Notify threshold.
    #[test]
    fn every_group_counts() {
        for (a, b) in [
            ("find-generic-password", "key4.db"),
            ("nkbihfbeogaejgnflmanmhepkdgfifhl", "Telegram Desktop/tdata"),
            ("Exodus/exodus.wallet", "NoteStore.sqlite"),
            ("Ledger Live", "cookies.sqlite"),
        ] {
            let body = format!("with hidden answer\n{a}\n{b}\n");
            let sig = eval("x.sh", body.as_bytes()).expect(a);
            assert_eq!(sig.weight, crate::scan::MEDIUM_SCORE_THRESHOLD);
            assert_eq!(sig.id, "credential-phish");
        }
    }

    /// `tdata/` inside a longer word is not the Telegram store.
    #[test]
    fn tdata_needs_boundary() {
        let phish = "with hidden answer\nlogin.keychain\n";
        assert!(eval("x.sh", format!("{phish}metadata/x\n").as_bytes()).is_none());
        assert!(eval("x.sh", format!("{phish}/tdata/x\n").as_bytes()).is_some());
    }

    /// Plain strings in a binary count, unlike `suspicious-strings` names.
    #[test]
    fn binary_strings_count() {
        let mut body = vec![0x9Du8; 600];
        body.extend_from_slice(b"\0with hidden answer\0login.keychain\0logins.json\0");
        assert!(eval("x.bin", &body).is_some());
    }

    /// Signed by Apple itself: excluded; any other result still reports.
    #[test]
    fn apple_signed_excluded() {
        let body = format!("with hidden answer\n{TARGETS}\n");
        for (exit, fires) in [(Some(0), false), (Some(3), true), (None, true)] {
            let path = write_temp_file("phish-apple", body.as_bytes());
            let ctx = ScanContext::load(&path);
            let _ = std::fs::remove_file(&path);
            ctx.apple_own_cache.set(exit).unwrap();
            let got = CredentialPhishRule.evaluate(&ctx).unwrap();
            assert_eq!(got.is_some(), fires, "{exit:?}");
        }
    }

    /// An allowance too small for codesign still reports, marked incomplete.
    #[test]
    fn skipped_check_reports() {
        let body = format!("with hidden answer\n{TARGETS}\n");
        let path = write_temp_file("phish-skip", body.as_bytes());
        let ctx = ScanContext::load_if(&path, body.len() as u64 + 10, |_| true).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(CredentialPhishRule.evaluate(&ctx).unwrap().is_some());
        assert!(ctx.marked_incomplete("credential-phish"));
    }

    /// An unreadable file is a gap, not clean.
    #[test]
    fn unreadable_is_gap() {
        let ctx = ScanContext::load(std::path::Path::new("/nonexistent/nav-phish"));
        assert!(matches!(
            CredentialPhishRule.evaluate(&ctx),
            Err(RuleOutcome::NotApplicable)
        ));
    }

    /// A trait straddling a stream chunk boundary and targets past the
    /// prefix are found.
    #[test]
    fn past_prefix_straddle() {
        let path = sparse_temp_file("phish-straddle", MAX_CONTENT_BYTES as u64 + 4096);
        write_at(
            &path,
            9 * STREAM_CHUNK as u64 - 5,
            b"\nwith hidden answer\n",
        );
        write_at(&path, MAX_CONTENT_BYTES as u64 + 100, b"\nlogin.keychain\n");
        write_at(&path, MAX_CONTENT_BYTES as u64 + 200, b"\nlogins.json\n");
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        assert!(CredentialPhishRule.covers_truncation(&ctx));
        ctx.apple_own_cache.set(Some(1)).unwrap();
        assert!(CredentialPhishRule.evaluate(&ctx).unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }
}
