//! `credential-phish` (§5.2, #305): a password-phish trait plus names from at
//! least two credential-store groups in one file. Matched on the
//! `suspicious-strings` scan, so the file is read once.

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

/// `[first byte][second byte]` pairs that start a needle, `dscl` or `echo`:
/// most bytes of a file fail this and skip the needle loop.
static PAIRS: [[bool; 256]; 256] = {
    let mut t = [[false; 256]; 256];
    let mut i = 0;
    while i < NEEDLES.len() {
        t[NEEDLES[i].text[0] as usize][NEEDLES[i].text[1] as usize] = true;
        i += 1;
    }
    t[b'd' as usize][b's' as usize] = true;
    t[b'e' as usize][b'c' as usize] = true;
    t
};

/// Longest run of blanks (space/tab) allowed inside a trait match.
const MAX_BLANKS: usize = 16;
/// `echo` text between the blanks and the pipe, at most.
const MAX_ECHO_BODY: usize = 40;
/// Option tokens of `sudo` inspected for `-S`, and the longest one.
const MAX_SUDO_TOKENS: usize = 4;
const MAX_TOKEN: usize = 32;

/// Longest trait match in bytes (the `echo` form, every option token with an
/// argument); it must fit in a stream window's overlap.
const MAX_MATCH: usize = 4
    + MAX_BLANKS
    + MAX_ECHO_BODY
    + 1
    + MAX_BLANKS
    + 4
    + MAX_BLANKS
    + MAX_SUDO_TOKENS * 2 * (MAX_TOKEN + MAX_BLANKS);
const _: () = assert!(MAX_MATCH < super::strings::STREAM_OVERLAP);

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

/// Index after, and length of, the run of blanks starting at `i`; `None` for
/// a run over `MAX_BLANKS`.
fn blanks(b: &[u8], i: usize) -> Option<(usize, usize)> {
    let n = b
        .get(i..)?
        .iter()
        .take(MAX_BLANKS + 1)
        .take_while(|&&c| c == b' ' || c == b'\t')
        .count();
    (n <= MAX_BLANKS).then_some((i + n, n))
}

/// `dscl (.|/Local/Default) [-]authonly` at the start of `rest`. Not
/// `/Search`, which admin scripts use.
fn dscl_authonly(rest: &[u8]) -> bool {
    let Some(after) = rest.strip_prefix(b"dscl") else {
        return false;
    };
    let Some((i, n)) = blanks(after, 0) else {
        return false;
    };
    let node = &after[i..];
    let node_len = if node.starts_with(b"/Local/Default") {
        14
    } else if node.starts_with(b".") {
        1
    } else {
        return false;
    };
    let tail = &node[node_len..];
    match blanks(tail, 0) {
        Some((j, m)) if n > 0 && m > 0 => {
            let tail = &tail[j..];
            tail.strip_prefix(b"-")
                .unwrap_or(tail)
                .starts_with(b"authonly")
        }
        _ => false,
    }
}

/// `sudo` flags that take the next token as an argument.
const SUDO_ARG_FLAGS: &[&[u8]] = &[b"-u", b"-g", b"-h", b"-p", b"-C", b"-r", b"-t", b"-U"];

/// The end of the non-blank token at `i`; `None` if empty or over `MAX_TOKEN`.
fn token_end(b: &[u8], i: usize) -> Option<usize> {
    let n = b
        .get(i..)?
        .iter()
        .take(MAX_TOKEN + 1)
        .take_while(|&&c| !c.is_ascii_whitespace())
        .count();
    (1..=MAX_TOKEN).contains(&n).then_some(i + n)
}

/// Whether `-S` (alone or inside a short-option token like `-kS`) is among
/// the first `MAX_SUDO_TOKENS` option tokens of `s`, the text after `sudo`.
/// Stops at the first token that is not an option.
fn sudo_stdin_flag(s: &[u8]) -> bool {
    let Some((mut i, n)) = blanks(s, 0) else {
        return false;
    };
    if n == 0 {
        return false;
    }
    for _ in 0..MAX_SUDO_TOKENS {
        let Some(end) = token_end(s, i) else {
            return false;
        };
        let tok = &s[i..end];
        if tok.len() < 2 || tok[0] != b'-' || tok[1] == b'-' {
            return false;
        }
        if tok[1..].iter().all(u8::is_ascii_alphabetic) && tok.contains(&b'S') {
            return true;
        }
        let Some((next, _)) = blanks(s, end) else {
            return false;
        };
        i = next;
        if SUDO_ARG_FLAGS.contains(&tok) {
            let Some(arg_end) = token_end(s, i) else {
                return false;
            };
            let Some((next, _)) = blanks(s, arg_end) else {
                return false;
            };
            i = next;
        }
    }
    false
}

/// `echo <≤40 non-pipe bytes> | sudo [options] -S` at the start of `rest`.
fn echo_sudo(rest: &[u8]) -> bool {
    let Some(after) = rest.strip_prefix(b"echo") else {
        return false;
    };
    let Some((start, n)) = blanks(after, 0) else {
        return false;
    };
    if n == 0 {
        return false;
    }
    let body = &after[start..];
    let Some(pipe) = body
        .iter()
        .take(MAX_ECHO_BODY + 1)
        .position(|&b| b == b'|' || b == b'\n')
        .filter(|&p| body[p] == b'|')
    else {
        return false;
    };
    let tail = &body[pipe + 1..];
    let Some((j, _)) = blanks(tail, 0) else {
        return false;
    };
    tail[j..].strip_prefix(b"sudo").is_some_and(sudo_stdin_flag)
}

/// Records every trait and group name found in `bytes`. A match cut by a
/// window edge is found whole in the next window's overlap.
pub(super) fn scan(bytes: &[u8], hits: &mut PhishHits) {
    for i in 0..bytes.len().saturating_sub(1) {
        let (b, b1) = (bytes[i], bytes[i + 1]);
        if !PAIRS[b as usize][b1 as usize] {
            continue;
        }
        let rest = &bytes[i..];
        let word_start = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if word_start && b == b'd' && dscl_authonly(rest) {
            hits.traits[DSCL_AUTHONLY] = true;
        } else if word_start && b == b'e' && echo_sudo(rest) {
            hits.traits[ECHO_SUDO] = true;
        }
        for n in NEEDLES {
            if n.text[0] != b || n.text[1] != b1 || !rest.starts_with(n.text) {
                continue;
            }
            if n.left_bounded && !word_start {
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

    /// As `suspicious-strings`: the shared scan streams the whole file.
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
        assert!(hit("echo \"$PW\" | sudo -k -S true"));
        assert!(hit("echo \"$PW\" | sudo -p '' -S true"));
        assert!(hit("echo \"$PW\" | sudo -E -S true"));
        assert!(hit("echo \"$PW\" | sudo -kS true"));
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
        assert!(!hit("echo pw | sudo -k true"));
        assert!(!hit("echo pw | sudo ls -S"));
        assert!(!hit("echo pw | sudo --stdin x"));
        assert!(!hit(&format!("echo pw | sudo{}-S x", " ".repeat(40))));
    }

    /// `dscl` and `echo` must start a word.
    #[test]
    fn trait_word_boundary() {
        assert!(!hit("mecho pw | sudo -S x"));
        assert!(!hit("xdscl . authonly u p"));
        assert!(hit("(echo pw | sudo -S x)"));
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

    /// Traits cut by a chunk boundary, inside the overlap, are found.
    #[test]
    fn trait_straddles_chunk() {
        for text in [
            &b"\necho \"$P\"  |  sudo -k -S true\n"[..],
            &b"\ndscl . authonly $U $P\n"[..],
        ] {
            for back in [3u64, 12] {
                let path = sparse_temp_file("phish-trait", MAX_CONTENT_BYTES as u64 + 4096);
                write_at(&path, 9 * STREAM_CHUNK as u64 - back, text);
                write_at(
                    &path,
                    MAX_CONTENT_BYTES as u64 + 100,
                    b"\nlogin.keychain\nlogins.json\n",
                );
                let ctx = ScanContext::load(&path);
                ctx.apple_own_cache.set(Some(1)).unwrap();
                assert!(CredentialPhishRule.evaluate(&ctx).unwrap().is_some());
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}
