//! Shared bounded XML primitives — tag boundaries, names, attributes, entity
//! decoding — used by both `plist.rs` and `xar.rs` so there is one XML
//! implementation on the attacker-controlled path, not two.
//!
//! §3/§11.9 discipline: no panics, every offset bounds-checked, and **bounded
//! lookahead that always advances** (a scanner that re-reads what it already
//! looked at goes quadratic on a run of bare `&`s — §3).

/// Longest entity body (`lt`, `#x1F600`, …) to look ahead for. Bounding it
/// keeps text with bare `&`s linear.
pub const MAX_ENTITY_BODY: usize = 32;

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Decode XML text: the five predefined entities plus numeric character
/// references. Iterates *characters* (text may be UTF-8), not bytes.
pub fn decode_entities(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    if !s.contains('&') {
        return s.into_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }

        // Bounded lookahead to the body's ';'. Every path below either consumes
        // the body it scanned or emits one '&' and consumes nothing extra.
        let mut body = String::new();
        let mut terminated = false;
        for ch in chars.clone().take(MAX_ENTITY_BODY + 1) {
            if ch == ';' {
                terminated = true;
                break;
            }
            body.push(ch);
        }
        if !terminated || body.is_empty() {
            // A bare '&', not an entity. Emit it without consuming what follows.
            out.push('&');
            continue;
        }

        let decoded = match body.as_str() {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ if body.starts_with("#x") || body.starts_with("#X") => body
                .get(2..)
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .and_then(char::from_u32),
            _ if body.starts_with('#') => body
                .get(1..)
                .and_then(|d| d.parse::<u32>().ok())
                .and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(ch) => out.push(ch),
            // Well-formed but unrecognized — keep it verbatim.
            None => {
                out.push('&');
                out.push_str(&body);
                out.push(';');
            }
        }

        // Advance past the body and its ';' — at most MAX_ENTITY_BODY + 1.
        for _ in 0..=body.len() {
            if chars.next().is_none() {
                break;
            }
        }
    }
    out
}

// --- cursor primitives ---------------------------------------------------
//
// Each takes a buffer + position and returns the new position, leaving the
// caller to keep whatever surrounding state it wants.

pub fn skip_ws(b: &[u8], mut pos: usize) -> usize {
    while b.get(pos).is_some_and(|c| c.is_ascii_whitespace()) {
        pos = pos.saturating_add(1);
    }
    pos
}

/// Skip whitespace, comments, processing instructions and the DOCTYPE. Loops,
/// not recurses (a long run of comments would overflow the stack). An
/// unterminated construct consumes the rest of the buffer.
pub fn skip_junk(b: &[u8], mut pos: usize) -> usize {
    loop {
        pos = skip_ws(b, pos);
        let rest = match b.get(pos..) {
            Some(r) => r,
            None => return b.len(),
        };
        let closer: &[u8] = if rest.starts_with(b"<!--") {
            b"-->"
        } else if rest.starts_with(b"<?") {
            b"?>"
        } else if rest.starts_with(b"<!") {
            // DOCTYPE (a plist's has no internal subset); stop at the next '>'.
            b">"
        } else {
            return pos;
        };
        match find(rest, closer) {
            Some(i) => pos = pos.saturating_add(i).saturating_add(closer.len()),
            None => return b.len(),
        }
    }
}

/// Name of the tag at `pos` (`<name ...>` or `<name/>`), consuming nothing.
/// `None` if the cursor isn't on a start tag.
pub fn peek_tag_name(b: &[u8], pos: usize) -> Option<&str> {
    let r = b.get(pos..)?;
    if r.first() != Some(&b'<') || matches!(r.get(1), Some(b'/') | Some(b'!') | Some(b'?')) {
        return None;
    }
    let name: &[u8] = r
        .get(1..)?
        .split(|c: &u8| c.is_ascii_whitespace() || *c == b'>' || *c == b'/')
        .next()?;
    if name.is_empty() {
        return None;
    }
    std::str::from_utf8(name).ok()
}

/// Consume `<name ...>` (not self-closing), returning the new position.
pub fn consume_open_tag(b: &[u8], pos: usize, name: &str) -> Option<usize> {
    let pos = skip_junk(b, pos);
    if peek_tag_name(b, pos)? != name {
        return None;
    }
    let rest = b.get(pos..)?;
    let i = find(rest, b">")?;
    let tag = rest.get(..i)?;
    if tag.ends_with(b"/") {
        return None; // self-closing; caller wanted an open tag
    }
    pos.checked_add(i)?.checked_add(1)
}

/// Consume `</name>`, returning the new position.
pub fn consume_close_tag(b: &[u8], pos: usize, name: &str) -> Option<usize> {
    let pos = skip_ws(b, pos);
    let want = format!("</{name}>");
    if b.get(pos..)?.starts_with(want.as_bytes()) {
        pos.checked_add(want.len())
    } else {
        None
    }
}

/// Read text up to the next `<`, with entities decoded. Returns the text and
/// the new position.
pub fn read_text(b: &[u8], pos: usize) -> (String, usize) {
    let Some(rest) = b.get(pos..) else {
        return (String::new(), b.len());
    };
    let end = find(rest, b"<").unwrap_or(rest.len());
    let raw = rest.get(..end).unwrap_or(rest);
    (decode_entities(raw), pos.saturating_add(end))
}

/// Locate a tag's closing `>`, skipping any that appear inside quoted
/// attribute values.
pub fn find_tag_end(rest: &[u8], from: usize) -> Option<usize> {
    let mut quote: Option<u8> = None;
    let mut i = from;
    while let Some(&c) = rest.get(i) {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None => match c {
                b'"' | b'\'' => quote = Some(c),
                b'>' => return Some(i),
                _ => {}
            },
        }
        i = i.checked_add(1)?;
    }
    None
}

/// Read a quoted attribute value by name out of a tag's attribute region.
pub fn attr(attrs: &[u8], want: &str) -> Option<String> {
    let mut i = 0usize;
    while i < attrs.len() {
        while attrs.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
            i = i.checked_add(1)?;
        }
        let start = i;
        while attrs
            .get(i)
            .is_some_and(|c| !c.is_ascii_whitespace() && *c != b'=')
        {
            i = i.checked_add(1)?;
        }
        let name = attrs.get(start..i)?;
        if name.is_empty() {
            return None;
        }
        while attrs.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
            i = i.checked_add(1)?;
        }
        if attrs.get(i) != Some(&b'=') {
            continue; // valueless attribute; move on
        }
        i = i.checked_add(1)?;
        while attrs.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
            i = i.checked_add(1)?;
        }
        let q = *attrs.get(i)?;
        if q != b'"' && q != b'\'' {
            return None;
        }
        i = i.checked_add(1)?;
        let vstart = i;
        while attrs.get(i).is_some_and(|c| *c != q) {
            i = i.checked_add(1)?;
        }
        let value = attrs.get(vstart..i)?;
        i = i.checked_add(1)?;
        if name == want.as_bytes() {
            return Some(decode_entities(value));
        }
    }
    None
}

// --- event scanning ------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<'a> {
    Open {
        name: &'a str,
        attrs: &'a [u8],
        self_closing: bool,
    },
    Close {
        name: &'a str,
    },
    Text(&'a [u8]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next<'a> {
    Event(Event<'a>),
    End,
    /// Structurally broken — an unterminated tag, comment or CDATA section.
    Bad,
}

/// A pull scanner over an XML document.
pub struct Scanner<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Scanner { b, pos: 0 }
    }

    pub fn next_event(&mut self) -> Next<'a> {
        // Loops past skippable constructs — see `skip_junk`.
        loop {
            let Some(rest) = self.b.get(self.pos..) else {
                return Next::End;
            };
            if rest.is_empty() {
                return Next::End;
            }

            if rest.first() != Some(&b'<') {
                // Text runs to the next '<'; always advances at least one byte.
                let end = find(rest, b"<").unwrap_or(rest.len());
                let text = rest.get(..end).unwrap_or(rest);
                self.pos = self.pos.saturating_add(end.max(1));
                return Next::Event(Event::Text(text));
            }

            if rest.starts_with(b"<!--") {
                match find(rest, b"-->") {
                    Some(i) => {
                        self.pos = self.pos.saturating_add(i + 3);
                        continue;
                    }
                    None => return Next::Bad,
                }
            }
            if rest.starts_with(b"<![CDATA[") {
                match find(rest, b"]]>") {
                    Some(i) => {
                        let text = rest.get(9..i).unwrap_or(&[]);
                        self.pos = self.pos.saturating_add(i + 3);
                        return Next::Event(Event::Text(text));
                    }
                    None => return Next::Bad,
                }
            }
            if rest.starts_with(b"<?") || rest.starts_with(b"<!") {
                match find(rest, b">") {
                    Some(i) => {
                        self.pos = self.pos.saturating_add(i + 1);
                        continue;
                    }
                    None => return Next::Bad,
                }
            }

            let closing = rest.get(1) == Some(&b'/');
            let body_start = if closing { 2 } else { 1 };
            let Some(gt) = find_tag_end(rest, body_start) else {
                return Next::Bad;
            };
            let Some(body) = rest.get(body_start..gt) else {
                return Next::Bad;
            };
            self.pos = self.pos.saturating_add(gt + 1);

            let self_closing = body.last() == Some(&b'/');
            let body = if self_closing {
                body.get(..body.len().saturating_sub(1)).unwrap_or(&[])
            } else {
                body
            };

            let split = body
                .iter()
                .position(|c| c.is_ascii_whitespace())
                .unwrap_or(body.len());
            let Some(name_bytes) = body.get(..split) else {
                return Next::Bad;
            };
            if name_bytes.is_empty() {
                return Next::Bad;
            }
            let Ok(name) = std::str::from_utf8(name_bytes) else {
                return Next::Bad;
            };
            let attrs = body.get(split..).unwrap_or(&[]);

            return if closing {
                Next::Event(Event::Close { name })
            } else {
                Next::Event(Event::Open {
                    name,
                    attrs,
                    self_closing,
                })
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entities_decode() {
        assert_eq!(decode_entities(b"a&amp;b"), "a&b");
        assert_eq!(decode_entities(b"&lt;x&gt;"), "<x>");
        assert_eq!(decode_entities(b"&quot;q&apos;"), "\"q'");
        assert_eq!(decode_entities(b"&#65;&#x42;&#X43;"), "ABC");
        assert_eq!(decode_entities(b"no entities here"), "no entities here");
    }

    /// Text is UTF-8, and decoding must not step through it a byte at a time.
    #[test]
    fn non_ascii_text_survives_decoding() {
        assert_eq!(decode_entities("café".as_bytes()), "café");
        assert_eq!(
            decode_entities("naïve &amp; bold".as_bytes()),
            "naïve & bold"
        );
        assert_eq!(decode_entities("日本語".as_bytes()), "日本語");
        // Attribute values go through the same path.
        let attrs = " style=\"café\"".as_bytes();
        assert_eq!(attr(attrs, "style").as_deref(), Some("café"));
    }

    /// Every branch must advance (§3's amplification bug came from one that didn't).
    #[test]
    fn unrecognized_entities_advance_and_stay_linear() {
        assert_eq!(decode_entities(b"a&nope;b"), "a&nope;b");
        assert_eq!(decode_entities(b"&&&"), "&&&");
        assert_eq!(decode_entities(b"a&"), "a&");
        let many = vec![b'&'; 8192];
        assert_eq!(decode_entities(&many).len(), 8192);
        // An over-long body is not an entity: emitted as a literal '&'.
        let long = format!("&{};", "x".repeat(MAX_ENTITY_BODY + 5));
        assert_eq!(decode_entities(long.as_bytes()), long);
    }

    #[test]
    fn attributes_are_read_by_name() {
        assert_eq!(attr(br#" style="sha1""#, "style").as_deref(), Some("sha1"));
        assert_eq!(attr(br#" style='RSA'"#, "style").as_deref(), Some("RSA"));
        assert_eq!(
            attr(br#" id="1" style="application/x-gzip""#, "style").as_deref(),
            Some("application/x-gzip")
        );
        assert_eq!(attr(br#" id="1""#, "style"), None);
        assert_eq!(attr(b"", "style"), None);
        assert_eq!(
            attr(br#" style="a&amp;b""#, "style").as_deref(),
            Some("a&b")
        );
    }

    #[test]
    fn a_quoted_angle_bracket_does_not_end_a_tag() {
        let mut sc = Scanner::new(br#"<encoding style="a>b"/>"#);
        match sc.next_event() {
            Next::Event(Event::Open {
                name,
                attrs,
                self_closing,
            }) => {
                assert_eq!(name, "encoding");
                assert!(self_closing);
                assert_eq!(attr(attrs, "style").as_deref(), Some("a>b"));
            }
            other => panic!("expected a self-closing open tag, got {other:?}"),
        }
    }

    /// Skipping comments and PIs must not consume stack per construct.
    #[test]
    fn a_long_run_of_comments_does_not_recurse() {
        let mut doc = Vec::new();
        for _ in 0..50_000 {
            doc.extend_from_slice(b"<!-- c -->");
        }
        doc.extend_from_slice(b"<toc/>");

        let mut sc = Scanner::new(&doc);
        match sc.next_event() {
            Next::Event(Event::Open { name, .. }) => assert_eq!(name, "toc"),
            other => panic!("expected <toc/>, got {other:?}"),
        }
        // The cursor form has to survive it too.
        assert_eq!(peek_tag_name(&doc, skip_junk(&doc, 0)), Some("toc"));
    }

    #[test]
    fn unterminated_constructs_are_bad_not_end() {
        assert_eq!(Scanner::new(b"<!-- unterminated").next_event(), Next::Bad);
        assert_eq!(
            Scanner::new(b"<![CDATA[ unterminated").next_event(),
            Next::Bad
        );
        assert_eq!(Scanner::new(b"<unterminated").next_event(), Next::Bad);
        assert_eq!(Scanner::new(b"<?pi unterminated").next_event(), Next::Bad);
        assert_eq!(Scanner::new(b"").next_event(), Next::End);
    }

    #[test]
    fn cursor_primitives_round_trip_a_small_document() {
        let doc = b"<?xml version=\"1.0\"?>\n<!-- hi -->\n<plist><key>Label</key></plist>";
        let pos = skip_junk(doc, 0);
        assert_eq!(peek_tag_name(doc, pos), Some("plist"));
        let pos = consume_open_tag(doc, pos, "plist").expect("open plist");
        let pos = consume_open_tag(doc, pos, "key").expect("open key");
        let (text, pos) = read_text(doc, pos);
        assert_eq!(text, "Label");
        let pos = consume_close_tag(doc, pos, "key").expect("close key");
        assert!(consume_close_tag(doc, pos, "plist").is_some());
    }

    #[test]
    fn scanner_never_panics_on_arbitrary_bytes() {
        let samples: [&[u8]; 8] = [
            b"",
            b"<",
            b"</",
            b"<>",
            b"< >",
            b"<a b='",
            b"<![CDATA[",
            b"\xff\xfe<a/>",
        ];
        for s in samples {
            let mut sc = Scanner::new(s);
            for _ in 0..16 {
                if matches!(sc.next_event(), Next::End | Next::Bad) {
                    break;
                }
            }
        }
    }
}
