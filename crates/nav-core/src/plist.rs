//! Minimal, defensive property-list reading (binary `bplist00` and XML), for
//! `.app` executable resolution ([`crate::bundle`]) and the launchd-persistence
//! rule. Real bundles ship binary plists, so both formats are handled.
//!
//! §3/§11.9 discipline: no panics, no unbounded reads, every offset
//! bounds-checked, ceilings on depth/node-count/total-bytes, no external crate.
//! Not a general plist library — unsupported types, malformed structure,
//! cycles, or anything past a ceiling make [`parse`] return `None`.

/// Deepest container nesting [`parse`] will descend.
const MAX_DEPTH: usize = 32;
/// Most values [`parse`] will materialize — a ceiling on total work.
const MAX_NODES: usize = 100_000;
/// Largest `<data>` / binary blob retained. No caller inspects the bytes.
const MAX_DATA_BYTES: usize = 4 * 1024 * 1024;
/// Cumulative ceiling on payload bytes one [`parse`] will materialize.
/// `MAX_NODES` bounds the count; this bounds the size. The binary format needs
/// both: shared references form a DAG (not a cycle), and each shared object is
/// re-materialized per path. Above [`crate::context::MAX_CONTENT_BYTES`] with
/// headroom for UTF-16 → UTF-8 growth.
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;

/// A parsed plist value. `Dict` preserves key order (plists are small; a vec is
/// cheaper and more predictable than a map here).
#[derive(Debug, Clone, PartialEq)]
pub enum PlistValue {
    Bool(bool),
    Integer(i64),
    Real(f64),
    String(String),
    Data(Vec<u8>),
    Array(Vec<PlistValue>),
    Dict(Vec<(String, PlistValue)>),
    /// Seconds relative to the Core Foundation epoch (2001-01-01T00:00:00Z),
    /// kept raw — no rule needs calendar math yet.
    Date(f64),
}

impl PlistValue {
    pub fn as_dict(&self) -> Option<&[(String, PlistValue)]> {
        match self {
            PlistValue::Dict(entries) => Some(entries),
            _ => None,
        }
    }

    /// Value for `key` if this is a dict containing it.
    pub fn get(&self, key: &str) -> Option<&PlistValue> {
        self.as_dict()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            PlistValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PlistValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[PlistValue]> {
        match self {
            PlistValue::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            PlistValue::Integer(n) => Some(*n),
            _ => None,
        }
    }
}

/// Parse `bytes` as a binary (`bplist00`) or XML property list.
///
/// Returns `None` for anything that isn't a plist this reader recognizes, or
/// that it can't walk within its bounds — truncated, malformed, cyclic, an
/// unsupported object type, or past the depth/node ceilings. Never panics.
pub fn parse(bytes: &[u8]) -> Option<PlistValue> {
    if bytes.starts_with(b"bplist00") {
        return binary::parse(bytes);
    }

    let text = skip_bom_and_ws(bytes);
    if text.first() == Some(&b'<') {
        return xml_reader::parse(text);
    }

    None
}

/// Skip a UTF-8 BOM and leading ASCII whitespace, returning the remaining slice.
fn skip_bom_and_ws(bytes: &[u8]) -> &[u8] {
    let mut b = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    while let [first, rest @ ..] = b {
        if first.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

/// Read up to 8 big-endian bytes as a `u64`. `slice.len()` must be `<= 8`.
fn be_uint(slice: &[u8]) -> u64 {
    slice.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

// ---------------------------------------------------------------------------
// Binary plist (`bplist00`)
// ---------------------------------------------------------------------------

mod binary {
    use super::{be_uint, PlistValue, MAX_DATA_BYTES, MAX_DEPTH, MAX_NODES, MAX_TOTAL_BYTES};

    const TRAILER_LEN: usize = 32;
    const HEADER_LEN: usize = 8;

    struct Ctx<'a> {
        data: &'a [u8],
        /// Byte offset of each object, indexed by object number.
        offsets: Vec<usize>,
        ref_size: usize,
        /// One past the last byte an object may occupy (the offset table and
        /// trailer live at/after this).
        objects_end: usize,
        nodes: usize,
        /// Payload bytes materialized so far ([`MAX_TOTAL_BYTES`]) — not implied
        /// by `nodes` or input length, because of shared references.
        bytes: usize,
        /// Object indices currently being expanded; an index appearing twice is
        /// a reference cycle.
        active: Vec<usize>,
    }

    /// Charge `n` payload bytes against the parse-wide budget.
    fn charge(ctx: &mut Ctx, n: usize) -> Option<()> {
        ctx.bytes = ctx.bytes.checked_add(n)?;
        (ctx.bytes <= MAX_TOTAL_BYTES).then_some(())
    }

    pub(super) fn parse(data: &[u8]) -> Option<PlistValue> {
        if data.len() < HEADER_LEN + TRAILER_LEN {
            return None;
        }
        let trailer_start = data.len() - TRAILER_LEN;
        let trailer = &data[trailer_start..];

        let offset_size = trailer[6] as usize;
        let ref_size = trailer[7] as usize;
        if !(1..=8).contains(&offset_size) || !(1..=8).contains(&ref_size) {
            return None;
        }
        let num_objects = usize::try_from(be_uint(&trailer[8..16])).ok()?;
        let top_object = usize::try_from(be_uint(&trailer[16..24])).ok()?;
        let offset_table_offset = usize::try_from(be_uint(&trailer[24..32])).ok()?;

        // Each object is >= 1 byte, so more objects than the region can hold is
        // impossible — reject before allocating.
        if num_objects == 0
            || num_objects > MAX_NODES
            || num_objects > trailer_start
            || top_object >= num_objects
            || offset_table_offset < HEADER_LEN
            || offset_table_offset > trailer_start
        {
            return None;
        }

        let table_len = num_objects.checked_mul(offset_size)?;
        let table_end = offset_table_offset.checked_add(table_len)?;
        if table_end > trailer_start {
            return None;
        }

        let mut offsets = Vec::with_capacity(num_objects);
        for i in 0..num_objects {
            let start = offset_table_offset + i * offset_size;
            let off = usize::try_from(be_uint(&data[start..start + offset_size])).ok()?;
            // An object must live in the region before the offset table.
            if off < HEADER_LEN || off >= offset_table_offset {
                return None;
            }
            offsets.push(off);
        }

        let mut ctx = Ctx {
            data,
            offsets,
            ref_size,
            objects_end: offset_table_offset,
            nodes: 0,
            bytes: 0,
            active: Vec::new(),
        };
        decode(&mut ctx, top_object, 0)
    }

    fn decode(ctx: &mut Ctx, index: usize, depth: usize) -> Option<PlistValue> {
        if depth > MAX_DEPTH {
            return None;
        }
        ctx.nodes += 1;
        if ctx.nodes > MAX_NODES {
            return None;
        }
        if ctx.active.contains(&index) {
            return None; // reference cycle
        }

        let offset = *ctx.offsets.get(index)?;
        let marker = *ctx.data.get(offset)?;
        let (high, low) = (marker >> 4, (marker & 0x0f) as usize);

        match high {
            0x0 => match low {
                0x08 => Some(PlistValue::Bool(false)),
                0x09 => Some(PlistValue::Bool(true)),
                _ => None, // null / fill / unsupported singleton
            },
            0x1 => decode_int(ctx.data, offset, low),
            0x2 => decode_real(ctx.data, offset, low),
            0x3 if low == 0x3 => {
                let bytes: [u8; 8] = ctx.data.get(offset + 1..offset + 9)?.try_into().ok()?;
                Some(PlistValue::Date(f64::from_be_bytes(bytes)))
            }
            0x4 => {
                let (len, start) = read_len(ctx.data, offset, low)?;
                if len > MAX_DATA_BYTES {
                    return None;
                }
                let end = start.checked_add(len)?;
                let blob = ctx.data.get(start..end)?.to_vec();
                charge(ctx, blob.len())?;
                Some(PlistValue::Data(blob))
            }
            0x5 => {
                let (len, start) = read_len(ctx.data, offset, low)?;
                let end = start.checked_add(len)?;
                let bytes = ctx.data.get(start..end)?;
                let s = std::str::from_utf8(bytes).ok()?.to_string();
                charge(ctx, s.len())?;
                Some(PlistValue::String(s))
            }
            0x6 => {
                let (units, start) = read_len(ctx.data, offset, low)?;
                let byte_len = units.checked_mul(2)?;
                let end = start.checked_add(byte_len)?;
                let bytes = ctx.data.get(start..end)?;
                let u16s: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                let s = char::decode_utf16(u16s)
                    .collect::<Result<String, _>>()
                    .ok()?;
                charge(ctx, s.len())?;
                Some(PlistValue::String(s))
            }
            0xa => {
                let (count, start) = read_len(ctx.data, offset, low)?;
                let refs = read_refs(ctx, start, count)?;
                ctx.active.push(index);
                let mut items = Vec::with_capacity(refs.len());
                for r in refs {
                    match decode(ctx, r, depth + 1) {
                        Some(v) => items.push(v),
                        None => {
                            ctx.active.pop();
                            return None;
                        }
                    }
                }
                ctx.active.pop();
                Some(PlistValue::Array(items))
            }
            0xd => {
                let (count, start) = read_len(ctx.data, offset, low)?;
                let key_refs = read_refs(ctx, start, count)?;
                let val_start = start + count * ctx.ref_size;
                let val_refs = read_refs(ctx, val_start, count)?;
                ctx.active.push(index);
                let mut entries = Vec::with_capacity(count);
                for (kr, vr) in key_refs.into_iter().zip(val_refs) {
                    let key = match decode(ctx, kr, depth + 1) {
                        Some(PlistValue::String(s)) => s,
                        _ => {
                            ctx.active.pop();
                            return None;
                        }
                    };
                    match decode(ctx, vr, depth + 1) {
                        Some(v) => entries.push((key, v)),
                        None => {
                            ctx.active.pop();
                            return None;
                        }
                    }
                }
                ctx.active.pop();
                Some(PlistValue::Dict(entries))
            }
            _ => None, // uid, set, and anything unrecognized
        }
    }

    fn decode_int(data: &[u8], offset: usize, low: usize) -> Option<PlistValue> {
        let count = 1usize << low; // 1, 2, 4, 8, or 16 bytes
        let bytes = data.get(offset + 1..offset + 1 + count)?;
        let value = match count {
            1 | 2 | 4 => be_uint(bytes) as i64,
            8 => i64::from_be_bytes(bytes.try_into().ok()?),
            16 => i64::try_from(i128::from_be_bytes(bytes.try_into().ok()?)).ok()?,
            _ => return None,
        };
        Some(PlistValue::Integer(value))
    }

    fn decode_real(data: &[u8], offset: usize, low: usize) -> Option<PlistValue> {
        let count = 1usize << low;
        let bytes = data.get(offset + 1..offset + 1 + count)?;
        let value = match count {
            4 => f32::from_be_bytes(bytes.try_into().ok()?) as f64,
            8 => f64::from_be_bytes(bytes.try_into().ok()?),
            _ => return None,
        };
        Some(PlistValue::Real(value))
    }

    /// Decode the length nibble shared by data/string/array/dict markers,
    /// returning `(length, offset_of_first_content_byte)`. A nibble of `0xf`
    /// means the real length follows as an inline integer object.
    fn read_len(data: &[u8], offset: usize, low: usize) -> Option<(usize, usize)> {
        if low != 0x0f {
            return Some((low, offset + 1));
        }
        let int_marker = *data.get(offset + 1)?;
        if int_marker >> 4 != 0x1 {
            return None;
        }
        let int_count = 1usize << (int_marker & 0x0f);
        // `be_uint` folds to u64 and silently drops the top bytes of a wider
        // integer (2^56+2 would read back as 2). A real length is 1/2/4/8 bytes.
        if int_count > 8 {
            return None;
        }
        let bytes = data.get(offset + 2..offset + 2 + int_count)?;
        let len = usize::try_from(be_uint(bytes)).ok()?;
        Some((len, offset + 2 + int_count))
    }

    /// Read `count` object references of `ctx.ref_size` bytes each, starting at
    /// `start`, validating every one is a real object index and the whole run
    /// sits inside the object region.
    fn read_refs(ctx: &Ctx, start: usize, count: usize) -> Option<Vec<usize>> {
        if count > MAX_NODES {
            return None;
        }
        let span = count.checked_mul(ctx.ref_size)?;
        let end = start.checked_add(span)?;
        if end > ctx.objects_end {
            return None;
        }
        let mut refs = Vec::with_capacity(count);
        for i in 0..count {
            let at = start + i * ctx.ref_size;
            let r = usize::try_from(be_uint(&ctx.data[at..at + ctx.ref_size])).ok()?;
            if r >= ctx.offsets.len() {
                return None;
            }
            refs.push(r);
        }
        Some(refs)
    }
}

// ---------------------------------------------------------------------------
// XML plist
// ---------------------------------------------------------------------------

mod xml_reader {
    use super::{PlistValue, MAX_DATA_BYTES, MAX_DEPTH, MAX_NODES};
    use crate::xml;

    pub(super) fn parse(bytes: &[u8]) -> Option<PlistValue> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut p = Parser {
            b: text.as_bytes(),
            pos: 0,
            nodes: 0,
        };
        p.skip_prolog();
        // <plist ...> wrapper is optional in the wild; step past it if present.
        if p.peek_tag_name() == Some("plist") {
            p.consume_open_tag("plist")?;
        }
        p.skip_junk();
        let value = p.parse_value(0)?;
        Some(value)
    }

    struct Parser<'a> {
        b: &'a [u8],
        pos: usize,
        nodes: usize,
    }

    impl<'a> Parser<'a> {
        fn rest(&self) -> &'a [u8] {
            self.b.get(self.pos.min(self.b.len())..).unwrap_or(&[])
        }

        fn starts_with(&self, s: &str) -> bool {
            self.rest().starts_with(s.as_bytes())
        }

        /// Skip whitespace, comments, processing instructions and the DOCTYPE.
        fn skip_junk(&mut self) {
            self.pos = xml::skip_junk(self.b, self.pos);
        }

        fn skip_prolog(&mut self) {
            self.skip_junk();
        }

        /// Name of the tag the cursor is on (`<name ...>` or `<name/>`), without
        /// consuming anything. `None` if the cursor isn't on a start tag.
        fn peek_tag_name(&self) -> Option<&'a str> {
            xml::peek_tag_name(self.b, self.pos)
        }

        /// Consume `<name ...>` (not self-closing). Returns `None` on mismatch.
        fn consume_open_tag(&mut self, name: &str) -> Option<()> {
            self.pos = xml::consume_open_tag(self.b, self.pos, name)?;
            Some(())
        }

        /// Consume `</name>`.
        fn consume_close_tag(&mut self, name: &str) -> Option<()> {
            self.pos = xml::consume_close_tag(self.b, self.pos, name)?;
            Some(())
        }

        /// Read text up to the next `<`, with XML entities decoded.
        fn read_text(&mut self) -> String {
            let (text, pos) = xml::read_text(self.b, self.pos);
            self.pos = pos;
            text
        }

        fn bump_nodes(&mut self) -> Option<()> {
            self.nodes += 1;
            if self.nodes > MAX_NODES {
                None
            } else {
                Some(())
            }
        }

        fn parse_value(&mut self, depth: usize) -> Option<PlistValue> {
            if depth > MAX_DEPTH {
                return None;
            }
            self.bump_nodes()?;
            self.skip_junk();
            let name = self.peek_tag_name()?;

            // Self-closing forms: <true/>, <false/>, <string/>, <array/>, <dict/>, <data/>.
            let r = self.rest();
            let close = xml::find(r, b">")?;
            let self_closing = r[..close].ends_with(b"/");
            self.pos += close + 1;

            match name {
                "true" => Some(PlistValue::Bool(true)),
                "false" => Some(PlistValue::Bool(false)),
                _ if self_closing => match name {
                    "string" => Some(PlistValue::String(String::new())),
                    "data" => Some(PlistValue::Data(Vec::new())),
                    "array" => Some(PlistValue::Array(Vec::new())),
                    "dict" => Some(PlistValue::Dict(Vec::new())),
                    "integer" | "real" => None,
                    _ => None,
                },
                "string" => {
                    let s = self.read_text();
                    self.consume_close_tag("string")?;
                    Some(PlistValue::String(s))
                }
                "integer" => {
                    let s = self.read_text();
                    self.consume_close_tag("integer")?;
                    s.trim().parse::<i64>().ok().map(PlistValue::Integer)
                }
                "real" => {
                    let s = self.read_text();
                    self.consume_close_tag("real")?;
                    s.trim().parse::<f64>().ok().map(PlistValue::Real)
                }
                "date" => {
                    let _ = self.read_text();
                    self.consume_close_tag("date")?;
                    Some(PlistValue::Date(0.0)) // value unused; keep the shape
                }
                "data" => {
                    let s = self.read_text();
                    self.consume_close_tag("data")?;
                    Some(PlistValue::Data(decode_base64_bounded(&s)))
                }
                "array" => {
                    let mut items = Vec::new();
                    loop {
                        self.skip_junk();
                        if self.starts_with("</array>") {
                            self.pos += "</array>".len();
                            break;
                        }
                        if self.rest().is_empty() {
                            return None;
                        }
                        items.push(self.parse_value(depth + 1)?);
                    }
                    Some(PlistValue::Array(items))
                }
                "dict" => {
                    let mut entries = Vec::new();
                    loop {
                        self.skip_junk();
                        if self.starts_with("</dict>") {
                            self.pos += "</dict>".len();
                            break;
                        }
                        if !self.starts_with("<key>") {
                            return None;
                        }
                        self.pos += "<key>".len();
                        let key = self.read_text();
                        self.consume_close_tag("key")?;
                        let value = self.parse_value(depth + 1)?;
                        entries.push((key, value));
                    }
                    Some(PlistValue::Dict(entries))
                }
                _ => None,
            }
        }
    }

    /// Best-effort bounded base64 decode. A malformed blob yields an empty vec
    /// rather than failing the parse — callers only need the value's shape.
    fn decode_base64_bounded(s: &str) -> Vec<u8> {
        fn val(c: u8) -> Option<u8> {
            match c {
                b'A'..=b'Z' => Some(c - b'A'),
                b'a'..=b'z' => Some(c - b'a' + 26),
                b'0'..=b'9' => Some(c - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        }
        let symbols: Vec<u8> = s.bytes().filter_map(val).collect();
        let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
        for chunk in symbols.chunks(4) {
            if chunk.len() < 2 {
                break;
            }
            let b = |i: usize| chunk.get(i).copied().unwrap_or(0);
            out.push((b(0) << 2) | (b(1) >> 4));
            if chunk.len() >= 3 {
                out.push((b(1) << 4) | (b(2) >> 2));
            }
            if chunk.len() >= 4 {
                out.push((b(2) << 6) | b(3));
            }
            if out.len() > MAX_DATA_BYTES {
                out.truncate(MAX_DATA_BYTES);
                break;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `bplist00` blob from top-level dict entries (string/bool/int/
    /// string-array values) — enough for the tests without `plutil`.
    fn synth_bplist(entries: &[(&str, TestVal)]) -> Vec<u8> {
        enum Obj {
            Str(String),
            Bool(bool),
            Int(i64),
            Arr(Vec<usize>),
            Dict(Vec<(usize, usize)>),
        }

        let mut objs: Vec<Obj> = Vec::new();
        // obj 0 is the root dict; fill its entry refs as we intern children.
        objs.push(Obj::Dict(Vec::new()));

        fn intern_str(objs: &mut Vec<Obj>, s: &str) -> usize {
            objs.push(Obj::Str(s.to_string()));
            objs.len() - 1
        }

        let mut dict_entries: Vec<(usize, usize)> = Vec::new();
        for (k, v) in entries {
            let kr = intern_str(&mut objs, k);
            let vr = match v {
                TestVal::Str(s) => intern_str(&mut objs, s),
                TestVal::Bool(b) => {
                    objs.push(Obj::Bool(*b));
                    objs.len() - 1
                }
                TestVal::Int(n) => {
                    objs.push(Obj::Int(*n));
                    objs.len() - 1
                }
                TestVal::Arr(items) => {
                    let refs: Vec<usize> = items.iter().map(|s| intern_str(&mut objs, s)).collect();
                    objs.push(Obj::Arr(refs));
                    objs.len() - 1
                }
            };
            dict_entries.push((kr, vr));
        }
        objs[0] = Obj::Dict(dict_entries);

        // Encode objects with 1-byte refs (few objects) but a real
        // extended-length header for any collection/string of 15+ elements.
        fn push_marker(body: &mut Vec<u8>, high: u8, len: usize) {
            if len < 15 {
                body.push((high << 4) | len as u8);
            } else {
                body.push((high << 4) | 0x0f);
                body.push(0x13); // inline 8-byte int length
                body.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }

        let mut body = Vec::new();
        let mut offsets = Vec::with_capacity(objs.len());
        for obj in &objs {
            offsets.push(8 + body.len());
            match obj {
                Obj::Str(s) => {
                    assert!(s.is_ascii());
                    push_marker(&mut body, 0x5, s.len());
                    body.extend_from_slice(s.as_bytes());
                }
                Obj::Bool(b) => body.push(if *b { 0x09 } else { 0x08 }),
                Obj::Int(n) => {
                    body.push(0x13); // 8-byte int
                    body.extend_from_slice(&n.to_be_bytes());
                }
                Obj::Arr(refs) => {
                    push_marker(&mut body, 0xa, refs.len());
                    body.extend(refs.iter().map(|&r| r as u8));
                }
                Obj::Dict(pairs) => {
                    push_marker(&mut body, 0xd, pairs.len());
                    body.extend(pairs.iter().map(|&(k, _)| k as u8));
                    body.extend(pairs.iter().map(|&(_, v)| v as u8));
                }
            }
        }

        let mut out = Vec::new();
        out.extend_from_slice(b"bplist00");
        out.extend_from_slice(&body);
        let table_off = out.len();
        out.extend(offsets.iter().map(|&o| o as u8));

        let mut trailer = [0u8; 32];
        trailer[6] = 1; // offset int size
        trailer[7] = 1; // object ref size
        trailer[8..16].copy_from_slice(&(objs.len() as u64).to_be_bytes());
        // top object 0 -> trailer[16..24] stays zero
        trailer[24..32].copy_from_slice(&(table_off as u64).to_be_bytes());
        out.extend_from_slice(&trailer);
        out
    }

    enum TestVal {
        Str(&'static str),
        Bool(bool),
        Int(i64),
        Arr(Vec<&'static str>),
    }

    const INFO_PLIST_XML: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>realmain</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.tool &amp; co</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
</dict>
</plist>"#;

    #[test]
    fn xml_info_plist_reads_bundle_executable() {
        let v = parse(INFO_PLIST_XML).expect("parses");
        assert_eq!(
            v.get("CFBundleExecutable").and_then(|x| x.as_str()),
            Some("realmain")
        );
        assert_eq!(
            v.get("CFBundleIdentifier").and_then(|x| x.as_str()),
            Some("com.example.tool & co")
        );
    }

    #[test]
    fn xml_launch_agent_shapes_parse() {
        let xml = br#"<plist version="1.0"><dict>
            <key>Label</key><string>com.example.helper</string>
            <key>ProgramArguments</key>
            <array><string>/usr/local/bin/helper</string><string>--daemon</string></array>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><false/>
            <key>StartInterval</key><integer>3600</integer>
        </dict></plist>"#;
        let v = parse(xml).expect("parses");
        assert_eq!(
            v.get("Label").and_then(|x| x.as_str()),
            Some("com.example.helper")
        );
        assert_eq!(v.get("RunAtLoad").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(v.get("KeepAlive").and_then(|x| x.as_bool()), Some(false));
        assert_eq!(v.get("StartInterval").and_then(|x| x.as_i64()), Some(3600));
        let args = v
            .get("ProgramArguments")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(args[0].as_str(), Some("/usr/local/bin/helper"));
    }

    #[test]
    fn binary_plist_round_trips() {
        let blob = synth_bplist(&[
            ("Label", TestVal::Str("com.apple.softwareupdate")),
            ("RunAtLoad", TestVal::Bool(true)),
            ("KeepAlive", TestVal::Bool(true)),
            ("StartInterval", TestVal::Int(30)),
            (
                "ProgramArguments",
                TestVal::Arr(vec!["/bin/sh", "-c", "payload"]),
            ),
        ]);
        let v = parse(&blob).expect("parses binary plist");
        assert_eq!(
            v.get("Label").and_then(|x| x.as_str()),
            Some("com.apple.softwareupdate")
        );
        assert_eq!(v.get("RunAtLoad").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(v.get("StartInterval").and_then(|x| x.as_i64()), Some(30));
        let args = v
            .get("ProgramArguments")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(args.len(), 3);
        assert_eq!(args[2].as_str(), Some("payload"));
    }

    #[test]
    fn non_plist_input_is_none() {
        assert!(parse(b"").is_none());
        assert!(parse(b"#!/bin/sh\necho hi\n").is_none());
        assert!(parse(b"\x7fELF\x02\x01\x01\x00").is_none());
        assert!(parse(b"bplist00").is_none()); // header only, no trailer
        assert!(parse(b"{ \"json\": true }").is_none());
    }

    #[test]
    fn truncated_and_garbage_binary_never_panics() {
        let good = synth_bplist(&[("k", TestVal::Str("v"))]);
        for len in 0..good.len() {
            let _ = parse(&good[..len]);
        }
        // Flip every byte in turn; must never panic, only ever return None/Some.
        for i in 0..good.len() {
            let mut m = good.clone();
            m[i] ^= 0xff;
            let _ = parse(&m);
        }
    }

    #[test]
    fn deeply_nested_xml_is_bounded_not_a_stack_overflow() {
        let mut xml = b"<plist>".to_vec();
        for _ in 0..5000 {
            xml.extend_from_slice(b"<array>");
        }
        // No closing tags: parser must bail on depth/EOF, not recurse forever.
        assert!(parse(&xml).is_none());
    }

    /// A tiny `bplist00` that decodes to `fanout ^ levels` copies of one
    /// `leaf`-byte string — a shared-reference DAG, not a cycle.
    fn synth_shared_ref_bplist(levels: usize, fanout: usize, leaf: usize) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let mut offsets: Vec<usize> = Vec::new();

        for level in 0..levels {
            offsets.push(8 + body.len());
            body.push(0xa0 | fanout as u8); // array, 1-byte refs
            body.extend(std::iter::repeat_n((level + 1) as u8, fanout));
        }
        offsets.push(8 + body.len());
        body.push(0x5f); // ASCII string, extended length
        body.push(0x12); // ... given as a 4-byte int
        body.extend_from_slice(&(leaf as u32).to_be_bytes());
        body.extend(std::iter::repeat_n(b'A', leaf));

        let mut out = b"bplist00".to_vec();
        out.extend_from_slice(&body);
        let table_off = out.len();
        for &o in &offsets {
            out.extend_from_slice(&(o as u32).to_be_bytes());
        }
        let mut trailer = [0u8; 32];
        trailer[6] = 4; // offset int size
        trailer[7] = 1; // object ref size
        trailer[8..16].copy_from_slice(&(offsets.len() as u64).to_be_bytes());
        // top object 0 -> trailer[16..24] stays zero
        trailer[24..32].copy_from_slice(&(table_off as u64).to_be_bytes());
        out.extend_from_slice(&trailer);
        out
    }

    /// Total payload bytes held by a parsed tree.
    fn materialized_bytes(v: &PlistValue) -> usize {
        let mut stack = vec![v];
        let mut total = 0usize;
        while let Some(x) = stack.pop() {
            match x {
                PlistValue::String(s) => total += s.len(),
                PlistValue::Data(d) => total += d.len(),
                PlistValue::Array(items) => stack.extend(items.iter()),
                PlistValue::Dict(entries) => {
                    for (k, val) in entries {
                        total += k.len();
                        stack.push(val);
                    }
                }
                _ => {}
            }
        }
        total
    }

    #[test]
    fn oversized_extended_length_integer_is_rejected() {
        // String length given as a 16-byte integer of 2^56+2, which `be_uint`
        // would fold to 2.
        let mut body: Vec<u8> = vec![0x5f, 0x14];
        let mut len = [0u8; 16];
        len[7] = 0x01;
        len[15] = 0x02;
        body.extend_from_slice(&len);
        body.extend_from_slice(b"hi");

        let mut out = b"bplist00".to_vec();
        out.extend_from_slice(&body);
        let table_off = out.len();
        out.push(8); // one object, at offset 8
        let mut trailer = [0u8; 32];
        trailer[6] = 1;
        trailer[7] = 1;
        trailer[8..16].copy_from_slice(&1u64.to_be_bytes());
        trailer[24..32].copy_from_slice(&(table_off as u64).to_be_bytes());
        out.extend_from_slice(&trailer);

        assert!(parse(&out).is_none(), "a >8-byte length must be rejected");
    }

    #[test]
    fn shared_references_cannot_amplify_memory() {
        // Regression: nothing capped total materialized bytes, so a shared-ref
        // DAG amplified an 8 KB input to 82 MB. `MAX_TOTAL_BYTES` is the fix.
        let blob = synth_shared_ref_bplist(4, 10, 8 * 1024);
        assert!(blob.len() < 16 * 1024, "input is small: {}", blob.len());
        assert!(
            parse(&blob).is_none(),
            "a tree past the byte budget must be rejected, not materialized"
        );

        // Sharing itself is fine: a DAG under the byte budget still parses.
        let modest = synth_shared_ref_bplist(2, 4, 1024);
        let v = parse(&modest).expect("a small shared-ref tree still parses");
        assert_eq!(materialized_bytes(&v), 4 * 4 * 1024);
    }

    #[test]
    fn xml_entities_decode() {
        let xml = br#"<plist><dict><key>k</key>
            <string>a&amp;b&lt;c&gt;d&quot;e&apos;f&#65;&#x42;&nope;&loose</string>
        </dict></plist>"#;
        let v = parse(xml).expect("parses");
        assert_eq!(
            v.get("k").and_then(|x| x.as_str()),
            // Known entities decode; unrecognized ones and bare '&' round-trip.
            Some(r#"a&b<c>d"e'fAB&nope;&loose"#)
        );
    }

    #[test]
    fn bare_ampersands_stay_linear_in_the_input() {
        // Regression: an unterminated entity left the cursor un-advanced, so
        // each '&' re-scanned and re-appended the rest of the text (quadratic).
        for n in [1_000usize, 4_000, 16_000] {
            let mut xml = b"<plist><dict><key>k</key><string>".to_vec();
            for _ in 0..n {
                xml.extend_from_slice(b"&a");
            }
            xml.extend_from_slice(b"</string></dict></plist>");

            let v = parse(&xml).expect("parses");
            let text = v.get("k").and_then(|x| x.as_str()).expect("string");
            // `&a` round-trips, so output length must track input exactly.
            assert_eq!(text.len(), 2 * n, "output must stay linear in input");
        }
    }

    #[test]
    fn binary_offset_table_out_of_range_is_rejected() {
        let mut blob = synth_bplist(&[("k", TestVal::Str("v"))]);
        let n = blob.len();
        // Point the offset-table offset past the trailer.
        blob[n - 8..n].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(parse(&blob).is_none());
    }
}
