//! Bounded PNG chunk walker (§5.2). Parses attacker-controlled input under
//! the §11.9 discipline: no panics, checked arithmetic, bounded loop.

use std::ops::Range;

use crate::inflate::crc32_extend;

/// The 8-byte PNG signature.
pub const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// Most chunks walked before the file is treated as malformed.
pub const MAX_CHUNKS: usize = 65_536;

/// Largest chunk length the format allows (2^31 - 1).
const MAX_CHUNK_LEN: u32 = 0x7FFF_FFFF;

/// Longest keyword (or iCCP profile name) before its NUL terminator.
const MAX_KEYWORD: usize = 79;

/// The byte ranges of `data`'s compressed-by-design payloads (`IDAT`,
/// `fdAT` after its sequence number, `zTXt`/`iCCP` after name and method,
/// compressed `iTXt` text), in file order. `None` unless `data` is a
/// well-formed PNG: verified CRCs, `IHDR` (length 13) first and only, and an
/// empty `IEND` ending exactly at the end of `data`.
pub fn compressed_ranges(data: &[u8]) -> Option<Vec<Range<usize>>> {
    if data.get(..8)? != SIGNATURE {
        return None;
    }
    let mut ranges = Vec::new();
    let mut pos = 8usize;
    for index in 0..MAX_CHUNKS {
        let len = u32::from_be_bytes(data.get(pos..pos.checked_add(4)?)?.try_into().ok()?);
        if len > MAX_CHUNK_LEN {
            return None;
        }
        let kind: [u8; 4] = data
            .get(pos.checked_add(4)?..pos.checked_add(8)?)?
            .try_into()
            .ok()?;
        if !kind.iter().all(u8::is_ascii_alphabetic) {
            return None;
        }
        let body_start = pos.checked_add(8)?;
        let body_end = body_start.checked_add(usize::try_from(len).ok()?)?;
        let end = body_end.checked_add(4)?;
        let body = data.get(body_start..body_end)?;
        let stored = u32::from_be_bytes(data.get(body_end..end)?.try_into().ok()?);
        if crc32_extend(crc32_extend(0, &kind), body) != stored {
            return None;
        }
        if (index == 0) != (&kind == b"IHDR") || (index == 0 && len != 13) {
            return None;
        }
        if &kind == b"IEND" {
            return (len == 0 && end == data.len()).then_some(ranges);
        }
        if let Some(offset) = compressed_offset(&kind, body)? {
            ranges.push(body_start.checked_add(offset)?..body_end);
        }
        pos = end;
    }
    None
}

/// Where the compressed part of a `kind` chunk's `body` starts:
/// `Some(None)` for a chunk with none, `None` if its header is malformed.
fn compressed_offset(kind: &[u8; 4], body: &[u8]) -> Option<Option<usize>> {
    match kind {
        b"IDAT" => Some(Some(0)),
        // 4-byte sequence number, then frame data
        b"fdAT" => (body.len() >= 4).then_some(Some(4)),
        b"zTXt" | b"iCCP" => {
            // keyword NUL, compression method, compressed data
            let method = keyword_end(body)?.checked_add(1)?;
            body.get(method)?;
            Some(Some(method.checked_add(1)?))
        }
        b"iTXt" => {
            // keyword NUL, flag, method, language NUL, translated keyword NUL, text
            let flag_at = keyword_end(body)?.checked_add(1)?;
            let flag = *body.get(flag_at)?;
            let lang_end = nul_after(body, flag_at.checked_add(2)?)?;
            let text = nul_after(body, lang_end.checked_add(1)?)?.checked_add(1)?;
            match flag {
                0 => Some(None),
                1 => Some(Some(text)),
                _ => None,
            }
        }
        _ => Some(None),
    }
}

/// The index of the NUL ending a 1-79 byte keyword at the start of `body`.
fn keyword_end(body: &[u8]) -> Option<usize> {
    let window = body.get(..body.len().min(MAX_KEYWORD + 1))?;
    let nul = window.iter().position(|&b| b == 0)?;
    (nul > 0).then_some(nul)
}

/// The index of the first NUL in `body` at or after `from`.
fn nul_after(body: &[u8], from: usize) -> Option<usize> {
    let rest = body.get(from..)?;
    from.checked_add(rest.iter().position(|&b| b == 0)?)
}

/// A chunk: big-endian length, `kind`, `body`, then the CRC-32 of both.
#[cfg(test)]
pub(crate) fn chunk(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut c = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    c.extend_from_slice(kind);
    c.extend_from_slice(body);
    c.extend_from_slice(&crate::inflate::crc32(&c[4..]).to_be_bytes());
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ihdr() -> Vec<u8> {
        chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0])
    }

    /// Signature, `IHDR`, `middle`, `IEND`.
    fn png(middle: &[Vec<u8>]) -> Vec<u8> {
        let mut c = SIGNATURE.to_vec();
        c.extend(ihdr());
        for m in middle {
            c.extend_from_slice(m);
        }
        c.extend(chunk(b"IEND", b""));
        c
    }

    /// Offset of the body of the `n`th chunk after `IHDR` in [`png`].
    fn body_at(middle: &[Vec<u8>], n: usize) -> usize {
        8 + 25 + middle[..n].iter().map(Vec::len).sum::<usize>() + 8
    }

    #[test]
    fn minimal_png_parses() {
        let middle = [chunk(b"IDAT", b"compressed")];
        let start = body_at(&middle, 0);
        let ranges = compressed_ranges(&png(&middle)).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], start..start + 10);
        assert_eq!(compressed_ranges(&png(&[])), Some(vec![]));
    }

    #[test]
    fn compressed_payload_offsets() {
        let middle = [
            chunk(b"tEXt", b"Comment\0plain"),
            chunk(b"zTXt", b"Comment\0\0zzzz"),
            chunk(b"iCCP", b"sRGB\0\0cccc"),
            chunk(b"iTXt", b"XML:com.adobe.xmp\0\0\0en\0\0<x/>"),
            chunk(b"iTXt", b"Title\0\x01\0en\0Titel\0iiii"),
            chunk(b"fdAT", b"\0\0\0\x01ffff"),
            chunk(b"stEg", b"private"),
        ];
        let c = png(&middle);
        let ranges = compressed_ranges(&c).unwrap();
        let picked: Vec<&[u8]> = ranges.iter().map(|r| &c[r.clone()]).collect();
        assert_eq!(picked, [&b"zzzz"[..], b"cccc", b"iiii", b"ffff"]);
        assert_eq!(ranges[0].start, body_at(&middle, 1) + 9);
    }

    #[test]
    fn bad_crc_rejected() {
        let mut c = png(&[chunk(b"IDAT", b"data")]);
        let crc_at = body_at(&[], 0) + 4;
        c[crc_at] ^= 1;
        assert_eq!(compressed_ranges(&c), None);
    }

    #[test]
    fn trailing_data_rejected() {
        let mut c = png(&[chunk(b"IDAT", b"data")]);
        c.push(0);
        assert_eq!(compressed_ranges(&c), None);
    }

    #[test]
    fn every_truncation_rejected() {
        let c = png(&[chunk(b"tEXt", b"k\0v"), chunk(b"IDAT", b"data")]);
        for len in 0..c.len() {
            assert_eq!(compressed_ranges(&c[..len]), None, "len {len}");
        }
    }

    #[test]
    fn missing_iend_rejected() {
        let mut c = SIGNATURE.to_vec();
        c.extend(ihdr());
        c.extend(chunk(b"IDAT", b"data"));
        assert_eq!(compressed_ranges(&c), None);
    }

    #[test]
    fn ihdr_placement_enforced() {
        // duplicate IHDR
        assert_eq!(compressed_ranges(&png(&[ihdr()])), None);
        // IHDR not first
        let mut c = SIGNATURE.to_vec();
        c.extend(chunk(b"tEXt", b"k\0v"));
        c.extend(ihdr());
        c.extend(chunk(b"IEND", b""));
        assert_eq!(compressed_ranges(&c), None);
        // IHDR of the wrong length
        let mut c = SIGNATURE.to_vec();
        c.extend(chunk(b"IHDR", &[0; 12]));
        c.extend(chunk(b"IEND", b""));
        assert_eq!(compressed_ranges(&c), None);
    }

    #[test]
    fn bad_headers_rejected() {
        let mut nonempty_iend = SIGNATURE.to_vec();
        nonempty_iend.extend(ihdr());
        nonempty_iend.extend(chunk(b"IEND", b"x"));
        let mut huge = png(&[]);
        let at = 8 + 25;
        huge[at..at + 4].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        for c in [
            nonempty_iend,
            huge,
            png(&[chunk(b"ID1T", b"data")]),
            png(&[chunk(b"zTXt", b"\0\0zz")]),
            png(&[chunk(b"zTXt", &[b'k'; 80])]),
            png(&[chunk(b"zTXt", b"Comment\0")]),
            png(&[chunk(b"iTXt", b"k\0\x02\0en\0t\0x")]),
            png(&[chunk(b"iTXt", b"k\0\x01\0en\0t")]),
            png(&[chunk(b"fdAT", b"\0\0\0")]),
        ] {
            assert_eq!(compressed_ranges(&c), None);
        }
    }

    #[test]
    fn keyword_length_bound() {
        let mut body = vec![b'k'; 79];
        body.extend_from_slice(b"\0\0zz");
        let ranges = compressed_ranges(&png(&[chunk(b"zTXt", &body)]));
        assert_eq!(ranges.map(|r| r.len()), Some(1));
    }

    #[test]
    fn chunk_count_capped() {
        let filler = chunk(b"tEXt", b"k\0v");
        let at_cap = png(&vec![filler.clone(); MAX_CHUNKS - 2]);
        assert_eq!(compressed_ranges(&at_cap), Some(vec![]));
        let over = png(&vec![filler; MAX_CHUNKS - 1]);
        assert_eq!(compressed_ranges(&over), None);
    }
}
