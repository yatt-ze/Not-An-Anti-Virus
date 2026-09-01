//! Bounded DEFLATE (RFC 1951) with zlib (RFC 1950) and gzip (RFC 1952)
//! wrappers. Needed to read a `.pkg`: the xar TOC is a zlib stream and the
//! install scripts are a gzip stream in the heap (§5.2, §6.1).
//!
//! Hand-written per §3 (no third-party code on the parse path). Contract:
//! never panics, every offset bounds-checked, and a cumulative output
//! `budget` checked *before* each write, so a bomb is refused rather than
//! materialized. [`InflateError::BudgetExceeded`] is a §6.2 policy stop, not
//! evidence of malice — callers must keep it distinct from `Malformed`.

/// Longest Huffman code permitted by RFC 1951 §3.2.7.
const MAX_BITS: usize = 15;

/// Starting capacity. The buffer grows toward `budget` as bytes are produced,
/// so a large budget is not allocated up front.
const INITIAL_OUTPUT_CAPACITY: usize = 64 * 1024;

/// Base lengths for length symbols 257..=285 (RFC 1951 §3.2.5).
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
/// Extra bits read after each length symbol.
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// Base distances for distance symbols 0..=29 (RFC 1951 §3.2.5).
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
/// Extra bits read after each distance symbol.
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// The order code-length code lengths arrive in for a dynamic block
/// (RFC 1951 §3.2.7).
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Why a stream could not be decoded. `BudgetExceeded` is a §6.2 policy stop,
/// not malformation — keep it distinct (§10/§11.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateError {
    /// Input ended mid-stream.
    Truncated,
    /// Structurally invalid: bad block type, over-subscribed Huffman table,
    /// out-of-range symbol, or a back-reference before the start of output.
    Malformed,
    /// Output would exceed the caller's budget. Not a maliciousness finding (§6.2).
    BudgetExceeded,
    /// zlib/gzip header invalid, or it requests an unsupported preset dictionary.
    BadHeader,
    /// Adler-32 (zlib) or CRC-32/ISIZE (gzip) trailer did not match the output.
    ChecksumMismatch,
}

/// Decode a raw DEFLATE stream, producing at most `budget` bytes.
pub fn inflate(data: &[u8], budget: usize) -> Result<Vec<u8>, InflateError> {
    inflate_inner(data, budget).map(|(out, _)| out)
}

/// Decode an RFC 1950 zlib stream (2-byte header, DEFLATE body, 4-byte BE
/// Adler-32), producing at most `budget` bytes. Entry point for the xar TOC.
pub fn zlib_decompress(data: &[u8], budget: usize) -> Result<Vec<u8>, InflateError> {
    let cmf = *data.first().ok_or(InflateError::Truncated)?;
    let flg = *data.get(1).ok_or(InflateError::Truncated)?;

    // CM must be 8 (deflate); CINFO above 7 means a window larger than the
    // 32 KiB the format allows.
    if cmf & 0x0f != 8 || (cmf >> 4) > 7 {
        return Err(InflateError::BadHeader);
    }
    // The two header bytes, read big-endian, are a multiple of 31.
    if ((cmf as u16) * 256 + flg as u16) % 31 != 0 {
        return Err(InflateError::BadHeader);
    }
    if (flg >> 5) & 1 == 1 {
        return Err(InflateError::BadHeader); // FDICT: preset dictionary
    }

    let body = data.get(2..).ok_or(InflateError::Truncated)?;
    let (out, used) = inflate_inner(body, budget)?;

    let end = used.checked_add(4).ok_or(InflateError::Malformed)?;
    let trailer: [u8; 4] = body
        .get(used..end)
        .ok_or(InflateError::Truncated)?
        .try_into()
        .map_err(|_| InflateError::Truncated)?;
    if adler32(&out) != u32::from_be_bytes(trailer) {
        return Err(InflateError::ChecksumMismatch);
    }
    Ok(out)
}

/// Decode an RFC 1952 gzip stream (10-byte header, optional
/// FEXTRA/FNAME/FCOMMENT/FHCRC fields, DEFLATE body, LE CRC-32 + ISIZE
/// trailer), producing at most `budget` bytes.
///
/// The xar `encoding` attribute is unreliable — entries labelled
/// `application/x-gzip` are actually zlib, the `Scripts` entry labelled
/// `application/octet-stream` is actually gzip — so callers dispatch between
/// this and [`zlib_decompress`] on the leading bytes, not the label.
pub fn gzip_decompress(data: &[u8], budget: usize) -> Result<Vec<u8>, InflateError> {
    const FHCRC: u8 = 1 << 1;
    const FEXTRA: u8 = 1 << 2;
    const FNAME: u8 = 1 << 3;
    const FCOMMENT: u8 = 1 << 4;
    /// Bits 5-7 are reserved and must be zero (RFC 1952 §2.3.1.2).
    const RESERVED: u8 = 0b1110_0000;

    if *data.first().ok_or(InflateError::Truncated)? != 0x1f
        || *data.get(1).ok_or(InflateError::Truncated)? != 0x8b
    {
        return Err(InflateError::BadHeader);
    }
    if *data.get(2).ok_or(InflateError::Truncated)? != 8 {
        return Err(InflateError::BadHeader); // CM must be deflate
    }
    let flg = *data.get(3).ok_or(InflateError::Truncated)?;
    if flg & RESERVED != 0 {
        return Err(InflateError::BadHeader);
    }
    // Bytes 4..10 are MTIME/XFL/OS, none of which affect decoding.
    let mut off = 10usize;

    if flg & FEXTRA != 0 {
        let lo = *data.get(off).ok_or(InflateError::Truncated)? as usize;
        let hi = *data.get(off + 1).ok_or(InflateError::Truncated)? as usize;
        let xlen = lo | (hi << 8);
        off = off
            .checked_add(2)
            .and_then(|o| o.checked_add(xlen))
            .ok_or(InflateError::Malformed)?;
    }
    // FNAME/FCOMMENT are NUL-terminated; a missing terminator is `Truncated`.
    for flag in [FNAME, FCOMMENT] {
        if flg & flag != 0 {
            let rest = data.get(off..).ok_or(InflateError::Truncated)?;
            let nul = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or(InflateError::Truncated)?;
            off = off
                .checked_add(nul)
                .and_then(|o| o.checked_add(1))
                .ok_or(InflateError::Malformed)?;
        }
    }
    if flg & FHCRC != 0 {
        // 16-bit header CRC; skipped, since the payload CRC below covers us.
        off = off.checked_add(2).ok_or(InflateError::Malformed)?;
    }

    let body = data.get(off..).ok_or(InflateError::Truncated)?;
    let (out, used) = inflate_inner(body, budget)?;

    let end = used.checked_add(8).ok_or(InflateError::Malformed)?;
    let trailer = body.get(used..end).ok_or(InflateError::Truncated)?;
    let crc: [u8; 4] = trailer
        .get(..4)
        .ok_or(InflateError::Truncated)?
        .try_into()
        .map_err(|_| InflateError::Truncated)?;
    let isize_bytes: [u8; 4] = trailer
        .get(4..8)
        .ok_or(InflateError::Truncated)?
        .try_into()
        .map_err(|_| InflateError::Truncated)?;

    if crc32(&out) != u32::from_le_bytes(crc) {
        return Err(InflateError::ChecksumMismatch);
    }
    // ISIZE is the output length mod 2^32; a mismatch means the stream and
    // its trailer disagree about what was encoded.
    if (out.len() as u64 & 0xFFFF_FFFF) as u32 != u32::from_le_bytes(isize_bytes) {
        return Err(InflateError::ChecksumMismatch);
    }
    Ok(out)
}

/// Decode a DEFLATE stream, returning the output and how many bytes of
/// `data` were consumed (needed to locate the zlib trailer).
fn inflate_inner(data: &[u8], budget: usize) -> Result<(Vec<u8>, usize), InflateError> {
    let mut r = BitReader::new(data);
    let mut out = Vec::with_capacity(budget.min(INITIAL_OUTPUT_CAPACITY));

    loop {
        let final_block = r.bits(1)? == 1;
        match r.bits(2)? {
            0 => stored_block(&mut r, &mut out, budget)?,
            1 => {
                let (lit, dist) = fixed_tables()?;
                compressed_block(&mut r, &mut out, budget, &lit, &dist)?;
            }
            2 => {
                let (lit, dist) = dynamic_tables(&mut r)?;
                compressed_block(&mut r, &mut out, budget, &lit, &dist)?;
            }
            // BTYPE=11 is reserved.
            _ => return Err(InflateError::Malformed),
        }
        if final_block {
            break;
        }
    }

    Ok((out, r.bytes_consumed()))
}

/// An uncompressed block: byte-aligned, with a length and its ones-complement.
fn stored_block(r: &mut BitReader, out: &mut Vec<u8>, budget: usize) -> Result<(), InflateError> {
    let len = r.take_u16_le()?;
    let nlen = r.take_u16_le()?;
    if len != !nlen {
        return Err(InflateError::Malformed);
    }
    let len = len as usize;
    if out.len().checked_add(len).ok_or(InflateError::Malformed)? > budget {
        return Err(InflateError::BudgetExceeded);
    }
    let bytes = r.take_bytes(len)?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// A Huffman-coded block, fixed or dynamic. Runs until the end-of-block
/// symbol (256); every iteration consumes at least one bit, so a stream that
/// never reaches 256 returns `Truncated` rather than looping.
fn compressed_block(
    r: &mut BitReader,
    out: &mut Vec<u8>,
    budget: usize,
    lit: &Huffman,
    dist: &Huffman,
) -> Result<(), InflateError> {
    loop {
        let sym = lit.decode(r)?;
        match sym {
            0..=255 => {
                if out.len() >= budget {
                    return Err(InflateError::BudgetExceeded);
                }
                out.push(sym as u8);
            }
            256 => return Ok(()),
            _ => {
                let li = (sym as usize)
                    .checked_sub(257)
                    .ok_or(InflateError::Malformed)?;
                // Symbols 286/287 decode but have no length assigned.
                let base = *LENGTH_BASE.get(li).ok_or(InflateError::Malformed)?;
                let extra = *LENGTH_EXTRA.get(li).ok_or(InflateError::Malformed)?;
                let len = base as usize + r.bits(extra as u32)? as usize;

                let di = dist.decode(r)? as usize;
                let dbase = *DIST_BASE.get(di).ok_or(InflateError::Malformed)?;
                let dextra = *DIST_EXTRA.get(di).ok_or(InflateError::Malformed)?;
                let distance = dbase as usize + r.bits(dextra as u32)? as usize;

                // Distance before the start of output => out-of-bounds attempt.
                if distance == 0 || distance > out.len() {
                    return Err(InflateError::Malformed);
                }
                if out.len().checked_add(len).ok_or(InflateError::Malformed)? > budget {
                    return Err(InflateError::BudgetExceeded);
                }

                // Byte-at-a-time: `len` may exceed `distance`, so the copy can
                // legitimately read bytes it just wrote.
                let start = out.len() - distance;
                for i in 0..len {
                    let b = *out.get(start + i).ok_or(InflateError::Malformed)?;
                    out.push(b);
                }
            }
        }
    }
}

/// The fixed literal/length and distance tables of RFC 1951 §3.2.6.
fn fixed_tables() -> Result<(Huffman, Huffman), InflateError> {
    let mut lit = [0u8; 288];
    for (i, l) in lit.iter_mut().enumerate() {
        *l = if i < 144 {
            8
        } else if i < 256 {
            9
        } else if i < 280 {
            7
        } else {
            8
        };
    }
    // All 32 distance codes are 5 bits. Symbols 30 and 31 decode but have no
    // base distance, so `compressed_block` rejects them.
    let dist = [5u8; 32];
    Ok((Huffman::new(&lit)?, Huffman::new(&dist)?))
}

/// Read a dynamic block's code-length table and build its two Huffman trees.
fn dynamic_tables(r: &mut BitReader) -> Result<(Huffman, Huffman), InflateError> {
    let hlit = r.bits(5)? as usize + 257;
    let hdist = r.bits(5)? as usize + 1;
    let hclen = r.bits(4)? as usize + 4;
    // Same ceilings zlib enforces; both are reachable from the bit widths
    // above but never appear in a valid stream.
    if hlit > 286 || hdist > 30 {
        return Err(InflateError::Malformed);
    }

    let mut clens = [0u8; 19];
    for i in 0..hclen {
        let idx = *CLEN_ORDER.get(i).ok_or(InflateError::Malformed)?;
        let v = r.bits(3)? as u8;
        *clens.get_mut(idx).ok_or(InflateError::Malformed)? = v;
    }
    let clh = Huffman::new(&clens)?;

    let total = hlit.checked_add(hdist).ok_or(InflateError::Malformed)?;
    let mut lengths = vec![0u8; total];
    let mut i = 0usize;
    while i < total {
        let sym = clh.decode(r)?;
        match sym {
            0..=15 => {
                *lengths.get_mut(i).ok_or(InflateError::Malformed)? = sym as u8;
                i += 1;
            }
            // 16: repeat the previous length 3-6 times.
            16 => {
                if i == 0 {
                    return Err(InflateError::Malformed); // nothing to repeat
                }
                let prev = *lengths.get(i - 1).ok_or(InflateError::Malformed)?;
                let rep = 3 + r.bits(2)? as usize;
                if i + rep > total {
                    return Err(InflateError::Malformed);
                }
                for _ in 0..rep {
                    *lengths.get_mut(i).ok_or(InflateError::Malformed)? = prev;
                    i += 1;
                }
            }
            // 17/18: runs of zero lengths, 3-10 and 11-138 respectively.
            17 | 18 => {
                let rep = if sym == 17 {
                    3 + r.bits(3)? as usize
                } else {
                    11 + r.bits(7)? as usize
                };
                if i + rep > total {
                    return Err(InflateError::Malformed);
                }
                i += rep; // `lengths` is already zeroed
            }
            _ => return Err(InflateError::Malformed),
        }
    }

    let lit = Huffman::new(lengths.get(..hlit).ok_or(InflateError::Malformed)?)?;
    let dist = Huffman::new(lengths.get(hlit..).ok_or(InflateError::Malformed)?)?;
    Ok((lit, dist))
}

/// Canonical Huffman table: per-length code counts plus symbols in code order.
/// Bit-at-a-time decode — slower than a lookup table, but nothing to mis-size
/// on hostile input, and TOCs are kilobytes.
struct Huffman {
    counts: [u16; MAX_BITS + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self, InflateError> {
        let mut counts = [0u16; MAX_BITS + 1];
        for &l in lengths {
            let l = l as usize;
            if l > MAX_BITS {
                return Err(InflateError::Malformed);
            }
            *counts.get_mut(l).ok_or(InflateError::Malformed)? += 1;
        }

        // Over-subscribed (more codes at a length than the tree fits) is
        // malformed. Incomplete is tolerated — some encoders emit a one-entry
        // distance table, and uncovered codes fail in `decode` anyway.
        let mut left: i32 = 1;
        for len in 1..=MAX_BITS {
            left <<= 1;
            left -= *counts.get(len).ok_or(InflateError::Malformed)? as i32;
            if left < 0 {
                return Err(InflateError::Malformed);
            }
        }

        let total: usize = counts.iter().skip(1).map(|&c| c as usize).sum();
        let mut offsets = [0u16; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            let next = offsets
                .get(len)
                .ok_or(InflateError::Malformed)?
                .checked_add(*counts.get(len).ok_or(InflateError::Malformed)?)
                .ok_or(InflateError::Malformed)?;
            *offsets.get_mut(len + 1).ok_or(InflateError::Malformed)? = next;
        }

        let mut symbols = vec![0u16; total];
        for (sym, &l) in lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let slot = offsets.get_mut(l as usize).ok_or(InflateError::Malformed)?;
            let idx = *slot as usize;
            *symbols.get_mut(idx).ok_or(InflateError::Malformed)? =
                u16::try_from(sym).map_err(|_| InflateError::Malformed)?;
            *slot += 1;
        }

        Ok(Huffman { counts, symbols })
    }

    /// Decode one symbol, consuming between 1 and `MAX_BITS` bits.
    fn decode(&self, r: &mut BitReader) -> Result<u16, InflateError> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=MAX_BITS {
            code |= r.bits(1)? as i32;
            let count = *self.counts.get(len).ok_or(InflateError::Malformed)? as i32;
            if code - first < count {
                let idx =
                    usize::try_from(index + (code - first)).map_err(|_| InflateError::Malformed)?;
                return self
                    .symbols
                    .get(idx)
                    .copied()
                    .ok_or(InflateError::Malformed);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(InflateError::Malformed)
    }
}

/// LSB-first bit reader. Running out of input is `Truncated` — never a panic,
/// never a silent zero-fill.
struct BitReader<'a> {
    data: &'a [u8],
    /// Index of the next byte to pull into the bit buffer.
    pos: usize,
    buf: u32,
    /// Valid bits in `buf`; never exceeds 23.
    cnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            buf: 0,
            cnt: 0,
        }
    }

    fn bits(&mut self, n: u32) -> Result<u32, InflateError> {
        if n == 0 {
            return Ok(0);
        }
        if n > 16 {
            return Err(InflateError::Malformed);
        }
        while self.cnt < n {
            let b = *self.data.get(self.pos).ok_or(InflateError::Truncated)?;
            self.pos += 1;
            self.buf |= (b as u32) << self.cnt;
            self.cnt += 8;
        }
        let mask = (1u32 << n) - 1;
        let v = self.buf & mask;
        self.buf >>= n;
        self.cnt -= n;
        Ok(v)
    }

    /// Discard bits up to the next byte boundary.
    fn align(&mut self) {
        let drop = self.cnt % 8;
        self.buf >>= drop;
        self.cnt -= drop;
    }

    /// Byte offset of the next unread byte. Only meaningful once aligned.
    fn byte_pos(&self) -> usize {
        self.pos - (self.cnt as usize / 8)
    }

    /// Take `n` whole bytes, aligning first and dropping any buffered bits.
    fn take_bytes(&mut self, n: usize) -> Result<&'a [u8], InflateError> {
        self.align();
        let start = self.byte_pos();
        let end = start.checked_add(n).ok_or(InflateError::Malformed)?;
        let s = self.data.get(start..end).ok_or(InflateError::Truncated)?;
        self.pos = end;
        self.buf = 0;
        self.cnt = 0;
        Ok(s)
    }

    fn take_u16_le(&mut self) -> Result<u16, InflateError> {
        let b: [u8; 2] = self
            .take_bytes(2)?
            .try_into()
            .map_err(|_| InflateError::Truncated)?;
        Ok(u16::from_le_bytes(b))
    }

    /// Total bytes consumed, rounded up to a byte boundary.
    fn bytes_consumed(&mut self) -> usize {
        self.align();
        self.byte_pos()
    }
}

/// CRC-32 (reflected IEEE polynomial, RFC 1952 §8), computed bitwise —
/// inputs are kilobytes.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Adler-32 (RFC 1950 §9). Chunked at 5552 bytes — the longest run before the
/// accumulators can overflow 32 bits.
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    const NMAX: usize = 5552;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for chunk in data.chunks(NMAX) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generous ceiling for the ordinary vectors; the budget is tested separately.
    const BIG: usize = 1 << 20;

    /// Small budget for the corruption sweeps: they only check for panics and
    /// run thousands of decodes, so a low ceiling keeps `cargo test` quick
    /// while still exercising every header/Huffman/back-reference path.
    const FLIP_BUDGET: usize = 4096;

    /// Vectors generated from CPython's zlib — checked against a reference
    /// implementation, not this decoder. See `testdata/inflate/` and its generator.
    macro_rules! raw_vectors {
        ($($name:literal),* $(,)?) => {
            [$((
                $name,
                include_bytes!(concat!("../testdata/inflate/", $name, ".in")).as_slice(),
                include_bytes!(concat!("../testdata/inflate/", $name, ".out")).as_slice(),
            )),*]
        };
    }

    fn raw_cases() -> [(&'static str, &'static [u8], &'static [u8]); 8] {
        raw_vectors![
            "empty",
            "hello",
            "fixed",
            "stored",
            "dynamic_text",
            "zeros_64k",
            "window",
            "random_4k",
        ]
    }

    fn zlib_cases() -> [(&'static str, &'static [u8], &'static [u8]); 2] {
        raw_vectors!["zlib_hello", "zlib_toc"]
    }

    const BOMB: &[u8] = include_bytes!("../testdata/inflate/bomb.in");

    #[test]
    fn decodes_reference_vectors() {
        for (name, input, expected) in raw_cases() {
            match inflate(input, BIG) {
                Ok(got) => assert_eq!(got, expected, "{name}: output mismatch"),
                Err(e) => panic!("{name}: expected success, got {e:?}"),
            }
        }
    }

    #[test]
    fn decodes_zlib_wrapped_vectors() {
        for (name, input, expected) in zlib_cases() {
            match zlib_decompress(input, BIG) {
                Ok(got) => assert_eq!(got, expected, "{name}: output mismatch"),
                Err(e) => panic!("{name}: expected success, got {e:?}"),
            }
        }
    }

    /// Confirms the corpus actually reaches all three block types.
    #[test]
    fn corpus_covers_every_block_type() {
        // `stored` is level 0 (BTYPE=00), `fixed` is level 1 on a tiny input
        // (BTYPE=01), `dynamic_text` is level 9 on varied text (BTYPE=10).
        for (name, input, _) in raw_cases() {
            if !matches!(name, "stored" | "fixed" | "dynamic_text") {
                continue;
            }
            let mut r = BitReader::new(input);
            let _final = r.bits(1).expect("block header");
            let btype = r.bits(2).expect("block type");
            let want = match name {
                "stored" => 0,
                "fixed" => 1,
                _ => 2,
            };
            assert_eq!(btype, want, "{name}: unexpected first block type");
        }
    }

    /// The budget is a hard ceiling, reported as `BudgetExceeded`, not corruption.
    #[test]
    fn budget_stops_a_bomb() {
        const FULL: usize = 8 * 1024 * 1024;
        assert_eq!(inflate(BOMB, FULL - 1), Err(InflateError::BudgetExceeded));
        assert_eq!(inflate(BOMB, 0), Err(InflateError::BudgetExceeded));
        assert_eq!(inflate(BOMB, 1024), Err(InflateError::BudgetExceeded));

        let out = inflate(BOMB, FULL).expect("exact budget should succeed");
        assert_eq!(out.len(), FULL);
        assert!(out.iter().all(|&b| b == 0));
    }

    /// An exactly-sufficient budget succeeds and one byte less does not.
    #[test]
    fn budget_boundary_is_exact() {
        let (_, input, expected) = raw_cases()[5]; // zeros_64k
        assert_eq!(expected.len(), 65536);
        assert!(inflate(input, expected.len()).is_ok());
        assert_eq!(
            inflate(input, expected.len() - 1),
            Err(InflateError::BudgetExceeded)
        );
    }

    /// Byte offsets to probe within an input of `len` bytes: exhaustive for
    /// small inputs, and for large ones the whole header region + an even
    /// stride across the body + the tail (a full sweep costs seconds in debug
    /// for no extra coverage).
    fn probe_offsets(len: usize) -> Vec<usize> {
        const EXHAUSTIVE_UP_TO: usize = 1024;
        const HEAD: usize = 128;
        const SAMPLES: usize = 256;

        if len <= EXHAUSTIVE_UP_TO {
            return (0..len).collect();
        }
        let mut v: Vec<usize> = (0..HEAD.min(len)).collect();
        let stride = (len / SAMPLES).max(1);
        v.extend((HEAD..len).step_by(stride));
        v.extend(len.saturating_sub(8)..len);
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Every prefix of a stream must either error or produce the exact full
    /// output — never a partial result presented as complete, never a panic.
    #[test]
    fn prefixes_fail_cleanly() {
        for (name, input, expected) in raw_cases() {
            for n in probe_offsets(input.len()) {
                match inflate(&input[..n], BIG) {
                    Err(_) => {}
                    Ok(got) => assert_eq!(
                        got, expected,
                        "{name}: prefix of {n} bytes decoded to something other than the full output"
                    ),
                }
            }
        }
        for (name, input, expected) in zlib_cases() {
            for n in probe_offsets(input.len()) {
                match zlib_decompress(&input[..n], BIG) {
                    Err(_) => {}
                    Ok(got) => assert_eq!(got, expected, "{name}: short prefix decoded"),
                }
            }
        }
    }

    /// Corrupting a stream must never panic, hang, or read out of bounds.
    #[test]
    fn bit_flips_do_not_panic() {
        for (_, input, _) in raw_cases() {
            for byte in probe_offsets(input.len()) {
                for bit in 0..8 {
                    let mut v = input.to_vec();
                    if let Some(b) = v.get_mut(byte) {
                        *b ^= 1 << bit;
                    }
                    let _ = inflate(&v, FLIP_BUDGET);
                }
            }
        }
    }

    /// Truncating in the middle of a dynamic block's code-length table is a
    /// distinct path from truncating the compressed data itself.
    #[test]
    fn truncated_dynamic_header_is_an_error() {
        let (_, input, _) = raw_cases()[4]; // dynamic_text
        for n in 1..40.min(input.len()) {
            assert!(
                inflate(&input[..n], BIG).is_err(),
                "dynamic header truncated to {n} bytes should not decode"
            );
        }
    }

    #[test]
    fn reserved_block_type_is_malformed() {
        // BFINAL=1, BTYPE=11.
        assert_eq!(inflate(&[0x07], BIG), Err(InflateError::Malformed));
    }

    #[test]
    fn distance_before_start_of_output_is_malformed() {
        // Hand-built fixed-Huffman block: literal 'A', then a distance-7
        // back-reference — further back than anything written.
        assert_eq!(
            inflate(&[0x73, 0x04, 0x52], BIG),
            Err(InflateError::Malformed)
        );
        // Distance 1 is valid — confirms the rejection is about the distance.
        assert_eq!(
            inflate(&[0x73, 0x04, 0x02, 0x00], BIG).as_deref(),
            Ok(b"AAAA".as_slice())
        );
    }

    #[test]
    fn zlib_header_is_validated() {
        assert_eq!(zlib_decompress(&[], BIG), Err(InflateError::Truncated));
        assert_eq!(zlib_decompress(&[0x78], BIG), Err(InflateError::Truncated));
        // CM=7 is not deflate.
        assert_eq!(
            zlib_decompress(&[0x77, 0x9c, 0x00], BIG),
            Err(InflateError::BadHeader)
        );
        // Correct CM but the header checksum fails.
        assert_eq!(
            zlib_decompress(&[0x78, 0x9d, 0x00], BIG),
            Err(InflateError::BadHeader)
        );
        // FDICT set: preset dictionaries are not supported.
        assert_eq!(
            zlib_decompress(&[0x78, 0xbb, 0x00], BIG),
            Err(InflateError::BadHeader)
        );
    }

    #[test]
    fn adler_mismatch_is_reported_separately() {
        let (_, input, _) = zlib_cases()[0];
        let mut v = input.to_vec();
        let last = v.len() - 1;
        v[last] ^= 0xff;
        assert_eq!(
            zlib_decompress(&v, BIG),
            Err(InflateError::ChecksumMismatch)
        );
    }

    #[test]
    fn adler32_matches_known_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"a"), 0x0062_0062);
        assert_eq!(adler32(b"abc"), 0x024d_0127);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    /// A raw stream handed to the zlib entry point (and vice versa) must fail
    /// rather than half-decode.
    #[test]
    fn wrappers_are_not_interchangeable() {
        let (_, raw_input, _) = raw_cases()[1]; // hello, raw deflate
        assert!(zlib_decompress(raw_input, BIG).is_err());
        let (_, zlib_input, _) = zlib_cases()[0];
        assert!(inflate(zlib_input, BIG).is_err());
    }

    #[test]
    fn over_subscribed_huffman_table_is_rejected() {
        // Three one-bit codes cannot coexist: the tree has room for two.
        assert_eq!(
            Huffman::new(&[1, 1, 1]).err(),
            Some(InflateError::Malformed)
        );
        // A length beyond the 15-bit maximum.
        assert_eq!(Huffman::new(&[16]).err(), Some(InflateError::Malformed));
        // A complete two-code table is fine.
        assert!(Huffman::new(&[1, 1]).is_ok());
        // So is an incomplete one.
        assert!(Huffman::new(&[1]).is_ok());
    }

    #[test]
    fn empty_input_is_truncated_not_empty_output() {
        assert_eq!(inflate(&[], BIG), Err(InflateError::Truncated));
    }

    // --- gzip (RFC 1952) ---------------------------------------------------

    macro_rules! gzip_vectors {
        ($($name:literal),* $(,)?) => {
            [$((
                $name,
                include_bytes!(concat!("../testdata/gzip/", $name, ".in")).as_slice(),
                include_bytes!(concat!("../testdata/gzip/", $name, ".out")).as_slice(),
            )),*]
        };
    }

    fn gzip_cases() -> [(&'static str, &'static [u8], &'static [u8]); 9] {
        gzip_vectors![
            "plain",
            "empty",
            "fname",
            "extra",
            "comment",
            "hcrc",
            "all_fields",
            "multiblock",
            // Not synthetic: the actual gzip'd cpio `Scripts` entry from a
            // pkgbuild-produced package.
            "real_scripts",
        ]
    }

    const GZIP_BOMB: &[u8] = include_bytes!("../testdata/gzip/bomb.in");

    #[test]
    fn decodes_gzip_vectors() {
        for (name, input, expected) in gzip_cases() {
            match gzip_decompress(input, BIG) {
                Ok(got) => assert_eq!(got, expected, "{name}: output mismatch"),
                Err(e) => panic!("{name}: expected success, got {e:?}"),
            }
        }
    }

    /// Each optional header field shifts where the deflate data starts.
    #[test]
    fn gzip_optional_fields_are_skipped_correctly() {
        for (name, input, expected) in gzip_cases() {
            if !matches!(name, "fname" | "extra" | "comment" | "hcrc" | "all_fields") {
                continue;
            }
            let got = gzip_decompress(input, BIG).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(got, expected, "{name}");
        }
    }

    #[test]
    fn gzip_budget_stops_a_bomb() {
        const FULL: usize = 8 * 1024 * 1024;
        assert_eq!(
            gzip_decompress(GZIP_BOMB, FULL - 1),
            Err(InflateError::BudgetExceeded)
        );
        let out = gzip_decompress(GZIP_BOMB, FULL).expect("exact budget should succeed");
        assert_eq!(out.len(), FULL);
    }

    #[test]
    fn gzip_header_is_validated() {
        assert_eq!(gzip_decompress(&[], BIG), Err(InflateError::Truncated));
        assert_eq!(gzip_decompress(&[0x1f], BIG), Err(InflateError::Truncated));
        // Wrong magic.
        assert_eq!(
            gzip_decompress(&[0x1f, 0x8c, 8, 0], BIG),
            Err(InflateError::BadHeader)
        );
        // Compression method other than deflate.
        assert_eq!(
            gzip_decompress(&[0x1f, 0x8b, 7, 0], BIG),
            Err(InflateError::BadHeader)
        );
        // Reserved flag bits set.
        assert_eq!(
            gzip_decompress(&[0x1f, 0x8b, 8, 0x20], BIG),
            Err(InflateError::BadHeader)
        );
        // FNAME set but never terminated: must not scan past the buffer.
        let mut v = vec![0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 3];
        v.extend_from_slice(b"unterminated-name");
        assert_eq!(gzip_decompress(&v, BIG), Err(InflateError::Truncated));
    }

    #[test]
    fn gzip_trailer_is_verified() {
        let (_, input, _) = gzip_cases()[0]; // plain
                                             // Corrupt the CRC-32.
        let mut v = input.to_vec();
        let n = v.len();
        v[n - 8] ^= 0xff;
        assert_eq!(
            gzip_decompress(&v, BIG),
            Err(InflateError::ChecksumMismatch)
        );
        // Corrupt ISIZE, leaving the CRC intact.
        let mut v = input.to_vec();
        v[n - 4] ^= 0xff;
        assert_eq!(
            gzip_decompress(&v, BIG),
            Err(InflateError::ChecksumMismatch)
        );
        // A truncated trailer is truncation, not corruption.
        assert_eq!(
            gzip_decompress(&input[..n - 3], BIG),
            Err(InflateError::Truncated)
        );
    }

    #[test]
    fn gzip_prefixes_fail_cleanly() {
        for (name, input, expected) in gzip_cases() {
            for n in probe_offsets(input.len()) {
                match gzip_decompress(&input[..n], BIG) {
                    Err(_) => {}
                    Ok(got) => assert_eq!(got, expected, "{name}: short prefix decoded"),
                }
            }
        }
    }

    #[test]
    fn gzip_bit_flips_do_not_panic() {
        for (_, input, _) in gzip_cases() {
            for byte in probe_offsets(input.len()) {
                for bit in 0..8 {
                    let mut v = input.to_vec();
                    if let Some(b) = v.get_mut(byte) {
                        *b ^= 1 << bit;
                    }
                    let _ = gzip_decompress(&v, FLIP_BUDGET);
                }
            }
        }
    }

    /// The three wrappers must not accept each other's streams.
    #[test]
    fn gzip_is_not_confused_with_zlib_or_raw() {
        let (_, gz, _) = gzip_cases()[0];
        assert!(zlib_decompress(gz, BIG).is_err());
        assert!(inflate(gz, BIG).is_err());
        let (_, zl, _) = zlib_cases()[0];
        assert_eq!(gzip_decompress(zl, BIG), Err(InflateError::BadHeader));
    }

    #[test]
    fn crc32_matches_known_values() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"abc"), 0x3524_41C2);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
