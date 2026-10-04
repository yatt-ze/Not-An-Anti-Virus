//! Bounded bzip2 decoder. Needed to read `.pkg` heap entries (notably the
//! `Distribution` file of packages built with the "Packages" tool) that xar
//! stores as bzip2 (§3, §5.2, §6.2).
//!
//! Hand-written per §3 (no third-party code on the parse path). Contract:
//! never panics, every table index is bounds-checked or bounded by a format
//! constant, working memory is bounded by the format's own maxima (one
//! block of at most 900 000 `u32`s), and the output `budget` is checked
//! *before* every write — including inside an RLE1 repeat — so a bomb is
//! refused rather than materialized. [`DecodeError::BudgetExceeded`] is a
//! §6.2 policy stop, not evidence of malice.
//!
//! Deliberate non-feature: only the first stream is decoded; bytes after
//! its trailer are ignored, as libxar does.

use crate::decode::DecodeError;

/// Starting output capacity; the buffer grows toward `budget` as bytes are
/// produced, so a large budget is not allocated up front.
const INITIAL_OUTPUT_CAPACITY: usize = 64 * 1024;

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_MAGIC: u64 = 0x1772_4538_5090;

/// Longest Huffman code the format permits.
const MAX_CODE_LEN: usize = 20;
/// RUNA, RUNB, up to 255 MTF values, end-of-block.
const MAX_ALPHA: usize = 258;
/// libbz2's `BZ2_rNums`: the obsolete block randomisation schedule.
const RNUMS: [u16; 512] = [
    619, 720, 127, 481, 931, 816, 813, 233, 566, 247, 985, 724, 205, 454, 863, 491, 741, 242, 949,
    214, 733, 859, 335, 708, 621, 574, 73, 654, 730, 472, 419, 436, 278, 496, 867, 210, 399, 680,
    480, 51, 878, 465, 811, 169, 869, 675, 611, 697, 867, 561, 862, 687, 507, 283, 482, 129, 807,
    591, 733, 623, 150, 238, 59, 379, 684, 877, 625, 169, 643, 105, 170, 607, 520, 932, 727, 476,
    693, 425, 174, 647, 73, 122, 335, 530, 442, 853, 695, 249, 445, 515, 909, 545, 703, 919, 874,
    474, 882, 500, 594, 612, 641, 801, 220, 162, 819, 984, 589, 513, 495, 799, 161, 604, 958, 533,
    221, 400, 386, 867, 600, 782, 382, 596, 414, 171, 516, 375, 682, 485, 911, 276, 98, 553, 163,
    354, 666, 933, 424, 341, 533, 870, 227, 730, 475, 186, 263, 647, 537, 686, 600, 224, 469, 68,
    770, 919, 190, 373, 294, 822, 808, 206, 184, 943, 795, 384, 383, 461, 404, 758, 839, 887, 715,
    67, 618, 276, 204, 918, 873, 777, 604, 560, 951, 160, 578, 722, 79, 804, 96, 409, 713, 940,
    652, 934, 970, 447, 318, 353, 859, 672, 112, 785, 645, 863, 803, 350, 139, 93, 354, 99, 820,
    908, 609, 772, 154, 274, 580, 184, 79, 626, 630, 742, 653, 282, 762, 623, 680, 81, 927, 626,
    789, 125, 411, 521, 938, 300, 821, 78, 343, 175, 128, 250, 170, 774, 972, 275, 999, 639, 495,
    78, 352, 126, 857, 956, 358, 619, 580, 124, 737, 594, 701, 612, 669, 112, 134, 694, 363, 992,
    809, 743, 168, 974, 944, 375, 748, 52, 600, 747, 642, 182, 862, 81, 344, 805, 988, 739, 511,
    655, 814, 334, 249, 515, 897, 955, 664, 981, 649, 113, 974, 459, 893, 228, 433, 837, 553, 268,
    926, 240, 102, 654, 459, 51, 686, 754, 806, 760, 493, 403, 415, 394, 687, 700, 946, 670, 656,
    610, 738, 392, 760, 799, 887, 653, 978, 321, 576, 617, 626, 502, 894, 679, 243, 440, 680, 879,
    194, 572, 640, 724, 926, 56, 204, 700, 707, 151, 457, 449, 797, 195, 791, 558, 945, 679, 297,
    59, 87, 824, 713, 663, 412, 693, 342, 606, 134, 108, 571, 364, 631, 212, 174, 643, 304, 329,
    343, 97, 430, 751, 497, 314, 983, 374, 822, 928, 140, 206, 73, 263, 980, 736, 876, 478, 430,
    305, 170, 514, 364, 692, 829, 82, 855, 953, 676, 246, 369, 970, 294, 750, 807, 827, 150, 790,
    288, 923, 804, 378, 215, 828, 592, 281, 565, 555, 710, 82, 896, 831, 547, 261, 524, 462, 293,
    465, 502, 56, 661, 821, 976, 991, 658, 869, 905, 758, 745, 193, 768, 550, 608, 933, 378, 286,
    215, 979, 792, 961, 61, 688, 793, 644, 986, 403, 106, 366, 905, 644, 372, 567, 466, 434, 645,
    210, 389, 550, 919, 135, 780, 773, 635, 389, 707, 100, 626, 958, 165, 504, 920, 176, 193, 713,
    857, 265, 203, 50, 668, 108, 645, 990, 626, 197, 510, 357, 358, 850, 858, 364, 936, 638,
];

/// Selectors beyond this many are read and discarded (libbz2 1.0.8 does too).
const MAX_SELECTORS: usize = 18002;
/// Symbols decoded per Huffman group before the next selector applies.
const GROUP_SIZE: u32 = 50;
/// Run-length weight at which RUNA/RUNB accumulation is refused.
const MAX_RUN_WEIGHT: usize = 2 * 1024 * 1024;

/// `BZh` plus a block-size digit 1-9: a bzip2 stream header.
pub(crate) fn has_bzip2_magic(data: &[u8]) -> bool {
    matches!(data, [b'B', b'Z', b'h', b'1'..=b'9', ..])
}

/// Decode one bzip2 stream, producing at most `budget` bytes. Bytes after
/// the first stream are ignored, as libxar does.
pub fn bzip2_decompress(data: &[u8], budget: usize) -> Result<Vec<u8>, DecodeError> {
    let (out, result) = bzip2_decompress_partial(data, budget);
    result.map(|()| out)
}

/// Like [`bzip2_decompress`], but on error also returns every byte written
/// before the failure (at most `budget`). Bytes after the last verified
/// block are unverified: they may be a prefix of the failing block, or all of
/// a block whose CRC mismatched. A bad header yields an empty `Vec`.
pub fn bzip2_decompress_partial(data: &[u8], budget: usize) -> (Vec<u8>, Result<(), DecodeError>) {
    let mut out = Vec::with_capacity(budget.min(INITIAL_OUTPUT_CAPACITY));
    let result = decode_stream(data, budget, &mut out);
    (out, result)
}

/// Decode the stream into `out`. On error `out` holds whatever was written.
fn decode_stream(data: &[u8], budget: usize, out: &mut Vec<u8>) -> Result<(), DecodeError> {
    let mut r = BitReader::new(data);
    for expected in *b"BZh" {
        if r.bits(8)? != u32::from(expected) {
            return Err(DecodeError::BadHeader);
        }
    }
    let level = r.bits(8)?;
    if !(u32::from(b'1')..=u32::from(b'9')).contains(&level) {
        return Err(DecodeError::BadHeader);
    }
    let max_block = (level - u32::from(b'0')) as usize * 100_000;

    let mut tt: Vec<u32> = Vec::new();
    let mut combined: u32 = 0;

    loop {
        let magic = (u64::from(r.bits(24)?) << 24) | u64::from(r.bits(24)?);
        match magic {
            BLOCK_MAGIC => {
                let crc = decode_block(&mut r, max_block, &mut tt, out, budget)?;
                combined = combined.rotate_left(1) ^ crc;
            }
            END_MAGIC => {
                if r.bits(32)? != combined {
                    return Err(DecodeError::ChecksumMismatch);
                }
                return Ok(());
            }
            _ => return Err(DecodeError::Malformed),
        }
    }
}

/// Decode one block (after its magic), appending to `out`. Returns the
/// block CRC, already verified against the decoded bytes.
fn decode_block(
    r: &mut BitReader,
    max_block: usize,
    tt: &mut Vec<u32>,
    out: &mut Vec<u8>,
    budget: usize,
) -> Result<u32, DecodeError> {
    let stored_crc = r.bits(32)?;
    // Obsolete, but libbz2 (hence Installer) still decodes it.
    let randomised = r.bits(1)? == 1;
    let orig_ptr = r.bits(24)? as usize;

    // Symbol map: which byte values occur, in increasing order.
    let mut seq_to_unseq = [0u8; 256];
    let mut n_in_use = 0usize;
    let ranges = r.bits(16)?;
    for i in 0..16u32 {
        if (ranges >> (15 - i)) & 1 == 0 {
            continue;
        }
        let used = r.bits(16)?;
        for j in 0..16u32 {
            if (used >> (15 - j)) & 1 == 1 {
                // At most 256 values are in use, so the slot lookup cannot miss.
                if let Some(slot) = seq_to_unseq.get_mut(n_in_use) {
                    *slot = (i * 16 + j) as u8;
                }
                n_in_use += 1;
            }
        }
    }
    if n_in_use == 0 {
        return Err(DecodeError::Malformed);
    }
    let alpha = n_in_use + 2;
    let eob = (n_in_use + 1) as u16;

    let n_groups = r.bits(3)? as usize;
    if !(2..=6).contains(&n_groups) {
        return Err(DecodeError::Malformed);
    }
    let n_selectors = r.bits(15)? as usize;
    if n_selectors == 0 {
        return Err(DecodeError::Malformed);
    }

    // Selectors: unary-coded MTF indices. Every bit read must exist, so the
    // loop is bounded by the input.
    let mut selectors: Vec<u8> = Vec::with_capacity(n_selectors.min(MAX_SELECTORS));
    let mut order = [0u8, 1, 2, 3, 4, 5];
    for i in 0..n_selectors {
        let mut j = 0usize;
        while r.bits(1)? == 1 {
            j += 1;
            if j >= n_groups {
                return Err(DecodeError::Malformed);
            }
        }
        if i < MAX_SELECTORS {
            let sel = *order.get(j).ok_or(DecodeError::Malformed)?;
            order.copy_within(0..j, 1);
            if let Some(front) = order.first_mut() {
                *front = sel;
            }
            selectors.push(sel);
        }
    }

    // Delta-coded code lengths, one set per group.
    let mut tables: Vec<Huffman> = Vec::with_capacity(n_groups);
    for _ in 0..n_groups {
        let mut lengths = [0u8; MAX_ALPHA];
        let mut curr = r.bits(5)?;
        for slot in lengths.iter_mut().take(alpha) {
            loop {
                if !(1..=MAX_CODE_LEN as u32).contains(&curr) {
                    return Err(DecodeError::Malformed);
                }
                if r.bits(1)? == 0 {
                    break;
                }
                if r.bits(1)? == 0 {
                    curr += 1;
                } else {
                    curr -= 1;
                }
            }
            *slot = curr as u8;
        }
        tables.push(Huffman::new(
            lengths.get(..alpha).ok_or(DecodeError::Malformed)?,
        )?);
    }

    // MTF + RUNA/RUNB decode into the pre-BWT array. Every iteration
    // consumes at least one input bit.
    tt.clear();
    let mut counts = [0u32; 256];
    let mut mtf = seq_to_unseq;
    let mut next_selector = 0usize;
    let mut left_in_group = 0u32;
    let mut table: Option<&Huffman> = None;
    let mut run = 0usize;
    let mut weight = 1usize;
    loop {
        if left_in_group == 0 {
            let sel = *selectors.get(next_selector).ok_or(DecodeError::Malformed)?;
            next_selector += 1;
            table = Some(tables.get(sel as usize).ok_or(DecodeError::Malformed)?);
            left_in_group = GROUP_SIZE;
        }
        left_in_group -= 1;
        let sym = table.ok_or(DecodeError::Malformed)?.decode(r)?;

        if sym <= 1 {
            if weight >= MAX_RUN_WEIGHT {
                return Err(DecodeError::Malformed);
            }
            run += (sym as usize + 1) * weight;
            weight <<= 1;
            // A run longer than a block can never be flushed.
            if run > max_block {
                return Err(DecodeError::Malformed);
            }
            continue;
        }

        if run > 0 {
            if tt.len() + run > max_block {
                return Err(DecodeError::Malformed);
            }
            let byte = mtf[0];
            counts[byte as usize] += run as u32;
            tt.resize(tt.len() + run, u32::from(byte));
            run = 0;
        }
        weight = 1;

        if sym == eob {
            break;
        }
        if tt.len() >= max_block {
            return Err(DecodeError::Malformed);
        }
        // `sym` is in 2..=n_in_use here, so the MTF index is below n_in_use.
        let idx = sym as usize - 1;
        let byte = *mtf.get(idx).ok_or(DecodeError::Malformed)?;
        mtf.copy_within(0..idx, 1);
        mtf[0] = byte;
        counts[byte as usize] += 1;
        tt.push(u32::from(byte));
    }

    // libbz2 also rejects an empty block: `origPtr >= nblock` holds for 0.
    let n = tt.len();
    if orig_ptr >= n {
        return Err(DecodeError::Malformed);
    }

    // Inverse BWT: link each position to its successor in the high 24 bits.
    // Counts sum to `n`, so every `cftab` slot used is below `n`.
    let mut cftab = [0usize; 257];
    for i in 0..256 {
        cftab[i + 1] = cftab[i] + counts[i] as usize;
    }
    for i in 0..n {
        let byte = (*tt.get(i).ok_or(DecodeError::Malformed)? & 0xff) as usize;
        let dst = cftab[byte];
        cftab[byte] += 1;
        *tt.get_mut(dst).ok_or(DecodeError::Malformed)? |= (i as u32) << 8;
    }

    // Walk the permutation and undo the initial run-length encoding: four
    // equal bytes are followed by a count of further repeats.
    let start = out.len();
    let mut t_pos = (*tt.get(orig_ptr).ok_or(DecodeError::Malformed)? >> 8) as usize;
    let mut last = 0u8;
    let mut same = 0u8;
    let mut rand_to_go = 0u16;
    let mut rand_pos = 0usize;
    for _ in 0..n {
        let entry = *tt.get(t_pos).ok_or(DecodeError::Malformed)?;
        let mut ch = (entry & 0xff) as u8;
        if randomised {
            // Applies to every walked byte, including RLE1 count bytes.
            if rand_to_go == 0 {
                rand_to_go = *RNUMS.get(rand_pos).ok_or(DecodeError::Malformed)?;
                rand_pos = (rand_pos + 1) % RNUMS.len();
            }
            rand_to_go -= 1;
            ch ^= u8::from(rand_to_go == 1);
        }
        t_pos = (entry >> 8) as usize;

        if same == 4 {
            put_run(out, last, ch as usize, budget)?;
            same = 0;
            continue;
        }
        if same > 0 && ch == last {
            same += 1;
        } else {
            last = ch;
            same = 1;
        }
        put_byte(out, ch, budget)?;
    }
    // A block never ends between four equal bytes and their count.
    if same == 4 {
        return Err(DecodeError::Malformed);
    }

    if crc32_msb(out.get(start..).ok_or(DecodeError::Malformed)?) != stored_crc {
        return Err(DecodeError::ChecksumMismatch);
    }
    Ok(stored_crc)
}

/// Append one byte, refusing to pass `budget`.
fn put_byte(out: &mut Vec<u8>, byte: u8, budget: usize) -> Result<(), DecodeError> {
    if out.len() >= budget {
        return Err(DecodeError::BudgetExceeded);
    }
    reserve(out, 1, budget);
    out.push(byte);
    Ok(())
}

/// Append `n` copies of `byte`. Writes only what fits under `budget` and
/// returns `BudgetExceeded` if that is fewer than `n`.
fn put_run(out: &mut Vec<u8>, byte: u8, n: usize, budget: usize) -> Result<(), DecodeError> {
    let room = budget.saturating_sub(out.len());
    let take = n.min(room);
    reserve(out, take, budget);
    out.resize(out.len() + take, byte);
    if take < n {
        return Err(DecodeError::BudgetExceeded);
    }
    Ok(())
}

/// Make room for `n` more bytes, doubling but never past `budget`.
/// Precondition: `out.len() + n <= budget`.
fn reserve(out: &mut Vec<u8>, n: usize, budget: usize) {
    let len = out.len();
    if out.capacity() - len >= n {
        return;
    }
    let grow = len
        .max(INITIAL_OUTPUT_CAPACITY)
        .max(n)
        .min(budget.saturating_sub(len));
    out.reserve_exact(grow);
}

/// Canonical Huffman decoder in libbz2's `limit`/`base`/`perm` form.
/// Incomplete and over-subscribed length sets are accepted as libbz2 does;
/// a code that matches no length is `Malformed`.
struct Huffman {
    min_len: u32,
    alpha: usize,
    limit: [i64; MAX_CODE_LEN + 3],
    base: [i64; MAX_CODE_LEN + 3],
    perm: [u16; MAX_ALPHA],
}

impl Huffman {
    /// `lengths` holds one code length per symbol, each in `1..=20`.
    fn new(lengths: &[u8]) -> Result<Self, DecodeError> {
        if lengths.is_empty() || lengths.len() > MAX_ALPHA {
            return Err(DecodeError::Malformed);
        }
        if lengths
            .iter()
            .any(|&l| !(1..=MAX_CODE_LEN as u8).contains(&l))
        {
            return Err(DecodeError::Malformed);
        }
        let min_len = lengths.iter().copied().min().unwrap_or(1) as usize;
        let max_len = lengths.iter().copied().max().unwrap_or(1) as usize;

        let mut perm = [0u16; MAX_ALPHA];
        let mut pp = 0usize;
        for len in min_len..=max_len {
            for (sym, &l) in lengths.iter().enumerate() {
                if l as usize == len {
                    perm[pp] = sym as u16;
                    pp += 1;
                }
            }
        }

        let mut base = [0i64; MAX_CODE_LEN + 3];
        for &l in lengths {
            base[l as usize + 1] += 1;
        }
        for i in 1..base.len() {
            base[i] += base[i - 1];
        }

        let mut limit = [0i64; MAX_CODE_LEN + 3];
        let mut vec = 0i64;
        for i in min_len..=max_len {
            vec += base[i + 1] - base[i];
            limit[i] = vec - 1;
            vec <<= 1;
        }
        for i in min_len + 1..=max_len {
            base[i] = ((limit[i - 1] + 1) << 1) - base[i];
        }

        Ok(Huffman {
            min_len: min_len as u32,
            alpha: lengths.len(),
            limit,
            base,
            perm,
        })
    }

    /// Decode one symbol, reading at most 20 bits.
    fn decode(&self, r: &mut BitReader) -> Result<u16, DecodeError> {
        let mut n = self.min_len as usize;
        let mut v = i64::from(r.bits(self.min_len)?);
        loop {
            if n > MAX_CODE_LEN {
                return Err(DecodeError::Malformed);
            }
            if v <= self.limit[n] {
                break;
            }
            n += 1;
            v = (v << 1) | i64::from(r.bits(1)?);
        }
        let idx = v - self.base[n];
        if idx < 0 || idx >= self.alpha as i64 {
            return Err(DecodeError::Malformed);
        }
        self.perm
            .get(idx as usize)
            .copied()
            .ok_or(DecodeError::Malformed)
    }
}

/// MSB-first bit reader. Running out of input is `Truncated` — never a
/// panic, never a silent zero-fill.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Low `cnt` bits are unread; higher bits are stale.
    buf: u64,
    /// Valid bits in `buf`; below 40.
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

    /// Read `n` bits (`n <= 32`) as an unsigned value.
    fn bits(&mut self, n: u32) -> Result<u32, DecodeError> {
        if n > 32 {
            return Err(DecodeError::Malformed);
        }
        while self.cnt < n {
            let b = *self.data.get(self.pos).ok_or(DecodeError::Truncated)?;
            self.pos += 1;
            self.buf = (self.buf << 8) | u64::from(b);
            self.cnt += 8;
        }
        self.cnt -= n;
        Ok(((self.buf >> self.cnt) & ((1u64 << n) - 1)) as u32)
    }
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ 0x04C1_1DB7
            } else {
                c << 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// bzip2's CRC-32: MSB-first (non-reflected), polynomial 0x04C11DB7, not
/// the gzip CRC.
fn crc32_msb(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = (crc << 8) ^ CRC_TABLE[usize::from((crc >> 24) as u8 ^ b)];
    }
    !crc
}

/// Test helper: `stream` without its end-of-stream trailer (end magic, CRC
/// and padding), keeping every block bit. Panics if no trailer is found.
#[cfg(test)]
pub(crate) fn cut_trailer(stream: &[u8]) -> &[u8] {
    let total_bits = stream.len() * 8;
    for pad in 0..8 {
        let end_off = total_bits - 80 - pad;
        let mut v = 0u64;
        for bit in end_off..end_off + 48 {
            v = (v << 1) | u64::from((stream[bit / 8] >> (7 - bit % 8)) & 1);
        }
        if v == END_MAGIC {
            return &stream[..end_off.div_ceil(8)];
        }
    }
    panic!("no end-of-stream trailer");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Generous ceiling for the ordinary vectors; the budget is tested separately.
    const BIG: usize = 4 << 20;
    /// Low ceiling for the corruption sweeps, which only look for panics.
    const FLIP_BUDGET: usize = 4096;

    /// Vectors generated from CPython's bz2 (real libbz2). See
    /// `testdata/bzip2/` and its generator.
    macro_rules! vec_in {
        ($name:literal) => {
            include_bytes!(concat!("../testdata/bzip2/", $name, ".in")).as_slice()
        };
    }
    macro_rules! vec_out {
        ($name:literal) => {
            include_bytes!(concat!("../testdata/bzip2/", $name, ".out")).as_slice()
        };
    }
    macro_rules! pairs {
        ($($name:literal),* $(,)?) => {
            [$(($name, vec_in!($name), vec_out!($name))),*]
        };
    }

    fn cases() -> Vec<(&'static str, &'static [u8], &'static [u8])> {
        pairs![
            "empty",
            "one_byte",
            "hello",
            "text",
            "all_bytes",
            "run_4",
            "run_5",
            "run_259",
            "run_260",
            "run_1000",
            "run_4_then_other",
            "run_255_plus_4",
            "zeros_64k",
            "multi_block",
            "run_cross_block",
            "groups_2",
            "groups_6",
        ]
        .to_vec()
    }

    const HELLO: &[u8] = vec_in!("hello");
    const BOMB: &[u8] = vec_in!("bomb");
    const FNV_WRAP: u64 = 0xf32c80ae10acbaa7;

    #[test]
    fn decodes_reference_vectors() {
        for (name, input, expected) in cases() {
            match bzip2_decompress(input, BIG) {
                Ok(got) => assert!(got == expected, "{name}: output mismatch"),
                Err(e) => panic!("{name}: expected success, got {e:?}"),
            }
        }
    }

    #[test]
    fn decodes_every_block_size_level() {
        macro_rules! levels {
            ($($n:literal),*) => { [$(include_bytes!(concat!("../testdata/bzip2/level_", $n, ".in")).as_slice()),*] };
        }
        let expected = vec_out!("text");
        for (i, input) in levels!("1", "2", "3", "4", "5", "6", "7", "8", "9")
            .iter()
            .enumerate()
        {
            let got = bzip2_decompress(input, BIG).unwrap();
            assert!(got == expected, "level {}: output mismatch", i + 1);
        }
    }

    #[test]
    fn magic_helper() {
        assert!(has_bzip2_magic(b"BZh1"));
        assert!(has_bzip2_magic(b"BZh9rest"));
        assert!(!has_bzip2_magic(b"BZh0"));
        assert!(!has_bzip2_magic(b"BZh:"));
        assert!(!has_bzip2_magic(b"BZh"));
        assert!(!has_bzip2_magic(b"bZh1"));
    }

    #[test]
    fn crc_matches_known_value() {
        // bzip2's CRC of "123456789" (CRC-32/BZIP2 check value).
        assert_eq!(crc32_msb(b"123456789"), 0xFC89_1918);
        assert_eq!(crc32_msb(b""), 0);
    }

    // ----- budget -----

    #[test]
    fn budget_exactly_the_output_is_ok_and_one_less_is_not() {
        for (name, input, expected) in cases() {
            let got = bzip2_decompress(input, expected.len())
                .unwrap_or_else(|e| panic!("{name}: exact budget failed: {e:?}"));
            assert!(got == expected, "{name}: output mismatch");
            // The output buffer never grows past the budget.
            assert!(got.capacity() <= expected.len().max(INITIAL_OUTPUT_CAPACITY));
            if !expected.is_empty() {
                assert_eq!(
                    bzip2_decompress(input, expected.len() - 1),
                    Err(DecodeError::BudgetExceeded),
                    "{name}: budget-1"
                );
            }
        }
    }

    #[test]
    fn zero_budget_only_admits_the_empty_stream() {
        assert_eq!(bzip2_decompress(vec_in!("empty"), 0), Ok(Vec::new()));
        assert_eq!(bzip2_decompress(HELLO, 0), Err(DecodeError::BudgetExceeded));
    }

    #[test]
    fn budget_is_enforced_inside_an_rle1_repeat() {
        // 1000 identical bytes are a handful of RLE1 groups; stop mid-group.
        let input = vec_in!("run_1000");
        for budget in [1, 4, 5, 100, 259, 260, 999] {
            assert_eq!(
                bzip2_decompress(input, budget),
                Err(DecodeError::BudgetExceeded),
                "budget {budget}"
            );
        }
    }

    #[test]
    fn bomb_is_refused_without_materializing() {
        // 512 MiB of zeros from a few hundred bytes. Output is only ever
        // grown to `len + n <= budget`, and every write is budget-checked
        // first, so at most 1 MiB is held when the error is returned.
        let t = Instant::now();
        assert_eq!(
            bzip2_decompress(BOMB, 1 << 20),
            Err(DecodeError::BudgetExceeded)
        );
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn huge_budget_does_not_preallocate() {
        // `with_capacity(usize::MAX)` would abort; this must just decode.
        assert_eq!(bzip2_decompress(HELLO, usize::MAX), Ok(b"hello".to_vec()));
    }

    // ----- trailing data -----

    #[test]
    fn bytes_after_the_stream_are_ignored() {
        let mut junk = HELLO.to_vec();
        junk.extend_from_slice(b"\xde\xad\xbe\xef junk");
        assert_eq!(bzip2_decompress(&junk, BIG), Ok(b"hello".to_vec()));
    }

    #[test]
    fn second_concatenated_stream_is_ignored() {
        let mut two = HELLO.to_vec();
        two.extend_from_slice(vec_in!("one_byte"));
        assert_eq!(bzip2_decompress(&two, BIG), Ok(b"hello".to_vec()));
    }

    // ----- truncation and corruption sweeps -----

    #[test]
    fn every_prefix_is_truncated() {
        for end in 0..HELLO.len() {
            assert_eq!(
                bzip2_decompress(&HELLO[..end], BIG),
                Err(DecodeError::Truncated),
                "prefix of {end} bytes"
            );
        }
        let big = vec_in!("groups_6");
        for end in (0..big.len()).step_by(37) {
            assert_eq!(
                bzip2_decompress(&big[..end], BIG),
                Err(DecodeError::Truncated),
                "groups_6 prefix of {end} bytes"
            );
        }
    }

    #[test]
    fn every_single_bit_flip_never_panics_or_lies() {
        for (name, input) in [("hello", HELLO), ("groups_2", vec_in!("groups_2"))] {
            let expected = if name == "hello" {
                b"hello".to_vec()
            } else {
                vec_out!("groups_2").to_vec()
            };
            for byte in 0..input.len() {
                for bit in 0..8 {
                    let mut m = input.to_vec();
                    m[byte] ^= 1 << bit;
                    if let Ok(out) = bzip2_decompress(&m, FLIP_BUDGET) {
                        assert_eq!(out, expected, "{name}: flip {byte}:{bit} gave wrong Ok");
                    }
                }
            }
        }
    }

    #[test]
    fn flips_in_a_large_block_never_panic() {
        let input = vec_in!("groups_6");
        for byte in (0..input.len()).step_by(11) {
            let mut m = input.to_vec();
            m[byte] ^= 0x10;
            let _ = bzip2_decompress(&m, FLIP_BUDGET);
        }
    }

    // ----- header and checksums -----

    #[test]
    fn bad_header_is_rejected() {
        assert_eq!(bzip2_decompress(b"", BIG), Err(DecodeError::Truncated));
        assert_eq!(bzip2_decompress(b"BZ", BIG), Err(DecodeError::Truncated));
        assert_eq!(bzip2_decompress(b"BZh", BIG), Err(DecodeError::Truncated));
        assert_eq!(bzip2_decompress(b"XZh9", BIG), Err(DecodeError::BadHeader));
        assert_eq!(bzip2_decompress(b"BZx9", BIG), Err(DecodeError::BadHeader));
        let mut zero = HELLO.to_vec();
        zero[3] = b'0';
        assert_eq!(bzip2_decompress(&zero, BIG), Err(DecodeError::BadHeader));
        zero[3] = b':';
        assert_eq!(bzip2_decompress(&zero, BIG), Err(DecodeError::BadHeader));
    }

    #[test]
    fn bad_block_magic_is_malformed() {
        let mut m = HELLO.to_vec();
        m[4] ^= 0x01;
        assert_eq!(bzip2_decompress(&m, BIG), Err(DecodeError::Malformed));
    }

    #[test]
    fn bad_block_crc_and_stream_crc() {
        // hello.in: header(4) magic(6) block_crc(4) ... end magic(6) crc(4)+pad.
        let mut m = HELLO.to_vec();
        m[10] ^= 0x80;
        assert_eq!(
            bzip2_decompress(&m, BIG),
            Err(DecodeError::ChecksumMismatch)
        );

        // The second-to-last byte lies wholly inside the stream CRC.
        let mut m = HELLO.to_vec();
        m[HELLO.len() - 2] ^= 0x01;
        assert_eq!(
            bzip2_decompress(&m, BIG),
            Err(DecodeError::ChecksumMismatch)
        );
    }

    // ----- hand-built streams -----

    /// MSB-first bit writer for building hostile streams.
    #[derive(Default)]
    struct BitWriter {
        bytes: Vec<u8>,
        nbits: usize,
    }
    impl BitWriter {
        fn put(&mut self, value: u64, n: u32) {
            for i in (0..n).rev() {
                if self.nbits % 8 == 0 {
                    self.bytes.push(0);
                }
                let bit = ((value >> i) & 1) as u8;
                let last = self.bytes.len() - 1;
                self.bytes[last] |= bit << (7 - self.nbits % 8);
                self.nbits += 1;
            }
        }
    }

    /// Everything a block header and body can say, so each field can be
    /// broken independently. The default is a valid block decoding to "aaa".
    #[derive(Clone)]
    struct Spec {
        crc: u32,
        randomised: bool,
        orig_ptr: u32,
        used: Vec<u8>,
        n_groups: u32,
        n_selectors: u32,
        /// Written as raw unary values (not MTF-encoded).
        selectors: Vec<u32>,
        /// Target code length per symbol, per group.
        lens: Vec<Vec<u32>>,
        /// First group's 5-bit start length; defaults to its first target.
        start_len: Option<u32>,
        /// Pre-encoded symbols as (code, bit count).
        body: Vec<(u64, u32)>,
        /// Stop writing once the selectors are out.
        stop_after_selectors: bool,
    }

    impl Spec {
        fn aaa() -> Spec {
            Spec {
                crc: crc32_msb(b"aaa"),
                randomised: false,
                orig_ptr: 0,
                used: vec![b'a'],
                n_groups: 2,
                n_selectors: 1,
                selectors: vec![0],
                lens: vec![vec![1, 2, 2]; 2],
                start_len: None,
                // RUNA RUNA EOB: run of 1 + 2 = 3.
                body: vec![(0b0, 1), (0b0, 1), (0b11, 2)],
                stop_after_selectors: false,
            }
        }

        /// Two used bytes, uniform 2-bit codes (symbol i has code i).
        fn ab() -> Spec {
            Spec {
                used: vec![b'a', b'b'],
                lens: vec![vec![2, 2, 2, 2]; 2],
                body: vec![(0b11, 2)],
                ..Spec::aaa()
            }
        }

        fn write(&self, w: &mut BitWriter) {
            w.put(BLOCK_MAGIC, 48);
            w.put(u64::from(self.crc), 32);
            w.put(u64::from(self.randomised), 1);
            w.put(u64::from(self.orig_ptr), 24);

            let mut ranges = 0u64;
            for &b in &self.used {
                ranges |= 1 << (15 - b / 16);
            }
            w.put(ranges, 16);
            for r in 0..16u8 {
                if ranges >> (15 - r) & 1 == 1 {
                    let mut m = 0u64;
                    for &b in self.used.iter().filter(|&&b| b / 16 == r) {
                        m |= 1 << (15 - b % 16);
                    }
                    w.put(m, 16);
                }
            }

            w.put(u64::from(self.n_groups), 3);
            w.put(u64::from(self.n_selectors), 15);
            for &s in &self.selectors {
                for _ in 0..s {
                    w.put(1, 1);
                }
                w.put(0, 1);
            }
            if self.stop_after_selectors {
                return;
            }
            for (g, lens) in self.lens.iter().enumerate() {
                let mut curr = match (g, self.start_len) {
                    (0, Some(s)) => s,
                    _ => lens[0],
                };
                w.put(u64::from(curr), 5);
                for &target in lens {
                    while curr < target {
                        w.put(0b10, 2);
                        curr += 1;
                    }
                    while curr > target {
                        w.put(0b11, 2);
                        curr -= 1;
                    }
                    w.put(0, 1);
                }
            }
            for &(code, n) in &self.body {
                w.put(code, n);
            }
        }
    }

    /// `BZh<level>` + blocks + end-of-stream with the given stream CRC.
    fn stream(level: u8, blocks: &[Spec], stream_crc: u32) -> Vec<u8> {
        let mut w = BitWriter::default();
        for b in [b'B', b'Z', b'h', level] {
            w.put(u64::from(b), 8);
        }
        for b in blocks {
            b.write(&mut w);
        }
        w.put(END_MAGIC, 48);
        w.put(u64::from(stream_crc), 32);
        w.bytes
    }

    fn one(spec: Spec) -> Vec<u8> {
        let crc = spec.crc;
        stream(b'1', &[spec], crc)
    }

    fn decode(spec: Spec) -> Result<Vec<u8>, DecodeError> {
        bzip2_decompress(&one(spec), BIG)
    }

    #[test]
    fn hand_built_baseline_decodes() {
        assert_eq!(decode(Spec::aaa()), Ok(b"aaa".to_vec()));
    }

    /// Guards the builder itself: `/usr/bin/bzip2` must accept every valid
    /// hand-built baseline and print the same bytes. Skipped only when the
    /// tool is absent. The stream goes in on stdin, so nothing touches disk.
    #[test]
    fn hand_built_streams_are_accepted_by_the_real_tool() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let a = Spec::aaa();
        let two_crc = a.crc.rotate_left(1) ^ a.crc;
        let cases = [
            ("aaa", one(Spec::aaa()), b"aaa".to_vec()),
            (
                "two blocks",
                stream(b'1', &[a.clone(), a.clone()], two_crc),
                b"aaaaaa".to_vec(),
            ),
            ("no blocks", stream(b'9', &[], 0), Vec::new()),
        ];
        for (name, input, expected) in cases {
            let child = Command::new("/usr/bin/bzip2")
                .arg("-dc")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();
            // Any spawn failure means no usable reference tool here: skip.
            let Ok(mut child) = child else { return };
            let mut stdin = child.stdin.take().expect("piped stdin");
            let writer = std::thread::spawn({
                let input = input.clone();
                move || stdin.write_all(&input)
            });
            let out = child.wait_with_output().expect("bzip2 runs");
            // A write error (EPIPE if bzip2 exited early) shows up in the
            // status and output checks below.
            let _ = writer.join().expect("writer");
            assert!(
                out.status.success(),
                "{name}: bzip2 rejected it: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            // Ours must agree with the reference on what these decode to.
            let ours = bzip2_decompress(&input, BIG).expect("our decode");
            assert_eq!(out.stdout, ours, "{name}: differs from bzip2");
            if !expected.is_empty() {
                assert_eq!(ours, expected, "{name}");
            }
        }
    }

    #[test]
    fn randomised_blocks_decode_as_libbz2_does() {
        for (name, input, expected) in
            pairs!["randomised_small", "randomised_3k", "randomised_runs"]
        {
            assert!(
                bzip2_decompress(input, BIG).unwrap() == expected,
                "{name}: output mismatch"
            );
        }
    }

    /// 600 000 bytes, wraps the 512-entry schedule twice. The block CRC is
    /// verified by the decoder; the FNV-1a hash was computed from Python's
    /// `bz2` output (SHA-256 f1327e51...70e2 matched the reference).
    #[test]
    fn randomised_block_wrapping_the_schedule_decodes() {
        let out = bzip2_decompress(vec_in!("randomised_wrap"), BIG).unwrap();
        assert_eq!(out.len(), 600_000);
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for &b in &out {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        assert_eq!(h, FNV_WRAP);
    }

    #[test]
    fn randomisation_table_is_transcribed_correctly() {
        assert_eq!(RNUMS.len(), 512);
        assert_eq!((RNUMS[0], RNUMS[1], RNUMS[4]), (619, 720, 931));
        assert_eq!(RNUMS[511], 638);
        assert_eq!(RNUMS[509..].to_vec(), vec![364, 936, 638]);
        assert_eq!(RNUMS.iter().map(|&v| u32::from(v)).sum::<u32>(), 278_212);
    }

    #[test]
    fn orig_ptr_at_or_past_the_block_length_is_malformed() {
        for p in [3, 4, 0x00FF_FFFF] {
            let s = Spec {
                orig_ptr: p,
                ..Spec::aaa()
            };
            assert_eq!(decode(s), Err(DecodeError::Malformed), "origPtr {p}");
        }
    }

    #[test]
    fn empty_block_is_malformed() {
        // EOB straight away: nblock == 0, which libbz2 rejects too.
        let s = Spec {
            body: vec![(0b11, 2)],
            ..Spec::aaa()
        };
        assert_eq!(decode(s), Err(DecodeError::Malformed));
    }

    #[test]
    fn group_count_out_of_range_is_malformed() {
        for g in [0, 1, 7] {
            let s = Spec {
                n_groups: g,
                ..Spec::aaa()
            };
            assert_eq!(decode(s), Err(DecodeError::Malformed), "nGroups {g}");
        }
    }

    #[test]
    fn zero_selectors_is_malformed() {
        let s = Spec {
            n_selectors: 0,
            selectors: vec![],
            ..Spec::aaa()
        };
        assert_eq!(decode(s), Err(DecodeError::Malformed));
    }

    #[test]
    fn selector_value_at_or_past_group_count_is_malformed() {
        let s = Spec {
            selectors: vec![2],
            ..Spec::aaa()
        };
        assert_eq!(decode(s), Err(DecodeError::Malformed));
    }

    #[test]
    fn selectors_beyond_the_maximum_are_read_and_discarded() {
        let s = Spec {
            n_selectors: 18_010,
            selectors: vec![0; 18_010],
            ..Spec::aaa()
        };
        assert_eq!(decode(s), Ok(b"aaa".to_vec()));
    }

    #[test]
    fn selector_bits_missing_from_the_input_are_truncated() {
        let s = Spec {
            n_selectors: 32_767,
            selectors: vec![0; 10],
            stop_after_selectors: true,
            n_groups: 6,
            ..Spec::aaa()
        };
        // `stream` appends the end-of-stream magic and CRC; those bits are
        // read as more selectors, but 32 767 can never be satisfied. The CRC
        // is zero so it holds no run of ones long enough to fail first.
        assert_eq!(
            bzip2_decompress(&stream(b'1', &[s], 0), BIG),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn running_out_of_selectors_is_malformed() {
        // 51 symbols but one selector covers only 50.
        let mut body = vec![(0b10, 2); 51];
        body.push((0b11, 2));
        let s = Spec { body, ..Spec::ab() };
        assert_eq!(decode(s), Err(DecodeError::Malformed));
    }

    #[test]
    fn code_length_driven_out_of_range_is_malformed() {
        // To 0 (start at 1, step down) and to 21 (start at 20, step up).
        let to_zero = Spec {
            lens: vec![vec![1, 0, 2], vec![1, 2, 2]],
            ..Spec::aaa()
        };
        assert_eq!(decode(to_zero), Err(DecodeError::Malformed));
        let to_21 = Spec {
            lens: vec![vec![20, 21, 2], vec![1, 2, 2]],
            ..Spec::aaa()
        };
        assert_eq!(decode(to_21), Err(DecodeError::Malformed));
        let start_zero = Spec {
            start_len: Some(0),
            ..Spec::aaa()
        };
        assert_eq!(decode(start_zero), Err(DecodeError::Malformed));
        let start_21 = Spec {
            start_len: Some(21),
            ..Spec::aaa()
        };
        assert_eq!(decode(start_21), Err(DecodeError::Malformed));
    }

    #[test]
    fn incomplete_table_is_accepted_but_an_undecodable_code_is_malformed() {
        // Lengths 2,2,2 leave code 11 unassigned. As libbz2 does, accept the
        // table; only decoding the unassigned code fails.
        let ok = Spec {
            lens: vec![vec![2, 2, 2]; 2],
            body: vec![(0b00, 2), (0b00, 2), (0b10, 2)],
            ..Spec::aaa()
        };
        assert_eq!(decode(ok), Ok(b"aaa".to_vec()));

        let mut body = vec![(0b00, 2), (0b11, 2)];
        body.extend(std::iter::repeat((1, 1)).take(40));
        let bad = Spec {
            lens: vec![vec![2, 2, 2]; 2],
            body,
            ..Spec::aaa()
        };
        assert_eq!(decode(bad), Err(DecodeError::Malformed));
    }

    #[test]
    fn oversubscribed_table_is_accepted_but_never_misdecodes() {
        // Lengths 1,1,2 are over-subscribed; libbz2 accepts them and the
        // third symbol is simply unreachable. Here that means EOB cannot be
        // coded, so the trailing end-of-stream bits are read as run symbols
        // until the run overflows the block.
        let s = Spec {
            lens: vec![vec![1, 1, 2]; 2],
            body: vec![(0b0, 1), (0b0, 1)],
            ..Spec::aaa()
        };
        assert_eq!(decode(s), Err(DecodeError::Malformed));
    }

    #[test]
    fn run_longer_than_the_block_is_malformed() {
        // Only RUNB: the run doubles each symbol. 31 and 63 symbols would be
        // runs near 2^31 and 2^63; the decoder must refuse as soon as the
        // run passes the block size, long before any allocation.
        for n in [20usize, 31, 63, 200] {
            let s = Spec {
                lens: vec![vec![1, 2, 2]; 2],
                body: vec![(0b10, 2); n],
                ..Spec::aaa()
            };
            assert_eq!(decode(s), Err(DecodeError::Malformed), "{n} RUNBs");
        }
    }

    #[test]
    fn more_symbols_than_the_block_size_is_malformed() {
        // Level 1: 100 000 bytes per block. 100 001 MTF symbols overflow it.
        let n = 100_001usize;
        let selectors = n.div_ceil(50) + 1;
        let mut body = vec![(0b10, 2); n];
        body.push((0b11, 2));
        let s = Spec {
            n_selectors: selectors as u32,
            selectors: vec![0; selectors],
            body,
            ..Spec::ab()
        };
        assert_eq!(decode(s), Err(DecodeError::Malformed));
    }

    #[test]
    fn exactly_the_block_size_is_not_an_overflow() {
        // 100 000 symbols fit a level-1 block; only the CRC is wrong here.
        let n = 100_000usize;
        let selectors = n.div_ceil(50) + 1;
        let mut body = vec![(0b10, 2); n];
        body.push((0b11, 2));
        let s = Spec {
            n_selectors: selectors as u32,
            selectors: vec![0; selectors],
            body,
            ..Spec::ab()
        };
        assert_eq!(decode(s), Err(DecodeError::ChecksumMismatch));
    }

    #[test]
    fn symbol_map_with_no_used_bytes_is_malformed() {
        let s = Spec {
            used: vec![],
            ..Spec::aaa()
        };
        assert_eq!(decode(s), Err(DecodeError::Malformed));
    }

    #[test]
    fn block_ending_between_four_equal_bytes_and_their_count_is_malformed() {
        // Run of 4 'a' with no count byte.
        let s = Spec {
            crc: crc32_msb(b"aaaa"),
            // RUNB RUNA... = 2 + 2 = 4 ('a' x4)
            body: vec![(0b10, 2), (0b0, 1), (0b11, 2)],
            ..Spec::aaa()
        };
        assert_eq!(decode(s), Err(DecodeError::Malformed));
    }

    #[test]
    fn block_and_stream_crc_checks_are_independent() {
        let spec = Spec::aaa();
        assert_eq!(
            bzip2_decompress(
                &stream(b'1', std::slice::from_ref(&spec), spec.crc ^ 1),
                BIG
            ),
            Err(DecodeError::ChecksumMismatch)
        );
        let bad_block = Spec {
            crc: spec.crc ^ 1,
            ..spec.clone()
        };
        assert_eq!(
            bzip2_decompress(
                &stream(b'1', std::slice::from_ref(&bad_block), bad_block.crc),
                BIG
            ),
            Err(DecodeError::ChecksumMismatch)
        );
    }

    #[test]
    fn multiple_hand_built_blocks_combine_their_crcs() {
        let a = Spec::aaa();
        let combined = a.crc.rotate_left(1) ^ a.crc;
        assert_eq!(
            bzip2_decompress(&stream(b'1', &[a.clone(), a.clone()], combined), BIG),
            Ok(b"aaaaaa".to_vec())
        );
        assert_eq!(
            bzip2_decompress(&stream(b'1', &[a.clone(), a.clone()], a.crc), BIG),
            Err(DecodeError::ChecksumMismatch)
        );
    }

    #[test]
    fn stream_with_no_blocks_is_empty() {
        assert_eq!(bzip2_decompress(&stream(b'9', &[], 0), BIG), Ok(Vec::new()));
        assert_eq!(
            bzip2_decompress(&stream(b'9', &[], 1), BIG),
            Err(DecodeError::ChecksumMismatch)
        );
    }

    // ----- partial decode -----

    /// Bit offsets at which the 48-bit `magic` occurs.
    fn find_magic(data: &[u8], magic: u64) -> Vec<usize> {
        let mut found = Vec::new();
        let mut window = 0u64;
        for bit in 0..data.len() * 8 {
            window = ((window << 1) | u64::from((data[bit / 8] >> (7 - bit % 8)) & 1))
                & 0xFFFF_FFFF_FFFF;
            if bit >= 47 && window == magic {
                found.push(bit - 47);
            }
        }
        found
    }

    #[test]
    fn partial_decode_keeps_everything_written_before_the_failure() {
        let input = vec_in!("multi_block");
        let expected = vec_out!("multi_block");
        let starts = find_magic(input, BLOCK_MAGIC);
        assert_eq!(starts.len(), 3, "three blocks");

        // Intact: everything, Ok.
        let (all, r) = bzip2_decompress_partial(input, BIG);
        assert_eq!(r, Ok(()));
        assert!(all == expected);

        // Trailer cut: all blocks, Truncated.
        let cut = cut_trailer(input);
        let (got, r) = bzip2_decompress_partial(cut, BIG);
        assert_eq!(r, Err(DecodeError::Truncated));
        assert!(got == expected);
        assert_eq!(bzip2_decompress(cut, BIG), Err(DecodeError::Truncated));

        // Cut inside a block's bitstream: it never reaches the output stage,
        // so only the verified blocks before it are returned.
        let (b1, r) = bzip2_decompress_partial(&input[..starts[1] / 8 + 100], BIG);
        assert_eq!(r, Err(DecodeError::Truncated));
        assert!(!b1.is_empty() && b1.len() < 100_000);
        assert!(b1[..] == expected[..b1.len()]);
        let (b12, r) = bzip2_decompress_partial(&input[..starts[2] / 8 + 100], BIG);
        assert_eq!(r, Err(DecodeError::Truncated));
        assert!(b12.len() > b1.len() && b12[..] == expected[..b12.len()]);
        assert_eq!(
            bzip2_decompress(&input[..starts[1] / 8 + 100], BIG),
            Err(DecodeError::Truncated)
        );

        // Bad CRC in block 2 (first bit of its stored CRC): the whole of
        // block 2 is returned, unverified.
        let mut bad = input.to_vec();
        let crc_bit = starts[1] + 48;
        bad[crc_bit / 8] ^= 0x80 >> (crc_bit % 8);
        let (got, r) = bzip2_decompress_partial(&bad, BIG);
        assert_eq!(r, Err(DecodeError::ChecksumMismatch));
        assert!(got == b12);
        assert_eq!(
            bzip2_decompress(&bad, BIG),
            Err(DecodeError::ChecksumMismatch)
        );

        // Budget hit inside block 2: exactly `budget` bytes.
        let budget = b1.len() + 10;
        let (got, r) = bzip2_decompress_partial(input, budget);
        assert_eq!(r, Err(DecodeError::BudgetExceeded));
        assert_eq!(got.len(), budget);
        assert!(got[..] == expected[..budget]);
        assert_eq!(
            bzip2_decompress(input, budget),
            Err(DecodeError::BudgetExceeded)
        );
    }

    /// A block whose CRC is wrong and whose trailer is missing: libxar never
    /// reaches the CRC check, so the block's bytes are the evidence.
    #[test]
    fn partial_decode_returns_a_block_with_a_wrong_crc() {
        let full = vec_in!("distribution_dropper");
        let mut bad = cut_trailer(full).to_vec();
        bad[10] ^= 0x01;
        let (got, r) = bzip2_decompress_partial(&bad, BIG);
        assert_eq!(r, Err(DecodeError::ChecksumMismatch));
        assert!(got == vec_out!("distribution_dropper"));
        assert_eq!(
            bzip2_decompress(&bad, BIG),
            Err(DecodeError::ChecksumMismatch)
        );
    }

    /// A tiny stream that exceeds the budget inside its only block: the
    /// in-budget prefix (which holds the dropper) is returned.
    #[test]
    fn partial_decode_returns_the_in_budget_prefix_of_a_big_block() {
        let input = vec_in!("distribution_big");
        let budget = 4 << 20;
        let (got, r) = bzip2_decompress_partial(input, budget);
        assert_eq!(r, Err(DecodeError::BudgetExceeded));
        assert_eq!(got.len(), budget);
        assert!(got.starts_with(vec_out!("distribution_dropper")));
        assert!(got.capacity() <= budget);
        assert_eq!(
            bzip2_decompress(input, budget),
            Err(DecodeError::BudgetExceeded)
        );
    }

    /// Valid CRCs, no trailer: every decoded byte comes back, junk tail included.
    #[test]
    fn partial_decode_returns_a_trailerless_stream_whole() {
        let full = vec_in!("distribution_junk_tail");
        let (got, r) = bzip2_decompress_partial(cut_trailer(full), BIG);
        assert_eq!(r, Err(DecodeError::Truncated));
        assert!(got == vec_out!("distribution_junk_tail"));
    }

    #[test]
    fn partial_decode_of_a_bad_header_is_empty() {
        let (got, r) = bzip2_decompress_partial(b"XZh9 rest", BIG);
        assert!(got.is_empty());
        assert_eq!(r, Err(DecodeError::BadHeader));
    }
}
