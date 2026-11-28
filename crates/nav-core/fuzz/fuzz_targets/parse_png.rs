#![no_main]
//! libFuzzer target for `nav_core::png::compressed_ranges` (§5.2/§11.9, #320).
//! Property: for any input, no panic, terminates, and at most `MAX_CHUNKS`
//! ranges come back, each forward, in bounds and after the previous one.
//! Each input is also tried with its chunk CRCs rewritten, so mutations
//! reach the chunk-body checks instead of failing on the CRC.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run parse_png
//!
//! Seed from `testdata/png/` and the PNG fixtures.

use libfuzzer_sys::fuzz_target;
use nav_core::png::{compressed_ranges, MAX_CHUNKS, SIGNATURE};

fuzz_target!(|data: &[u8]| {
    check(data);
    check(&with_fixed_crcs(data));
});

fn check(data: &[u8]) {
    let Some(ranges) = compressed_ranges(data) else {
        return;
    };
    assert!(data.starts_with(SIGNATURE));
    assert!(ranges.len() <= MAX_CHUNKS);
    let mut end = 0;
    for range in ranges {
        assert!(end <= range.start && range.start <= range.end);
        assert!(range.end <= data.len());
        end = range.end;
    }
}

/// `data` with each chunk's CRC recomputed, walking lengths as the parser
/// does and stopping at the first chunk that cannot fit.
fn with_fixed_crcs(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut pos = 8usize;
    for _ in 0..=MAX_CHUNKS {
        let Some(len) = out.get(pos..pos + 4) else {
            break;
        };
        let len = u32::from_be_bytes(len.try_into().unwrap());
        if len > 0x7FFF_FFFF {
            break;
        }
        let body_end = pos + 8 + len as usize;
        if body_end + 4 > out.len() {
            break;
        }
        let mut crc = flate2::Crc::new();
        crc.update(&out[pos + 4..body_end]);
        out[body_end..body_end + 4].copy_from_slice(&crc.sum().to_be_bytes());
        pos = body_end + 4;
    }
    out
}
