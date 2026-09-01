#![no_main]
//! libFuzzer target for `nav_core::inflate` (§11.9/§12). Property: for any
//! input, no panic, no OOB read, terminates (a compressed format makes the
//! last easy to get wrong — a back-reference loop hangs). Plus the §3
//! amplification rule — output never exceeds the budget.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run inflate
//!
//! Seed deliberately (§3): the 840:1/1000:1 bomb vectors, a stored block
//! running past the buffer, an over-subscribed Huffman table, a max-distance
//! back-reference — none reachable by mutating a valid stream.

use libfuzzer_sys::fuzz_target;

/// Small, so a violation is obvious and the fuzzer stays on decode paths.
const BUDGET: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    // Each entry point locates the payload differently; give each the same bytes.
    if let Ok(out) = nav_core::inflate::inflate(data, BUDGET) {
        assert!(
            out.len() <= BUDGET,
            "raw deflate produced {} bytes against a {BUDGET}-byte budget",
            out.len()
        );
    }
    if let Ok(out) = nav_core::inflate::zlib_decompress(data, BUDGET) {
        assert!(
            out.len() <= BUDGET,
            "zlib produced {} bytes against a {BUDGET}-byte budget",
            out.len()
        );
    }
    if let Ok(out) = nav_core::inflate::gzip_decompress(data, BUDGET) {
        assert!(
            out.len() <= BUDGET,
            "gzip produced {} bytes against a {BUDGET}-byte budget",
            out.len()
        );
    }

    // A zero budget must never yield output — the "check before the write" boundary.
    for r in [
        nav_core::inflate::inflate(data, 0),
        nav_core::inflate::zlib_decompress(data, 0),
        nav_core::inflate::gzip_decompress(data, 0),
    ] {
        if let Ok(out) = r {
            assert!(out.is_empty(), "produced output under a zero budget");
        }
    }
});
