#![no_main]
//! libFuzzer target for `nav_core::bzip2` (§11.9/§12). Property: for any
//! input, no panic, no OOB read, terminates, and (§3 amplification rule)
//! output never exceeds the budget; a zero budget never yields output; the
//! partial API agrees with the strict one.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run bzip2
//!
//! Seed from `testdata/bzip2/*.in` plus hostile streams: a huge RUNA/RUNB
//! run, more than 18002 selectors, a 6-group block, the 512 MiB bomb —
//! none reachable by mutating a valid stream. Each input is also tried with
//! a `BZh9` header prepended so mutations reach the block parser quickly.

use libfuzzer_sys::fuzz_target;

/// Small, so a violation is obvious and the fuzzer stays on decode paths.
const BUDGET: usize = 1 << 20;

fn check(data: &[u8]) {
    let strict = nav_core::bzip2::bzip2_decompress(data, BUDGET);
    if let Ok(out) = &strict {
        assert!(
            out.len() <= BUDGET,
            "bzip2 produced {} bytes against a {BUDGET}-byte budget",
            out.len()
        );
    }
    let (kept, result) = nav_core::bzip2::bzip2_decompress_partial(data, BUDGET);
    assert!(kept.len() <= BUDGET, "partial output over budget");
    match strict {
        Ok(v) => assert!(
            result == Ok(()) && kept == v,
            "partial disagrees on success"
        ),
        Err(e) => assert!(result == Err(e), "partial disagrees on error"),
    }
    // A zero budget must never yield output — the "check before the write" boundary.
    if let Ok(out) = nav_core::bzip2::bzip2_decompress(data, 0) {
        assert!(out.is_empty(), "produced output under a zero budget");
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    let mut with_header = Vec::with_capacity(data.len() + 4);
    with_header.extend_from_slice(b"BZh9");
    with_header.extend_from_slice(data);
    check(&with_header);
});
