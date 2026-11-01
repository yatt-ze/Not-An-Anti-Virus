#![no_main]
//! libFuzzer target for `nav_core::inflate` (§11.9/§12). Property: for any
//! input, no panic, no OOB read, terminates (a compressed format makes the
//! last easy to get wrong — a back-reference loop hangs). Plus the §3
//! amplification rule — output never exceeds the budget, partial results
//! included. Output matches an independent decoder (flate2 over miniz_oxide)
//! on every input both accept, and the streaming `_to` forms hand a sink, run
//! by run, the bytes, result and consumed count the `Vec` forms return.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run inflate
//!
//! Seed deliberately (§3): the 840:1/1000:1 bomb vectors, a stored block
//! running past the buffer, an over-subscribed Huffman table, a max-distance
//! back-reference — none reachable by mutating a valid stream.

use libfuzzer_sys::fuzz_target;
use std::io::Read;

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
    for (name, (out, _)) in [
        ("zlib partial", nav_core::inflate::zlib_decompress_partial(data, BUDGET)),
        ("gzip partial", nav_core::inflate::gzip_decompress_partial(data, BUDGET)),
    ] {
        assert!(
            out.len() <= BUDGET,
            "{name} produced {} bytes against a {BUDGET}-byte budget",
            out.len()
        );
    }

    // Callers slice the unread rest at `consumed`.
    let (out, consumed, _) = nav_core::inflate::gzip_decompress_consumed(data, BUDGET);
    assert!(out.len() <= BUDGET, "gzip consumed exceeded the budget");
    assert!(
        consumed <= data.len(),
        "gzip consumed {consumed} of {} input bytes",
        data.len()
    );

    // An independent decoder agrees wherever both accept the input.
    let reference = |mut r: Box<dyn Read + '_>| {
        let mut out = Vec::new();
        r.by_ref()
            .take(BUDGET as u64 + 1)
            .read_to_end(&mut out)
            .ok()
            .filter(|_| out.len() <= BUDGET)
            .map(|_| out)
    };
    let pairs = [
        (
            "raw",
            nav_core::inflate::inflate(data, BUDGET).ok(),
            reference(Box::new(flate2::read::DeflateDecoder::new(data))),
        ),
        (
            "zlib",
            nav_core::inflate::zlib_decompress(data, BUDGET).ok(),
            reference(Box::new(flate2::read::ZlibDecoder::new(data))),
        ),
        (
            "gzip",
            nav_core::inflate::gzip_decompress(data, BUDGET).ok(),
            reference(Box::new(flate2::read::GzDecoder::new(data))),
        ),
    ];
    for (name, ours, theirs) in pairs {
        if let (Some(ours), Some(theirs)) = (ours, theirs) {
            assert!(ours == theirs, "{name}: output differs from flate2");
        }
    }

    // The streaming forms hand over exactly what the Vec forms return, and
    // never an empty run.
    for budget in [BUDGET, 1000] {
        let mut streamed = Vec::new();
        let r = nav_core::inflate::inflate_to(data, budget, &mut |b| {
            assert!(!b.is_empty(), "empty run");
            streamed.extend_from_slice(b)
        });
        match nav_core::inflate::inflate(data, budget) {
            Ok(out) => assert_eq!((out, Ok(())), (streamed, r), "raw stream differs"),
            Err(e) => assert_eq!(r, Err(e), "raw stream result differs"),
        }
        let mut streamed = Vec::new();
        let r = nav_core::inflate::zlib_decompress_to(data, budget, &mut |b| {
            streamed.extend_from_slice(b)
        });
        assert_eq!(
            nav_core::inflate::zlib_decompress_partial(data, budget),
            (streamed, r),
            "zlib stream differs"
        );
        let mut streamed = Vec::new();
        let (used, r) = nav_core::inflate::gzip_decompress_to(data, budget, &mut |b| {
            streamed.extend_from_slice(b)
        });
        assert_eq!(
            nav_core::inflate::gzip_decompress_consumed(data, budget),
            (streamed, used, r),
            "gzip stream differs"
        );
    }

    // A zero budget must never yield output — the clamp-to-budget boundary.
    for r in [
        nav_core::inflate::inflate(data, 0),
        nav_core::inflate::zlib_decompress(data, 0),
        nav_core::inflate::gzip_decompress(data, 0),
    ] {
        if let Ok(out) = r {
            assert!(out.is_empty(), "produced output under a zero budget");
        }
    }
    for (out, _) in [
        nav_core::inflate::zlib_decompress_partial(data, 0),
        nav_core::inflate::gzip_decompress_partial(data, 0),
    ] {
        assert!(out.is_empty(), "partial produced output under a zero budget");
    }
});
