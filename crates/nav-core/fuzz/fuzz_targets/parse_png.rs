#![no_main]
//! libFuzzer target for `nav_core::png::compressed_ranges` (§5.2/§11.9, #320).
//! Property: for any input, no panic, terminates, and every returned range
//! is forward, in bounds and after the previous one.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run parse_png
//!
//! Seed with real PNGs, including ones with text metadata first.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(ranges) = nav_core::png::compressed_ranges(data) {
        assert!(data.starts_with(nav_core::png::SIGNATURE));
        let mut end = 0;
        for range in ranges {
            assert!(end <= range.start && range.start <= range.end);
            assert!(range.end <= data.len());
            end = range.end;
        }
    }
});
