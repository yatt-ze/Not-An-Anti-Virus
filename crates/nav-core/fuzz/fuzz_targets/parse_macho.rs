#![no_main]
//! libFuzzer target for `nav_core::macho::parse` (§11.9/§12). Property: for
//! any input, no panic, no OOB read, terminates.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run parse_macho
//!
//! Seed with real thin/fat Mach-O plus the unit tests' malformed cases.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(image) = nav_core::macho::parse(data) {
        // A located __TEXT range is forward. It's an absolute file range, so
        // it may extend past `data` (the caller clips) — not asserted here.
        if let Some(range) = image.text_range {
            assert!(range.start <= range.end);
        }
    }
});
