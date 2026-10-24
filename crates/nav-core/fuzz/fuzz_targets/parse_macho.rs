#![no_main]
//! libFuzzer target for `nav_core::macho::scan_ranged` (§11.9/§12, #45).
//! Property: for any input, no panic, no OOB read, terminates.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run parse_macho
//!
//! Seed with real thin/fat Mach-O plus the unit tests' malformed cases.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `data` is the whole "file". Every located `__TEXT` range is forward,
    // even after being shifted to an absolute offset.
    let scan = nav_core::macho::scan_ranged(data);
    for image in &scan.images {
        if let Some(range) = &image.text_range {
            assert!(range.start <= range.end);
        }
    }
});
