#![no_main]
//! libFuzzer target for `nav_core::macho::parse` and `scan_ranged` (§11.9/
//! §12, #45). Property: for any input, no panic, no OOB read, terminates.
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

    // Offset-based scan over the same bytes, treated as the whole "file" —
    // same no-panic/no-OOB property, and every located `__TEXT` range must
    // still be forward even after being shifted to an absolute offset.
    let scan = nav_core::macho::scan_ranged(data);
    for image in &scan.images {
        if let Some(range) = &image.text_range {
            assert!(range.start <= range.end);
        }
    }
});
