#![no_main]
//! libFuzzer target for `nav_core::cpio::parse` (§11.9/§12). Property: no
//! panic, no OOB read, always terminates — the last matters because entry
//! strides come from the header (a zero-size entry loops). Also asserts the
//! reader's own ceilings.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run parse_cpio
//!
//! Seed from `testdata/cpio/`: both formats, the real pkgbuild archive, the
//! adversarial set (huge namesize/filesize, truncation at each boundary,
//! missing trailer, non-numeric fields, many tiny entries).

use libfuzzer_sys::fuzz_target;
use nav_core::cpio::{self, CpioLimits};

fuzz_target!(|data: &[u8]| {
    let limits = CpioLimits {
        max_entries: 64,
        max_total_bytes: 1 << 20,
    };
    let Some(archive) = cpio::parse(data, &limits) else {
        return;
    };

    assert!(
        archive.entries.len() <= limits.max_entries,
        "returned {} entries against a limit of {}",
        archive.entries.len(),
        limits.max_entries
    );

    let mut total = 0usize;
    for e in &archive.entries {
        // Entry data must be a real slice of the input, not synthesized.
        assert!(
            e.data.len() <= data.len(),
            "entry data longer than the whole archive"
        );
        total += e.data.len();
        assert!(
            total <= limits.max_total_bytes,
            "entries total {total} bytes against a limit of {}",
            limits.max_total_bytes
        );
    }

    // Complete => reached the trailer, so not also halted (§10/§11.8).
    if archive.is_complete() {
        assert!(archive.halted.is_none());
    }
});
