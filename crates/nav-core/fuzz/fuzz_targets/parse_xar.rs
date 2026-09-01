#![no_main]
//! libFuzzer target for `nav_core::xar::parse` (§11.9/§12) — the deepest
//! attacker-controlled path in the crate (header → zlib → XML → compressed
//! heap entries).
//!
//! Beyond no-panic/no-OOB/terminates, asserts: the §6.2 ceilings hold on what
//! comes back (entry count, depth); `read_entry` respects its budget per
//! entry; a complete archive is not also halted.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run parse_xar
//!
//! Seed from `testdata/xar/` (real packages + adversarial set). Per §3, seed
//! the amplification shapes: a huge declared TOC, a tiny TOC expanding to
//! deep nesting, a tiny heap entry declaring megabytes.

use libfuzzer_sys::fuzz_target;
use nav_core::xar::{self, XarLimits};

fuzz_target!(|data: &[u8]| {
    // Tight ceilings: unambiguous violations, no budget wasted on big trees.
    let limits = XarLimits {
        max_toc_bytes: 1 << 20,
        max_entries: 128,
        max_depth: 4,
        max_entry_bytes: 256 * 1024,
    };

    let Some(archive) = xar::parse(data, &limits) else {
        return;
    };

    assert!(
        archive.files.len() <= limits.max_entries,
        "returned {} files against a limit of {}",
        archive.files.len(),
        limits.max_entries
    );

    for f in &archive.files {
        assert!(
            f.depth <= limits.max_depth,
            "entry {:?} at depth {} exceeds the §6.2 recursion ceiling of {}",
            f.path,
            f.depth,
            limits.max_depth
        );

        // read_entry is where a hostile container turns a few TOC bytes into
        // an allocation. Output must fit the budget; failing is fine.
        if let Ok(bytes) = xar::read_entry(data, &archive, f, &limits) {
            assert!(
                bytes.len() <= limits.max_entry_bytes,
                "entry {:?} produced {} bytes against a {}-byte budget",
                f.path,
                bytes.len(),
                limits.max_entry_bytes
            );
        }
    }

    if archive.is_complete() {
        assert!(archive.halted.is_none());
    }
});
