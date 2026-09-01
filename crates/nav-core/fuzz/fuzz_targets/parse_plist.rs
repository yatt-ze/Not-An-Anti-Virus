#![no_main]
//! libFuzzer target for `nav_core::plist::parse` (§11.9/§12). Property: for
//! any input, no panic, no OOB read, terminates — and anything returned
//! respects the reader's structural ceilings.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run parse_plist
//!
//! Seed with real XML/`bplist00` plists plus the unit tests' malformed cases,
//! and the two amplification shapes explicitly (a run of bare `&`s; a
//! `bplist00` whose arrays share one child by reference) — neither reachable
//! by mutation, both found by review rather than by an 800k-run session.

use libfuzzer_sys::fuzz_target;
use nav_core::plist::PlistValue;

// Sanity ceilings, well above the reader's own limits (MAX_DEPTH = 32,
// MAX_NODES = 100_000, MAX_TOTAL_BYTES = 16 MiB).
const DEPTH_CEILING: usize = 64;
const NODE_CEILING: usize = 250_000;
const BYTE_CEILING: usize = 32 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let Some(root) = nav_core::plist::parse(data) else {
        return;
    };

    // Iterative walk — a buggy over-deep tree must not overflow the checker's
    // own stack before the assert fires.
    let mut stack: Vec<(&PlistValue, usize)> = vec![(&root, 1)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;

    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        assert!(depth <= DEPTH_CEILING, "plist tree deeper than {DEPTH_CEILING}");
        assert!(nodes <= NODE_CEILING, "plist tree larger than {NODE_CEILING} nodes");
        // Node count alone doesn't bound memory — shared references let a
        // small file decode to a much larger tree. Charge the payload too.
        assert!(
            bytes <= BYTE_CEILING,
            "plist tree holds more than {BYTE_CEILING} bytes"
        );

        match value {
            PlistValue::String(s) => bytes += s.len(),
            PlistValue::Data(d) => bytes += d.len(),
            PlistValue::Array(items) => {
                for item in items {
                    stack.push((item, depth + 1));
                }
            }
            PlistValue::Dict(entries) => {
                for (k, v) in entries {
                    bytes += k.len();
                    stack.push((v, depth + 1));
                }
            }
            _ => {}
        }
    }
});
