#![no_main]
//! libFuzzer target for `nav_core::xar::parse` (§11.9/§12) — the deepest
//! attacker-controlled path in the crate (header → zlib → XML → compressed
//! heap entries).
//!
//! Beyond no-panic/no-OOB/terminates, asserts: the §6.2 ceilings hold on what
//! comes back (entry count, depth); `ReadBudget::read_entry_partial` and
//! `read_entry_nested` respect the entry cap, never charge more than the
//! entry's allowance (outer and nested layers together) or grow the archive
//! budget, and charge at least the bytes they return; a nested zlib read
//! leaves the nested layer at least a third of the allowance; the
//! un-budgeted `read_entry_partial` respects `max_entry_bytes` and a gap
//! carries bytes; a complete archive is not also halted.
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
        // Room for a level-9 bzip2 block (900,000 bytes) in a half-allowance.
        max_read_back_bytes: 16 * 1024 * 1024,
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

    let mut budget = xar::ReadBudget::new(&limits);

    for (i, f) in archive.files.iter().enumerate() {
        assert!(
            f.depth <= limits.max_depth,
            "entry {:?} at depth {} exceeds the §6.2 recursion ceiling of {}",
            f.path,
            f.depth,
            limits.max_depth
        );

        // read_entry_partial(_nested) is where a hostile container turns a few TOC
        // bytes into an allocation. Output must fit the entry cap and the
        // total work the archive budget; failing is fine.
        let allowance = budget.remaining() / (archive.files.len() - i);
        budget.start_entry(archive.files.len() - i);
        let cap = budget.entry_cap();
        let before = budget.remaining();
        // (bytes, gap, other bytes returned)
        let result = if i % 2 == 0 {
            budget
                .read_entry_partial(data, &archive, f)
                .map(|(bytes, gap)| (bytes, gap, 0))
        } else {
            // A zlib entry is the one a nested read splits in three.
            let zlib = matches!(
                (
                    xar::entry_allowance(data, &archive, f, true),
                    xar::entry_allowance(data, &archive, f, false),
                ),
                (Ok(three), Ok(two)) if three > two
            );
            let mut outer = budget.clone();
            let _ = outer.read_entry_partial_nested(data, &archive, f);
            if zlib {
                assert!(
                    outer.entry_cap() >= (allowance / 3).min(limits.max_entry_bytes),
                    "entry {:?}: the outer read left the nested layer {} of a {}-byte allowance",
                    f.path,
                    outer.entry_cap(),
                    allowance
                );
            }
            budget
                .read_entry_nested(data, &archive, f)
                .map(|e| (e.bytes, e.gap, e.unread.len() + e.later.len()))
        };
        assert!(budget.remaining() <= before, "the budget grew");
        assert!(
            before - budget.remaining() <= allowance,
            "entry {:?} was charged more than its {}-byte allowance",
            f.path,
            allowance
        );
        if let Ok((bytes, gap, other)) = result {
            assert!(
                before - budget.remaining() >= bytes.len() + other,
                "entry {:?}: returned bytes were not charged",
                f.path
            );
            assert!(
                bytes.len() <= cap && cap <= limits.max_entry_bytes,
                "entry {:?} produced {} bytes against a {}-byte cap",
                f.path,
                bytes.len(),
                cap
            );
            // A nested gzip can fail having consumed all its input.
            assert!(
                gap.is_none() || !bytes.is_empty() || i % 2 == 1,
                "entry {:?}: a partial read must carry bytes",
                f.path
            );
        }
    }

    for f in archive.files.iter().take(4) {
        if let Ok((bytes, gap)) = xar::read_entry_partial(data, &archive, f, &limits) {
            assert!(
                bytes.len() <= limits.max_entry_bytes,
                "entry {:?} produced {} bytes against a {}-byte limit",
                f.path,
                bytes.len(),
                limits.max_entry_bytes
            );
            assert!(
                gap.is_none() || !bytes.is_empty(),
                "entry {:?}: a partial read must carry bytes",
                f.path
            );
        }
    }

    if archive.is_complete() {
        assert!(archive.halted.is_none());
    }
});
