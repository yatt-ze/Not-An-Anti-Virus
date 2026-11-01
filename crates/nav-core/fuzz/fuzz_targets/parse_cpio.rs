#![no_main]
//! libFuzzer target for `nav_core::cpio::parse` (§11.9/§12). Property: no
//! panic, no OOB read, always terminates — the last matters because entry
//! strides come from the header (a zero-size entry loops). Also asserts the
//! reader's own ceilings, and that `CpioStream` fed the input in pieces walks
//! it exactly as `parse` does when no byte ceiling is in play.
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run parse_cpio
//!
//! Seed from `testdata/cpio/`: both formats, the real pkgbuild archive, the
//! adversarial set (huge namesize/filesize, truncation at each boundary,
//! missing trailer, non-numeric fields, many tiny entries).

use libfuzzer_sys::fuzz_target;
use nav_core::cpio::{self, CpioLimits, CpioStream, MemberEnd, StreamEnd, StreamLimits};

fuzz_target!(|data: &[u8]| {
    check_stream(data);
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

    // A cut-short member exists only on a truncation, and its data is the
    // input's tail.
    if let Some(cut) = &archive.cut_short {
        assert_eq!(archive.halted, Some(cpio::CpioHalt::Truncated));
        assert!(data.ends_with(cut.data), "cut-short data is not a suffix");
    }

    // Complete => reached the trailer, so not also halted (§10/§11.8).
    if archive.is_complete() {
        assert!(archive.halted.is_none());
    }
});

/// `CpioStream` over `data` in pieces sized by its first byte agrees with
/// `parse` with no byte ceiling.
fn check_stream(data: &[u8]) {
    let chunk = usize::from(data.first().copied().unwrap_or(1)).max(1);
    let max_entries = 64;
    let mut walk = CpioStream::new(StreamLimits {
        max_entries,
        max_member_bytes: usize::MAX,
    });
    let mut members = Vec::new();
    for piece in data.chunks(chunk) {
        members.extend(walk.push(piece));
    }
    let (last, end) = walk.finish();
    members.extend(last);

    let limits = CpioLimits {
        max_entries,
        max_total_bytes: usize::MAX,
    };
    let Some(archive) = cpio::parse(data, &limits) else {
        assert_eq!(
            end,
            StreamEnd::NotCpio {
                raw: data.to_vec(),
                more: false
            },
            "stream saw cpio"
        );
        assert!(members.is_empty());
        return;
    };
    assert_eq!(members.len(), archive.entries.len(), "member count differs");
    for (m, e) in members.iter().zip(&archive.entries) {
        assert_eq!(
            (&m.name, m.name_lossy, m.mode, m.data.as_slice(), m.end),
            (&e.name, e.name_lossy, e.mode, e.data, MemberEnd::Whole),
            "member differs"
        );
    }
    let StreamEnd::Archive { halted, cut_short } = end else {
        panic!("stream saw no cpio");
    };
    assert_eq!(halted, archive.halted, "halt differs");
    assert_eq!(
        cut_short.map(|m| (m.name, m.data, m.end)),
        archive
            .cut_short
            .map(|e| (e.name, e.data.to_vec(), MemberEnd::CutShort)),
        "cut-short member differs"
    );
}
