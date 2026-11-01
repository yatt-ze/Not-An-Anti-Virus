#![no_main]
//! libFuzzer target for `nav_core::zip::read` (§11.9/§12). Property: no
//! panic, no OOB read, terminates; no member is longer than the member cap;
//! a member handed on cut short comes with a gap; and the members' bytes
//! stay within the read budget (decoded output is charged to it).
//!
//! Run from `crates/nav-core/` (needs nightly + cargo-fuzz):
//!   cargo +nightly fuzz run parse_zip
//!
//! Seed from `testdata/zip/` (both views disagreeing in each way the
//! differential tests cover) and the fixture zips.

use libfuzzer_sys::fuzz_target;
use nav_core::zip::{self, Member, ZipLimits};

fuzz_target!(|data: &[u8]| {
    let limits = ZipLimits {
        max_entries: 256,
        max_depth: 3,
        max_member_bytes: 64 * 1024,
        max_read_back_bytes: 1 << 20,
        max_ratio: 300,
    };
    let mut total = 0usize;
    let mut cut = 0usize;
    let result = zip::read(data, &limits, &mut |m: &Member| {
        assert!(
            m.bytes.len() <= limits.max_member_bytes,
            "member of {} bytes against a cap of {}",
            m.bytes.len(),
            limits.max_member_bytes
        );
        assert!(!m.bytes.is_empty(), "an empty member was handed on");
        total += m.bytes.len();
        cut += usize::from(m.cut);
    });
    assert!(
        total <= limits.max_read_back_bytes,
        "members total {total} bytes against a budget of {}",
        limits.max_read_back_bytes
    );
    assert!(cut == 0 || !result.gaps.is_empty(), "a cut member with no gap");
});
