//! Shared temp-file helpers for tests that need bytes on a real file, not
//! just in-memory content — a range past `context::MAX_CONTENT_BYTES` only
//! reaches a rule through `ScanContext`'s file handle. Mirrors the
//! `macho::tests_support` pattern for non-Mach-O fixtures.

#![cfg(test)]

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// A path under the system temp dir, unique to this process and moment, for
/// `tag`.
fn unique_temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nav-test-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Write `body` to a fresh, uniquely-named temp file and return its path.
pub(crate) fn write_temp_file(tag: &str, body: &[u8]) -> PathBuf {
    let p = unique_temp_path(tag);
    std::fs::write(&p, body).unwrap();
    p
}

/// A zero-filled (sparse) temp file of exactly `total_len` bytes, for tests
/// that need a file bigger than `MAX_CONTENT_BYTES` without writing that
/// many bytes.
pub(crate) fn sparse_temp_file(tag: &str, total_len: u64) -> PathBuf {
    let p = unique_temp_path(tag);
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(total_len).unwrap();
    p
}

/// Overwrite `bytes` at `offset` within an existing file at `path`.
pub(crate) fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
    let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(bytes).unwrap();
}

/// Deterministic xorshift32 pseudo-random bytes (seed `0x1234_5678`), for
/// tests and fixture generation.
pub(crate) fn xorshift_bytes(len: usize) -> Vec<u8> {
    let mut state: u32 = 0x1234_5678;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state & 0xff) as u8
        })
        .collect()
}
