//! [`ByteSource`]: offset-based access to file-like bytes, shared by every
//! parser that reads past the in-memory content prefix (§5.2, §11.7).

use std::borrow::Cow;

/// Uniform access to file-like bytes for offset-based parsing
/// ([`crate::macho::scan_ranged`]): shared by `[u8]` (a whole in-memory
/// buffer — tests, the fuzz target) and [`crate::context::ScanContext`] (reads through the
/// scan's own file handle past its in-memory prefix).
pub trait ByteSource {
    /// Total length of the underlying object.
    fn source_len(&self) -> u64;
    /// Leading bytes already resident in memory — readable at no I/O cost.
    /// `0` by default. `[u8]` overrides this to its whole length (it's all
    /// memory already); [`crate::context::ScanContext`] to `content`'s
    /// length. `macho::read_budgeted` only charges a read for the part of
    /// its range beyond this.
    fn held_len(&self) -> u64 {
        0
    }
    /// Whether [`Self::source_len`] is the object's true total size. `true`
    /// by default. `false` for a capture that stopped short of the real
    /// object's end (an embedded/container member extracted only up to a
    /// budget): an offset past `source_len` there may still land on real
    /// data this source just doesn't have — see `macho::scan_ranged_fat`.
    fn source_len_is_authoritative(&self) -> bool {
        true
    }
    /// Reads exactly `len` bytes starting at `off`, or `None` if the range
    /// doesn't fit or the read fails. Borrows straight from memory already
    /// held when the whole range lies inside it, rather than copying — a
    /// single slice's header/signature reads can number in the thousands on
    /// hostile input (§5.2).
    fn read_range(&self, off: u64, len: usize) -> Option<Cow<'_, [u8]>>;
}

impl ByteSource for [u8] {
    fn source_len(&self) -> u64 {
        self.len() as u64
    }

    fn held_len(&self) -> u64 {
        self.len() as u64
    }

    fn read_range(&self, off: u64, len: usize) -> Option<Cow<'_, [u8]>> {
        let start = usize::try_from(off).ok()?;
        let end = start.checked_add(len)?;
        self.get(start..end).map(Cow::Borrowed)
    }
}
