//! Error type shared by the bounded decompressors (`inflate`, `bzip2`).
//! `BudgetExceeded` is a §6.2 policy stop, not malformation.

/// Why a stream could not be decoded. `BudgetExceeded` is a §6.2 policy stop,
/// not malformation — keep it distinct (§10/§11.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended mid-stream.
    Truncated,
    /// Structurally invalid: a field, table or symbol the format forbids.
    Malformed,
    /// Output would exceed the caller's budget. Not a maliciousness finding (§6.2).
    BudgetExceeded,
    /// The stream's header or magic is invalid or unsupported.
    BadHeader,
    /// A stored checksum did not match the decoded bytes.
    ChecksumMismatch,
}
