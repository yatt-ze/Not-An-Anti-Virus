//! Error type shared by the bounded decompressors (currently `inflate`).
//! `BudgetExceeded` is a §6.2 policy stop, not malformation.

/// Why a stream could not be decoded. `BudgetExceeded` is a §6.2 policy stop,
/// not malformation — keep it distinct (§10/§11.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended mid-stream.
    Truncated,
    /// Structurally invalid: bad block type, over-subscribed Huffman table,
    /// out-of-range symbol, or a back-reference before the start of output.
    Malformed,
    /// Output would exceed the caller's budget. Not a maliciousness finding (§6.2).
    BudgetExceeded,
    /// zlib/gzip header invalid, or it requests an unsupported preset dictionary.
    BadHeader,
    /// Adler-32 (zlib) or CRC-32/ISIZE (gzip) trailer did not match the output.
    ChecksumMismatch,
}
