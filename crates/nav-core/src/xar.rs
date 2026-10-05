//! Bounded xar container parsing — the *metadata* of a macOS `.pkg` (structure,
//! signature, install-script contents). Payload inspection is out of scope,
//! deferred to §6.1/§6.2's explicit-command path.
//!
//! Layout: 28-byte BE header, then a zlib-compressed XML table of contents,
//! then the heap. The TOC is a *tree* — a nested `.pkg` is a
//! `<file type="directory">` with children — so it carries §6.2's depth ceiling.
//!
//! Two format quirks, both confirmed against real packages:
//! - A `<file>`'s `<name>` can appear *after* its children, so paths are
//!   resolved in a second pass once every node's name is known.
//! - The `encoding` attribute is unreliable: `application/x-gzip` entries are
//!   really zlib, and `Scripts` (`application/octet-stream`) is really gzip.
//!   [`read_entry`] dispatches on the leading bytes (gzip, zlib, bzip2).
//!
//! Hand-written per §3. XML goes through [`crate::xml`], shared with the plist
//! reader so there is only one XML implementation to fuzz.

use crate::decode::DecodeError;
use crate::inflate;
use crate::xml::{self, Event, Next, Scanner};

/// `xar!`, read big-endian.
const XAR_MAGIC: u32 = 0x7861_7221;
/// Size of the fixed header this parser understands.
const XAR_HEADER_LEN: usize = 28;
/// Sanity ceiling; real headers are exactly 28 bytes.
const MAX_HEADER_LEN: usize = 1024;
/// The only xar version this parser implements (every `.pkg` in the wild).
const SUPPORTED_VERSION: u16 = 1;

/// Ceilings applied while reading a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XarLimits {
    /// Maximum inflated TOC size.
    pub max_toc_bytes: usize,
    /// Maximum `<file>` nodes recorded.
    pub max_entries: usize,
    /// Maximum nesting depth of `<file>` elements — §6.2's recursion-depth
    /// limit, whose default is 4.
    pub max_depth: usize,
    /// Maximum decompressed size of any single heap entry read back.
    pub max_entry_bytes: usize,
    /// Maximum total of compressed bytes consumed plus decoded bytes produced
    /// reading entries back from the heap across one archive.
    pub max_read_back_bytes: usize,
}

impl Default for XarLimits {
    fn default() -> Self {
        XarLimits {
            max_toc_bytes: 8 * 1024 * 1024,
            max_entries: 10_000,
            max_depth: 4,
            max_entry_bytes: 4 * 1024 * 1024,
            max_read_back_bytes: 256 * 1024 * 1024,
        }
    }
}

/// The fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XarHeader {
    pub header_size: u16,
    pub version: u16,
    pub toc_len_compressed: u64,
    pub toc_len_uncompressed: u64,
    /// 0 none, 1 sha1, 2 md5, 3 sha256, 4 sha512.
    pub checksum_alg: u32,
}

/// What a TOC entry claims to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XarKind {
    File,
    Directory,
    /// Anything else the TOC named (symlink, fifo, …), kept verbatim.
    Other(String),
    /// No `<type>` element present.
    Unspecified,
}

/// One `<file>` node from the TOC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XarFile {
    /// `/`-joined path from this node and its ancestors. Never normalized.
    pub path: String,
    /// Final path component.
    pub name: String,
    /// Nesting depth; 0 for a top-level entry.
    pub depth: usize,
    pub kind: XarKind,
    /// `<encoding style>`, if present. Advisory only — see module docs.
    pub encoding: Option<String>,
    /// Offset of this entry's bytes within the heap.
    pub offset: Option<u64>,
    /// Stored (still-compressed) length in the heap.
    pub length: Option<u64>,
    /// Claimed size after decompression. A declaration, not a fact.
    pub size: Option<u64>,
}

impl XarFile {
    /// Whether Phase 0a may read this entry back. Excludes `Payload`, which has
    /// the same gzip+cpio shape as `Scripts` but is deferred by §6.1.
    pub fn is_metadata_entry(&self) -> bool {
        matches!(
            self.name.as_str(),
            "PackageInfo" | "Distribution" | "Scripts"
        )
    }
}

/// The TOC's own `<signature>` (a direct child of `<toc>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XarSignature {
    /// e.g. `RSA`, or `CMS` for a notarized package.
    pub style: String,
    pub offset: Option<u64>,
    pub size: Option<u64>,
}

/// Why a walk stopped early. A halt means the view is partial — the caller
/// degrades completeness rather than reporting a clean scan (§10, §11.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XarHalt {
    /// Header is self-inconsistent (e.g. claims to be smaller than 28 bytes).
    BadHeader,
    /// Declares a xar version this parser doesn't implement; parsing it as v1
    /// would risk silent overclaiming (§10/§11.8).
    UnsupportedVersion,
    /// The TOC's byte range lies outside the data we hold (lying header, or a
    /// bounded read that stopped short).
    TocOutOfRange,
    /// The TOC declares, or inflates to, more than `max_toc_bytes`. Not a
    /// maliciousness finding on its own (§6.2).
    TocTooLarge,
    /// The TOC is not a valid zlib stream.
    TocUndecodable,
    /// The TOC inflated but is not well-formed XML we can walk.
    TocMalformed,
    /// Hit `max_entries`.
    EntryLimit,
    /// Hit `max_depth` — §6.2's bounded recursion for nested containers.
    DepthLimit,
}

/// A parsed container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XarArchive {
    pub header: XarHeader,
    pub files: Vec<XarFile>,
    pub signature: Option<XarSignature>,
    /// `style` of the TOC's own `<checksum>` (`sha1`, `md5`, `sha256`, …).
    pub checksum_style: Option<String>,
    /// Absolute offset where the heap begins.
    pub heap_start: u64,
    pub halted: Option<XarHalt>,
}

impl XarArchive {
    pub fn is_complete(&self) -> bool {
        self.halted.is_none()
    }

    /// End of the recorded signature's heap range (absolute), or `None` if it
    /// lacks an `offset`, has no non-zero `size`, or the range overflows.
    pub fn signature_end(&self) -> Option<u64> {
        let sig = self.signature.as_ref()?;
        let (offset, size) = (sig.offset?, sig.size?);
        if size == 0 {
            return None;
        }
        self.heap_start.checked_add(offset)?.checked_add(size)
    }

    /// True when the root `<toc>`'s signature has an `offset` and a non-zero
    /// `size` whose heap range lies within `source_len`, the whole archive's
    /// length. Presence only: validity is not checked (§5.2).
    pub fn has_plausible_signature(&self, source_len: u64) -> bool {
        self.signature_end().is_some_and(|end| end <= source_len)
    }

    /// The entries Phase 0a is allowed to read back — see
    /// [`XarFile::is_metadata_entry`].
    pub fn metadata_entries(&self) -> impl Iterator<Item = &XarFile> {
        self.files.iter().filter(|f| f.is_metadata_entry())
    }
}

/// Why a heap entry could not be read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XarEntryError {
    /// The TOC gave no offset/length for this entry.
    NoHeapLocation,
    /// The entry's bytes lie outside the data we hold. A completeness problem,
    /// not corruption: with a bounded read a large installer's entry can just
    /// be past the end of what was read.
    OutOfRange,
    /// The entry's bytes are not a compression format we recognize.
    UnknownEncoding,
    /// Decompression failed or exceeded `max_entry_bytes`.
    Undecodable(DecodeError),
}

impl XarEntryError {
    /// The read stopped at a size or work limit.
    pub const BUDGET_EXCEEDED: XarEntryError =
        XarEntryError::Undecodable(DecodeError::BudgetExceeded);
}

/// True if `data` opens with the xar magic (`xar!`). [`parse`] uses this same
/// check to decide whether `data` is a package at all, so the two can't drift.
pub(crate) fn has_xar_magic(data: &[u8]) -> bool {
    be_u32(data, 0) == Some(XAR_MAGIC)
}

/// Parse a xar container's header and table of contents.
///
/// `None` only when `data` doesn't start with the xar magic (not a package).
/// Once the magic matches, every later failure yields an archive carrying a
/// [`XarHalt`] — the header and recovered entries are still evidence.
pub fn parse(data: &[u8], limits: &XarLimits) -> Option<XarArchive> {
    if !has_xar_magic(data) {
        return None;
    }

    let header = XarHeader {
        header_size: be_u16(data, 4)?,
        version: be_u16(data, 6)?,
        toc_len_compressed: be_u64(data, 8)?,
        toc_len_uncompressed: be_u64(data, 16)?,
        checksum_alg: be_u32(data, 24)?,
    };

    // From here on, never return `None` — that would report a damaged package
    // as "not a package".
    let mut archive = XarArchive {
        header,
        files: Vec::new(),
        signature: None,
        checksum_style: None,
        heap_start: 0,
        halted: None,
    };

    let header_size = header.header_size as usize;
    if !(XAR_HEADER_LEN..=MAX_HEADER_LEN).contains(&header_size) {
        archive.halted = Some(XarHalt::BadHeader);
        return Some(archive);
    }
    if header.version != SUPPORTED_VERSION {
        archive.halted = Some(XarHalt::UnsupportedVersion);
        return Some(archive);
    }

    let toc_end = match header_size.checked_add(usize_or_max(header.toc_len_compressed)) {
        Some(e) => e,
        None => {
            archive.halted = Some(XarHalt::TocOutOfRange);
            return Some(archive);
        }
    };
    archive.heap_start = toc_end as u64;

    // Reject an absurd declared size before doing any work for it.
    if header.toc_len_uncompressed > limits.max_toc_bytes as u64 {
        archive.halted = Some(XarHalt::TocTooLarge);
        return Some(archive);
    }

    let Some(toc_compressed) = data.get(header_size..toc_end) else {
        archive.halted = Some(XarHalt::TocOutOfRange);
        return Some(archive);
    };
    if toc_compressed.is_empty() {
        archive.halted = Some(XarHalt::TocUndecodable);
        return Some(archive);
    }

    let toc = match inflate::zlib_decompress(toc_compressed, limits.max_toc_bytes) {
        Ok(t) => t,
        Err(DecodeError::BudgetExceeded) => {
            archive.halted = Some(XarHalt::TocTooLarge);
            return Some(archive);
        }
        Err(_) => {
            archive.halted = Some(XarHalt::TocUndecodable);
            return Some(archive);
        }
    };

    walk_toc(&toc, limits, &mut archive);
    Some(archive)
}

/// Read one entry's bytes back out of the heap, decompressing under budget.
///
/// `data` must be the same buffer that was handed to [`parse`].
pub fn read_entry(
    data: &[u8],
    archive: &XarArchive,
    file: &XarFile,
    limits: &XarLimits,
) -> Result<Vec<u8>, XarEntryError> {
    match read_entry_partial(data, archive, file, limits)? {
        (bytes, None) => Ok(bytes),
        (_, Some(e)) => Err(e),
    }
}

/// Like [`read_entry`], but an entry that fails partway (a compressed one
/// that breaks, a stored one over `max_entry_bytes`) still yields the bytes
/// before the failure, which may include an unverified or cut-short final
/// block. `Ok((bytes, None))` is a full read; `Ok((bytes, Some(err)))` is a
/// non-empty partial one. Callers must treat the latter as incomplete
/// evidence, never as a clean read.
pub fn read_entry_partial(
    data: &[u8],
    archive: &XarArchive,
    file: &XarFile,
    limits: &XarLimits,
) -> Result<(Vec<u8>, Option<XarEntryError>), XarEntryError> {
    decode_entry(entry_bytes(data, archive, file)?, limits)
}

/// The entry's bytes in the heap. `data` must be the buffer given to [`parse`].
fn entry_bytes<'d>(
    data: &'d [u8],
    archive: &XarArchive,
    file: &XarFile,
) -> Result<&'d [u8], XarEntryError> {
    let (offset, length) = match (file.offset, file.length) {
        (Some(o), Some(l)) => (o, l),
        _ => return Err(XarEntryError::NoHeapLocation),
    };

    let start = archive
        .heap_start
        .checked_add(offset)
        .and_then(|s| usize::try_from(s).ok())
        .ok_or(XarEntryError::OutOfRange)?;
    let end = usize::try_from(length)
        .ok()
        .and_then(|l| start.checked_add(l))
        .ok_or(XarEntryError::OutOfRange)?;
    data.get(start..end).ok_or(XarEntryError::OutOfRange)
}

/// An xz stream: a format with no decoder here.
fn is_xz(raw: &[u8]) -> bool {
    raw.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00])
}

/// What [`ReadBudget::read_entry_partial`] charges for `file`'s input: its heap
/// length, or for a bzip2 stream at least one block of its declared size.
/// `Err` for an entry that cannot be located, or is xz (reading it costs nothing).
pub fn entry_cost(
    data: &[u8],
    archive: &XarArchive,
    file: &XarFile,
) -> Result<usize, XarEntryError> {
    let raw = entry_bytes(data, archive, file)?;
    if is_xz(raw) {
        return Err(XarEntryError::UnknownEncoding);
    }
    Ok(match crate::bzip2::block_size(raw) {
        Some(block) => raw.len().max(block),
        None => raw.len(),
    })
}

/// Decodes one entry's raw heap bytes under `limits`; results as [`read_entry_partial`].
fn decode_entry(
    raw: &[u8],
    limits: &XarLimits,
) -> Result<(Vec<u8>, Option<XarEntryError>), XarEntryError> {
    // Dispatch on the bytes, not the `encoding` attribute (see module docs).
    // Formats we have no decoder for (xz) must not come back as "stored" text.
    if is_xz(raw) {
        Err(XarEntryError::UnknownEncoding)
    } else if crate::bzip2::has_bzip2_magic(raw) {
        let (bytes, result) = crate::bzip2::bzip2_decompress_partial(raw, limits.max_entry_bytes);
        partial_read(bytes, result)
    } else if inflate::has_gzip_magic(raw) {
        let (bytes, result) = inflate::gzip_decompress_partial(raw, limits.max_entry_bytes);
        partial_read(bytes, result)
    } else if raw.first().is_some_and(|b| b & 0x0f == 8) {
        // Plausible zlib CMF; if the header checks fail, treat it as stored.
        let (bytes, result) = inflate::zlib_decompress_partial(raw, limits.max_entry_bytes);
        match result {
            Err(DecodeError::BadHeader) => stored(raw, limits),
            result => partial_read(bytes, result),
        }
    } else {
        stored(raw, limits)
    }
}

/// Work spent reading entries back from one archive's heap (§6.2): compressed
/// bytes consumed plus decoded bytes produced, against an archive-wide total
/// and a per-entry allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadBudget {
    limits: XarLimits,
    remaining: usize,
    entry_remaining: usize,
}

impl ReadBudget {
    /// A fresh budget of `limits.max_read_back_bytes`; `limits` also governs
    /// later reads. Until [`ReadBudget::start_entry`] the whole budget is
    /// the entry allowance.
    pub fn new(limits: &XarLimits) -> Self {
        ReadBudget {
            limits: *limits,
            remaining: limits.max_read_back_bytes,
            entry_remaining: limits.max_read_back_bytes,
        }
    }

    /// Bytes still available across the archive.
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Gives the next entry an equal share of what remains. `entries_left`
    /// counts it and every entry still to come. Call once before each entry,
    /// cheapest ([`entry_cost`]) first, so unused allowance carries to later ones.
    pub fn start_entry(&mut self, entries_left: usize) {
        self.entry_remaining = self.remaining / entries_left.max(1);
    }

    /// Charges `n` bytes against the archive total and the current entry's
    /// allowance (a nested layer, or an entry read). Saturates at zero.
    pub fn charge(&mut self, n: usize) {
        self.remaining = self.remaining.saturating_sub(n);
        self.entry_remaining = self.entry_remaining.saturating_sub(n);
    }

    /// The decoded-size cap for the current entry: the smaller of
    /// `limits.max_entry_bytes` and its allowance.
    pub fn entry_cap(&self) -> usize {
        self.limits.max_entry_bytes.min(self.entry_remaining)
    }

    /// [`read_entry_partial`] under the current entry's allowance: at most half
    /// of it pays for input (a bzip2 entry at least one block), the rest is left
    /// for output. Charges the input read and the bytes returned, nothing if
    /// the entry cannot be located, is xz, or does not fit. An entry longer
    /// than that half is cut, and then always reports `Undecodable(BudgetExceeded)`
    /// with non-empty bytes, or `Err`.
    pub fn read_entry_partial(
        &mut self,
        data: &[u8],
        archive: &XarArchive,
        file: &XarFile,
    ) -> Result<(Vec<u8>, Option<XarEntryError>), XarEntryError> {
        let over = XarEntryError::BUDGET_EXCEEDED;
        let raw = entry_bytes(data, archive, file)?;
        if is_xz(raw) {
            return Err(XarEntryError::UnknownEncoding);
        }
        let half = self.entry_remaining / 2;
        if half == 0 || self.limits.max_entry_bytes == 0 {
            return Err(over);
        }
        let (input, cost, cut) = match crate::bzip2::block_size(raw) {
            // A block is decoded before its first output byte is checked.
            Some(block) => {
                let cost = raw.len().max(block);
                if cost > half {
                    return Err(over);
                }
                (raw, cost, false)
            }
            None => {
                let input = raw.get(..half).unwrap_or(raw);
                (input, input.len(), raw.len() > half)
            }
        };
        self.charge(cost);
        let capped = XarLimits {
            max_entry_bytes: self.entry_cap(),
            ..self.limits
        };
        let result = decode_entry(input, &capped);
        if let Ok((bytes, _)) = &result {
            self.charge(bytes.len());
        }
        match (cut, result) {
            (true, Ok((bytes, _))) if !bytes.is_empty() => Ok((bytes, Some(over))),
            (true, Ok(_) | Err(XarEntryError::Undecodable(_))) => Err(over),
            (_, result) => result,
        }
    }
}

/// A decoder's result as a partial read: a failure with output is
/// `Ok((bytes, Some(err)))`, a failure with none is `Err`.
fn partial_read(
    bytes: Vec<u8>,
    result: Result<(), DecodeError>,
) -> Result<(Vec<u8>, Option<XarEntryError>), XarEntryError> {
    match result {
        Ok(()) => Ok((bytes, None)),
        // Decoded bytes are kept as evidence for every error kind (§5.2).
        Err(e) if !bytes.is_empty() => Ok((bytes, Some(XarEntryError::Undecodable(e)))),
        Err(e) => Err(XarEntryError::Undecodable(e)),
    }
}

/// An entry stored without compression. Over `max_entry_bytes` it yields the
/// first `max_entry_bytes` bytes with `BudgetExceeded`, or `Err` if that is none.
fn stored(
    raw: &[u8],
    limits: &XarLimits,
) -> Result<(Vec<u8>, Option<XarEntryError>), XarEntryError> {
    let over = XarEntryError::BUDGET_EXCEEDED;
    match raw.get(..limits.max_entry_bytes) {
        Some(prefix) if prefix.len() < raw.len() => {
            if prefix.is_empty() {
                Err(over)
            } else {
                Ok((prefix.to_vec(), Some(over)))
            }
        }
        _ => Ok((raw.to_vec(), None)),
    }
}

// --- TOC walking ---------------------------------------------------------

/// A `<file>` node under construction. Fields arrive in no fixed order (and
/// `<name>` may follow the children), so paths are resolved in a second pass.
struct Node {
    parent: Option<usize>,
    name: Option<String>,
    kind: XarKind,
    encoding: Option<String>,
    offset: Option<u64>,
    length: Option<u64>,
    size: Option<u64>,
    depth: usize,
}

fn walk_toc(toc: &[u8], limits: &XarLimits, archive: &mut XarArchive) {
    let mut sc = Scanner::new(toc);
    // Stack of open elements, so text is attributed to the right parent
    // (`<offset>` under `<data>` vs. under `<checksum>`).
    let mut elems: Vec<&str> = Vec::new();
    let mut open_files: Vec<usize> = Vec::new();
    let mut nodes: Vec<Node> = Vec::new();
    let mut sig: Option<XarSignature> = None;
    // True while the recorded root-level `<signature>` is the open element.
    let mut in_sig = false;
    // A TOC with no `<toc>` element must halt, not come back "complete, zero
    // files" (which reads as "package contains nothing").
    let mut saw_toc = false;

    loop {
        match sc.next_event() {
            Next::End => {
                // Elements still open at EOF => the TOC was cut short.
                if !elems.is_empty() {
                    archive.halted = Some(XarHalt::TocMalformed);
                }
                break;
            }
            Next::Bad => {
                archive.halted = Some(XarHalt::TocMalformed);
                break;
            }
            Next::Event(Event::Open {
                name,
                attrs,
                self_closing,
            }) => {
                let parent_elem = elems.last().copied();

                match name {
                    "file" => {
                        if open_files.len() >= limits.max_depth {
                            archive.halted = Some(XarHalt::DepthLimit);
                            break;
                        }
                        if nodes.len() >= limits.max_entries {
                            archive.halted = Some(XarHalt::EntryLimit);
                            break;
                        }
                        let idx = nodes.len();
                        nodes.push(Node {
                            parent: open_files.last().copied(),
                            name: None,
                            kind: XarKind::Unspecified,
                            encoding: None,
                            offset: None,
                            length: None,
                            size: None,
                            depth: open_files.len(),
                        });
                        if !self_closing {
                            open_files.push(idx);
                        }
                    }
                    "encoding" if parent_elem == Some("data") => {
                        if let Some(i) = open_files.last().copied() {
                            if let Some(n) = nodes.get_mut(i) {
                                n.encoding = xml::attr(attrs, "style");
                            }
                        }
                    }
                    "signature" if sig.is_none() && elems.as_slice() == ["xar", "toc"] => {
                        sig = Some(XarSignature {
                            style: xml::attr(attrs, "style").unwrap_or_default(),
                            offset: None,
                            size: None,
                        });
                        in_sig = !self_closing;
                    }
                    "checksum" if archive.checksum_style.is_none() => {
                        archive.checksum_style = xml::attr(attrs, "style");
                    }
                    "toc" => saw_toc = true,
                    _ => {}
                }

                if !self_closing {
                    elems.push(name);
                }
            }
            Next::Event(Event::Close { name }) => {
                if name == "file" {
                    open_files.pop();
                }
                if name == "signature" && elems.len() == 3 {
                    in_sig = false;
                }
                // Tolerate a stray close — entries collected so far are evidence.
                if elems.last() == Some(&name) {
                    elems.pop();
                }
            }
            Next::Event(Event::Text(raw)) => {
                let Some(&elem) = elems.last() else { continue };
                let parent = elems
                    .len()
                    .checked_sub(2)
                    .and_then(|i| elems.get(i))
                    .copied();

                // Offset/size of the recorded signature only; any other
                // <signature> never fills it in.
                if parent == Some("signature") {
                    if let (Some(s), true) = (sig.as_mut(), in_sig && elems.len() == 4) {
                        match elem {
                            "offset" => s.offset = parse_u64(raw),
                            "size" => s.size = parse_u64(raw),
                            _ => {}
                        }
                    }
                    continue;
                }

                let Some(i) = open_files.last().copied() else {
                    continue;
                };
                let Some(node) = nodes.get_mut(i) else {
                    continue;
                };

                match (parent, elem) {
                    (Some("file"), "name") => node.name = Some(xml::decode_entities(raw)),
                    (Some("file"), "type") => {
                        node.kind = match xml::decode_entities(raw).as_str() {
                            "file" => XarKind::File,
                            "directory" => XarKind::Directory,
                            other => XarKind::Other(other.to_string()),
                        }
                    }
                    (Some("data"), "offset") => node.offset = parse_u64(raw),
                    (Some("data"), "length") => node.length = parse_u64(raw),
                    (Some("data"), "size") => node.size = parse_u64(raw),
                    _ => {}
                }
            }
        }
    }

    if !saw_toc && archive.halted.is_none() {
        archive.halted = Some(XarHalt::TocMalformed);
    }

    archive.signature = sig;
    archive.files = resolve_paths(&nodes, limits);
}

/// Second pass: now that every node's name is known, build full paths.
fn resolve_paths(nodes: &[Node], limits: &XarLimits) -> Vec<XarFile> {
    let name_of = |i: usize| -> &str {
        nodes
            .get(i)
            .and_then(|n| n.name.as_deref())
            .unwrap_or("<unnamed>")
    };

    let mut out = Vec::with_capacity(nodes.len());
    for (i, n) in nodes.iter().enumerate() {
        // Walk to the root, bounded by max_depth against a malformed chain.
        let mut parts: Vec<&str> = vec![name_of(i)];
        let mut cur = n.parent;
        let mut guard = 0usize;
        while let Some(p) = cur {
            if guard > limits.max_depth {
                break;
            }
            parts.push(name_of(p));
            cur = nodes.get(p).and_then(|x| x.parent);
            guard += 1;
        }
        parts.reverse();

        out.push(XarFile {
            path: parts.join("/"),
            name: name_of(i).to_string(),
            depth: n.depth,
            kind: n.kind.clone(),
            encoding: n.encoding.clone(),
            offset: n.offset,
            length: n.length,
            size: n.size,
        });
    }
    out
}

/// Parse element text as a decimal `u64`, rejecting anything else.
fn parse_u64(raw: &[u8]) -> Option<u64> {
    // Hand-rolled trim: `<[u8]>::trim_ascii` is stable only since 1.80.
    let start = raw
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    let t = raw.get(start..end)?;
    if t.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &c in t {
        v = v
            .checked_mul(10)?
            .checked_add(u64::from(char::from(c).to_digit(10)?))?;
    }
    Some(v)
}

fn usize_or_max(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

fn be_u16(d: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        d.get(off..off.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn be_u32(d: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        d.get(off..off.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn be_u64(d: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        d.get(off..off.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
/// A xar whose TOC is `toc_body` inside `<xar><toc>`, zlib-wrapped as one
/// stored block (test TOCs are far below 64 KiB).
pub(crate) fn toc_xar_bytes(toc_body: &str) -> Vec<u8> {
    let toc = format!("<?xml version=\"1.0\"?><xar><toc>{toc_body}</toc></xar>");
    let len = toc.len() as u16;
    let mut z = vec![0x78, 0x01, 0x01];
    z.extend_from_slice(&len.to_le_bytes());
    z.extend_from_slice(&(!len).to_le_bytes());
    z.extend_from_slice(toc.as_bytes());
    z.extend_from_slice(&inflate::adler32(toc.as_bytes()).to_be_bytes());
    let mut v = Vec::new();
    v.extend_from_slice(b"xar!");
    v.extend_from_slice(&28u16.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&(z.len() as u64).to_be_bytes());
    v.extend_from_slice(&(toc.len() as u64).to_be_bytes());
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&z);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! pkg {
        ($name:literal) => {
            include_bytes!(concat!("../testdata/xar/", $name, ".pkg")).as_slice()
        };
    }
    macro_rules! adversarial {
        ($name:literal) => {
            include_bytes!(concat!("../testdata/xar/", $name, ".xar")).as_slice()
        };
    }

    fn adversarial_vectors() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("valid_minimal", adversarial!("valid_minimal")),
            ("truncated_header", adversarial!("truncated_header")),
            ("bad_magic", adversarial!("bad_magic")),
            ("hdrsize_absurd", adversarial!("hdrsize_absurd")),
            ("hdrsize_zero", adversarial!("hdrsize_zero")),
            ("toc_c_past_eof", adversarial!("toc_c_past_eof")),
            ("toc_u_absurd", adversarial!("toc_u_absurd")),
            ("toc_not_zlib", adversarial!("toc_not_zlib")),
            ("toc_empty", adversarial!("toc_empty")),
            ("version_absurd", adversarial!("version_absurd")),
            ("toc_not_xml", adversarial!("toc_not_xml")),
            ("toc_unclosed", adversarial!("toc_unclosed")),
            ("deep_nesting", adversarial!("deep_nesting")),
            ("wide_toc", adversarial!("wide_toc")),
            ("heap_past_eof", adversarial!("heap_past_eof")),
            ("heap_entry_bomb", adversarial!("heap_entry_bomb")),
            ("offset_overflow", adversarial!("offset_overflow")),
        ]
    }

    #[test]
    fn reads_a_real_pkgbuild_package() {
        let a = parse(pkg!("benign"), &XarLimits::default()).expect("should be a xar");
        assert!(a.is_complete(), "halted: {:?}", a.halted);
        assert_eq!(a.header.header_size, 28);
        assert_eq!(a.header.version, 1);
        assert_eq!(a.header.checksum_alg, 1); // sha1
        assert_eq!(a.checksum_style.as_deref(), Some("sha1"));
        assert!(a.signature.is_none(), "pkgbuild output is unsigned");

        let mut names: Vec<&str> = a.files.iter().map(|f| f.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["Bom", "PackageInfo", "Payload", "Scripts"]);

        // Every top-level entry sits at depth 0 with a heap location.
        for f in &a.files {
            assert_eq!(f.depth, 0);
            assert!(f.offset.is_some() && f.length.is_some(), "{}", f.name);
        }
    }

    /// A productbuild package nests a whole `.pkg`, and repeats names across
    /// levels — which is why paths, not names, identify an entry.
    #[test]
    fn reads_a_nested_productbuild_package() {
        let a = parse(pkg!("product"), &XarLimits::default()).expect("xar");
        assert!(a.is_complete(), "halted: {:?}", a.halted);

        let paths: Vec<&str> = a.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"Distribution"), "{paths:?}");
        assert!(paths.contains(&"benign.pkg"), "{paths:?}");
        // Nested children carry their parent in the path.
        assert!(paths.contains(&"benign.pkg/Scripts"), "{paths:?}");
        assert!(paths.contains(&"benign.pkg/PackageInfo"), "{paths:?}");

        let nested = a
            .files
            .iter()
            .find(|f| f.path == "benign.pkg")
            .expect("nested package present");
        assert_eq!(nested.kind, XarKind::Directory);
        assert_eq!(nested.depth, 0);

        let child = a
            .files
            .iter()
            .find(|f| f.path == "benign.pkg/Scripts")
            .expect("nested Scripts present");
        assert_eq!(child.depth, 1);
        // The bare name repeats across levels; only the path is unique.
        assert_eq!(
            a.files.iter().filter(|f| f.name == "Scripts").count(),
            1,
            "product.pkg has one Scripts per contained package"
        );
    }

    /// The point of the module: reach the install-script text for the string
    /// and entropy rules to score.
    #[test]
    fn recovers_install_script_contents() {
        let data = pkg!("suspicious");
        let a = parse(data, &XarLimits::default()).expect("xar");
        assert!(a.is_complete());

        let scripts = a
            .metadata_entries()
            .find(|f| f.name == "Scripts")
            .expect("Scripts is a metadata entry");
        let archive = read_entry(data, &a, scripts, &XarLimits::default()).expect("readable");

        let cpio = crate::cpio::parse(&archive, &crate::cpio::CpioLimits::default())
            .expect("Scripts holds a cpio archive");
        let script = cpio
            .entries
            .iter()
            .find(|e| e.name.ends_with("preinstall"))
            .expect("preinstall present");
        let text = String::from_utf8_lossy(script.data);
        assert!(text.contains("curl -fsSL"));
        assert!(text.contains("base64 -d"));
        assert!(text.contains("osascript -e"));
    }

    /// `PackageInfo` is labelled `application/x-gzip` but is really zlib.
    /// Dispatching on the label rather than the bytes fails here.
    #[test]
    fn entry_encoding_label_is_not_trusted() {
        let data = pkg!("benign");
        let a = parse(data, &XarLimits::default()).expect("xar");

        let info = a
            .files
            .iter()
            .find(|f| f.name == "PackageInfo")
            .expect("PackageInfo present");
        assert_eq!(info.encoding.as_deref(), Some("application/x-gzip"));
        let bytes = read_entry(data, &a, info, &XarLimits::default()).expect("readable");
        assert!(String::from_utf8_lossy(&bytes).contains("<pkg-info"));

        let scripts = a
            .files
            .iter()
            .find(|f| f.name == "Scripts")
            .expect("Scripts present");
        // Labelled octet-stream, actually gzip — the opposite way round.
        assert_eq!(
            scripts.encoding.as_deref(),
            Some("application/octet-stream")
        );
        let bytes = read_entry(data, &a, scripts, &XarLimits::default()).expect("readable");
        assert_eq!(bytes.get(..6), Some(b"070707".as_slice()));
    }

    #[test]
    fn payload_is_not_a_metadata_entry() {
        let a = parse(pkg!("benign"), &XarLimits::default()).expect("xar");
        let meta: Vec<&str> = a.metadata_entries().map(|f| f.name.as_str()).collect();
        assert!(meta.contains(&"Scripts"));
        assert!(meta.contains(&"PackageInfo"));
        assert!(
            !meta.contains(&"Payload"),
            "payload inspection is Phase 0b (§6.1)"
        );
        assert!(!meta.contains(&"Bom"));
    }

    #[test]
    fn a_package_without_scripts_is_complete_and_scriptless() {
        let a = parse(pkg!("noscripts"), &XarLimits::default()).expect("xar");
        assert!(a.is_complete());
        assert!(a.files.iter().all(|f| f.name != "Scripts"));
        // Absence of scripts must not look like a failure to read them.
        assert!(a.metadata_entries().any(|f| f.name == "PackageInfo"));
    }

    /// Mirrors `parse`'s own magic check.
    #[test]
    fn has_xar_magic_matches_parses_gate() {
        assert!(has_xar_magic(b"xar!\x00\x1c\x00\x01"));
        assert!(!has_xar_magic(b""));
        assert!(!has_xar_magic(b"PK\x03\x04"));
    }

    #[test]
    fn non_xar_input_is_not_a_package() {
        assert!(parse(b"", &XarLimits::default()).is_none());
        assert!(parse(b"#!/bin/sh\n", &XarLimits::default()).is_none());
        assert!(parse(adversarial!("bad_magic"), &XarLimits::default()).is_none());
    }

    /// A hostile *TOC* must be rejected as not-a-xar or come back halted, never
    /// as a clean archive. The excluded vectors have valid TOCs and hostile
    /// *heap* pointers only — those are `read_entry`'s job, covered by
    /// `heap_pointers_outside_the_buffer_are_out_of_range` and
    /// `a_heap_entry_bomb_is_stopped_by_the_entry_budget`.
    #[test]
    fn hostile_tocs_halt_rather_than_look_clean() {
        for (name, bytes) in adversarial_vectors() {
            if matches!(
                name,
                "valid_minimal" | "heap_past_eof" | "heap_entry_bomb" | "offset_overflow"
            ) {
                continue;
            }
            match parse(bytes, &XarLimits::default()) {
                None => {}
                Some(a) => assert!(
                    !a.is_complete(),
                    "{name}: hostile container reported complete with {} files",
                    a.files.len()
                ),
            }
        }
    }

    #[test]
    fn declared_toc_size_bomb_is_refused_without_inflating() {
        let a = parse(adversarial!("toc_u_absurd"), &XarLimits::default()).expect("xar");
        assert_eq!(a.halted, Some(XarHalt::TocTooLarge));
    }

    #[test]
    fn an_unknown_xar_version_is_not_parsed_as_version_one() {
        let a = parse(adversarial!("version_absurd"), &XarLimits::default()).expect("xar");
        assert_eq!(a.halted, Some(XarHalt::UnsupportedVersion));
        assert!(a.files.is_empty());
        // The header is still reported — it tells the caller why.
        assert_eq!(a.header.version, 0xFFFF);
    }

    #[test]
    fn nesting_depth_is_bounded() {
        let a = parse(adversarial!("deep_nesting"), &XarLimits::default()).expect("xar");
        assert_eq!(a.halted, Some(XarHalt::DepthLimit));
        assert!(a.files.len() <= XarLimits::default().max_depth + 1);
    }

    #[test]
    fn entry_count_is_bounded() {
        let limits = XarLimits {
            max_entries: 32,
            ..XarLimits::default()
        };
        let a = parse(adversarial!("wide_toc"), &limits).expect("xar");
        assert_eq!(a.halted, Some(XarHalt::EntryLimit));
        assert_eq!(a.files.len(), 32);
    }

    /// One-entry xar whose heap is `blob`.
    fn single_entry(blob: &[u8]) -> Vec<u8> {
        let toc = format!(
            r#"<file id="1"><name>Distribution</name><type>file</type><data><offset>0</offset><length>{n}</length><size>{n}</size></data></file>"#,
            n = blob.len()
        );
        let mut bytes = toc_xar_bytes(&toc);
        bytes.extend_from_slice(blob);
        bytes
    }

    fn read_single(blob: &[u8], limits: &XarLimits) -> Result<Vec<u8>, XarEntryError> {
        let bytes = single_entry(blob);
        let a = parse(&bytes, limits).expect("xar");
        let f = a.files.first().expect("entry");
        read_entry(&bytes, &a, f, limits)
    }

    /// xz is not decoded and must not come back as stored bytes.
    #[test]
    fn xz_entries_are_unknown_encodings() {
        assert_eq!(
            read_single(b"\xFD7zXZ\x00\x00\x04", &XarLimits::default()),
            Err(XarEntryError::UnknownEncoding)
        );
        // Plain text that merely starts with B is still stored.
        assert_eq!(
            read_single(b"BZx", &XarLimits::default()),
            Ok(b"BZx".to_vec())
        );
    }

    #[test]
    fn bzip2_entries_are_decoded() {
        let hello = include_bytes!("../testdata/bzip2/hello.in");
        assert_eq!(
            read_single(hello, &XarLimits::default()),
            Ok(b"hello".to_vec())
        );
    }

    #[test]
    fn a_corrupt_bzip2_entry_is_undecodable() {
        let mut bad = include_bytes!("../testdata/bzip2/hello.in").to_vec();
        bad[10] ^= 0x80; // block CRC
        assert_eq!(
            read_single(&bad, &XarLimits::default()),
            Err(XarEntryError::Undecodable(DecodeError::ChecksumMismatch))
        );
        // A bare header is a truncated stream, not "unknown".
        assert_eq!(
            read_single(b"BZh1", &XarLimits::default()),
            Err(XarEntryError::Undecodable(DecodeError::Truncated))
        );
    }

    /// A bzip2 entry missing its trailer: strict read fails, but libxar (so
    /// Installer) still yields the plaintext; the partial reader does too.
    #[test]
    fn a_bzip2_entry_without_its_trailer_reads_partially() {
        let full = include_bytes!("../testdata/bzip2/distribution_dropper.in");
        let cut = crate::bzip2::cut_trailer(full);
        let limits = XarLimits::default();
        let bytes = single_entry(cut);
        let a = parse(&bytes, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        let trunc = XarEntryError::Undecodable(DecodeError::Truncated);
        assert_eq!(read_entry(&bytes, &a, f, &limits), Err(trunc));
        let plain = include_bytes!("../testdata/bzip2/distribution_dropper.out");
        assert_eq!(
            read_entry_partial(&bytes, &a, f, &limits),
            Ok((plain.to_vec(), Some(trunc)))
        );
        // An entry that fails before its first block yields nothing.
        let bytes = single_entry(&cut[..8]);
        let a = parse(&bytes, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        assert_eq!(read_entry_partial(&bytes, &a, f, &limits), Err(trunc));
    }

    type PartialRead = Result<(Vec<u8>, Option<XarEntryError>), XarEntryError>;

    /// `read_entry` and `read_entry_partial` on a one-entry xar holding `blob`.
    fn read_both(blob: &[u8], limits: &XarLimits) -> (Result<Vec<u8>, XarEntryError>, PartialRead) {
        let bytes = single_entry(blob);
        let a = parse(&bytes, limits).expect("xar");
        let f = a.files.first().expect("entry");
        (
            read_entry(&bytes, &a, f, limits),
            read_entry_partial(&bytes, &a, f, limits),
        )
    }

    /// Strict read fails with `err`; the partial read yields `want` plus `err`.
    fn assert_reads_partially(blob: &[u8], want: &[u8], err: DecodeError) {
        let e = XarEntryError::Undecodable(err);
        let (strict, partial) = read_both(blob, &XarLimits::default());
        assert_eq!(strict, Err(e));
        assert_eq!(partial, Ok((want.to_vec(), Some(e))));
    }

    #[test]
    fn a_zlib_entry_without_its_adler_reads_partially() {
        let full = include_bytes!("../testdata/inflate/zlib_distribution_dropper.in");
        let plain = include_bytes!("../testdata/inflate/zlib_distribution_dropper.out");
        assert_reads_partially(&full[..full.len() - 4], plain, DecodeError::Truncated);
        assert_reads_partially(&full[..full.len() - 2], plain, DecodeError::Truncated);

        let mut bad = full.to_vec();
        *bad.last_mut().expect("non-empty") ^= 0xff;
        assert_reads_partially(&bad, plain, DecodeError::ChecksumMismatch);
    }

    #[test]
    fn a_zlib_entry_cut_mid_stream_reads_a_prefix() {
        let full = include_bytes!("../testdata/inflate/zlib_distribution_padded.in");
        let plain = include_bytes!("../testdata/inflate/zlib_distribution_padded.out");
        let e = XarEntryError::Undecodable(DecodeError::Truncated);
        let (strict, partial) = read_both(&full[..full.len() - 10], &XarLimits::default());
        assert_eq!(strict, Err(e));
        let (bytes, gap) = partial.expect("partial read");
        assert_eq!(gap, Some(e));
        assert!(!bytes.is_empty() && bytes.len() < plain.len());
        assert!(plain.starts_with(&bytes));
    }

    #[test]
    fn a_gzip_entry_without_its_trailer_reads_partially() {
        let full = include_bytes!("../testdata/gzip/scripts_dropper.in");
        let plain = include_bytes!("../testdata/gzip/scripts_dropper.out");
        assert_reads_partially(&full[..full.len() - 8], plain, DecodeError::Truncated);
    }

    #[test]
    fn a_gzip_entry_cut_mid_stream_reads_a_prefix() {
        let full = include_bytes!("../testdata/gzip/scripts_dropper_long.in");
        let plain = include_bytes!("../testdata/gzip/scripts_dropper_long.out");
        let e = XarEntryError::Undecodable(DecodeError::Truncated);
        let (strict, partial) = read_both(&full[..full.len() - 8 - 100], &XarLimits::default());
        assert_eq!(strict, Err(e));
        let (bytes, gap) = partial.expect("partial read");
        assert_eq!(gap, Some(e));
        assert!(!bytes.is_empty() && bytes.len() < plain.len());
        assert!(plain.starts_with(&bytes));
    }

    #[test]
    fn a_gzip_entry_with_a_bad_crc_or_isize_reads_in_full() {
        let full = include_bytes!("../testdata/gzip/scripts_dropper.in");
        let plain = include_bytes!("../testdata/gzip/scripts_dropper.out");
        for from_end in [8, 4] {
            let mut bad = full.to_vec();
            let i = bad.len() - from_end;
            *bad.get_mut(i).expect("in range") ^= 0xff;
            assert_reads_partially(&bad, plain, DecodeError::ChecksumMismatch);
        }
    }

    #[test]
    fn an_over_budget_gzip_entry_yields_exactly_the_budget() {
        let full = include_bytes!("../testdata/gzip/scripts_dropper_long.in");
        let plain = include_bytes!("../testdata/gzip/scripts_dropper_long.out");
        let limits = XarLimits {
            max_entry_bytes: 100,
            ..XarLimits::default()
        };
        let e = XarEntryError::Undecodable(DecodeError::BudgetExceeded);
        let (strict, partial) = read_both(full, &limits);
        assert_eq!(strict, Err(e));
        assert_eq!(partial, Ok((plain[..100].to_vec(), Some(e))));
    }

    #[test]
    fn a_zlib_entry_failing_before_any_output_is_undecodable() {
        let e = XarEntryError::Undecodable(DecodeError::Truncated);
        let (strict, partial) = read_both(&[0x78, 0x9c], &XarLimits::default());
        assert_eq!(strict, Err(e));
        assert_eq!(partial, Err(e));
    }

    #[test]
    fn an_over_budget_zlib_entry_yields_exactly_the_budget() {
        let full = include_bytes!("../testdata/inflate/zlib_distribution_padded.in");
        let plain = include_bytes!("../testdata/inflate/zlib_distribution_padded.out");
        let limits = XarLimits {
            max_entry_bytes: 100,
            ..XarLimits::default()
        };
        let e = XarEntryError::Undecodable(DecodeError::BudgetExceeded);
        let (strict, partial) = read_both(full, &limits);
        assert_eq!(strict, Err(e));
        assert_eq!(partial, Ok((plain[..100].to_vec(), Some(e))));
    }

    fn budget_limits() -> XarLimits {
        XarLimits {
            max_entry_bytes: 1000,
            max_read_back_bytes: 2500,
            ..XarLimits::default()
        }
    }

    const BUDGET_ERR: XarEntryError = XarEntryError::Undecodable(DecodeError::BudgetExceeded);

    const ORDINARY: &[u8] = include_bytes!("../testdata/inflate/zlib_distribution_ordinary.in");
    /// Compressed length and decoded length of `ORDINARY`.
    const ORDINARY_IN: usize = 402;
    const ORDINARY_OUT: usize = 844;

    /// A zlib stream of `n` empty non-final stored blocks: `5n + 11` bytes in,
    /// nothing out.
    fn empty_blocks_zlib(n: usize) -> Vec<u8> {
        let mut v = vec![0x78, 0x01];
        for _ in 0..n {
            v.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff]);
        }
        v.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01]);
        v
    }

    /// Heap entries `(offset, length)` named `Distribution`, over `heap`.
    fn entries_over(heap: &[u8], spans: &[(usize, usize)]) -> Vec<u8> {
        let body: String = spans
            .iter()
            .map(|(o, l)| {
                format!(
                    r#"<file id="1"><name>Distribution</name><type>file</type><data><offset>{o}</offset><length>{l}</length><size>{l}</size></data></file>"#
                )
            })
            .collect();
        let mut bytes = toc_xar_bytes(&body);
        bytes.extend_from_slice(heap);
        bytes
    }

    /// `n` entries named `Distribution`, all pointing at one heap blob.
    fn shared_blob_entries(blob: &[u8], n: usize) -> Vec<u8> {
        entries_over(blob, &vec![(0, blob.len()); n])
    }

    #[test]
    fn the_read_back_budget_is_charged_for_input_and_output() {
        assert_eq!(ORDINARY.len(), ORDINARY_IN);
        let plain = include_bytes!("../testdata/inflate/zlib_distribution_ordinary.out");
        assert_eq!(plain.len(), ORDINARY_OUT);
        let limits = XarLimits {
            max_entry_bytes: 1000,
            max_read_back_bytes: 9000,
            ..XarLimits::default()
        };
        let bytes = shared_blob_entries(ORDINARY, 6);
        let a = parse(&bytes, &limits).expect("xar");
        let mut budget = ReadBudget::new(&limits);
        let cost = ORDINARY_IN + ORDINARY_OUT;

        for (i, f) in a.files.iter().enumerate() {
            budget.start_entry(a.files.len() - i);
            let got = budget.read_entry_partial(&bytes, &a, f);
            assert_eq!(got, Ok((plain.to_vec(), None)));
            assert_eq!(budget.remaining(), 9000 - (i + 1) * cost);
        }
    }

    #[test]
    fn an_exhausted_budget_reads_nothing() {
        let limits = budget_limits();
        let bytes = single_entry(b"abc");
        let a = parse(&bytes, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        let mut budget = ReadBudget::new(&limits);
        budget.charge(usize::MAX);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.read_entry_partial(&bytes, &a, f), Err(BUDGET_ERR));

        // Not even a zero-length entry is read once nothing is left.
        let empty = single_entry(b"");
        let a = parse(&empty, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        assert_eq!(budget.read_entry_partial(&empty, &a, f), Err(BUDGET_ERR));
        assert_eq!(budget.remaining(), 0);
        let mut fresh = ReadBudget::new(&limits);
        assert_eq!(
            fresh.read_entry_partial(&empty, &a, f),
            Ok((Vec::new(), None))
        );
    }

    #[test]
    fn entries_get_a_fair_share_and_unused_allowance_carries_forward() {
        let limits = XarLimits {
            max_entry_bytes: 4000,
            max_read_back_bytes: 4000,
            ..XarLimits::default()
        };
        // Three 10-byte stored entries, then a 1500-byte one.
        let heap = vec![b'a'; 1530];
        let bytes = entries_over(&heap, &[(0, 10), (10, 10), (20, 10), (30, 1500)]);
        let a = parse(&bytes, &limits).expect("xar");
        let mut budget = ReadBudget::new(&limits);

        for (i, f) in a.files.iter().take(3).enumerate() {
            budget.start_entry(4 - i);
            assert!(budget.entry_cap() <= 4000 / (4 - i));
            let got = budget.read_entry_partial(&bytes, &a, f);
            assert_eq!(got, Ok((vec![b'a'; 10], None)));
        }
        assert_eq!(budget.remaining(), 4000 - 3 * 20);

        // A quarter of the total is 1000; the last entry costs 3000.
        budget.start_entry(1);
        let f = a.files.get(3).expect("entry");
        let (got, gap) = budget.read_entry_partial(&bytes, &a, f).expect("reads");
        assert_eq!((got.len(), gap), (1500, None));
        assert_eq!(budget.remaining(), 4000 - 60 - 3000);

        // Up front, an entry gets at most its share, input and output together:
        // 1000 allows a 500-byte prefix and 500 bytes of output.
        let mut budget = ReadBudget::new(&limits);
        budget.start_entry(4);
        let big = a.files.get(3).expect("entry");
        assert_eq!(
            budget.read_entry_partial(&bytes, &a, big),
            Ok((vec![b'a'; 500], Some(BUDGET_ERR)))
        );
        assert_eq!(budget.remaining(), 4000 - 1000);
    }

    #[test]
    fn a_stored_entry_larger_than_the_remaining_budget_yields_its_prefix() {
        let limits = XarLimits {
            max_entry_bytes: 1000,
            max_read_back_bytes: 1000,
            ..XarLimits::default()
        };
        let blob = vec![b'a'; 800];
        let bytes = single_entry(&blob);
        let a = parse(&bytes, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        let mut budget = ReadBudget::new(&limits);
        // At most half the allowance pays for input; the same half is output.
        assert_eq!(
            budget.read_entry_partial(&bytes, &a, f),
            Ok((blob[..500].to_vec(), Some(BUDGET_ERR)))
        );
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn charge_saturates_at_zero() {
        let mut budget = ReadBudget::new(&budget_limits());
        assert_eq!(budget.entry_cap(), 1000);
        budget.charge(2000);
        assert_eq!(budget.remaining(), 500);
        assert_eq!(budget.entry_cap(), 500);
        budget.charge(usize::MAX);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.entry_cap(), 0);
    }

    #[test]
    fn start_entry_with_nothing_left_to_read_does_not_divide_by_zero() {
        let mut budget = ReadBudget::new(&budget_limits());
        budget.start_entry(0);
        assert_eq!(budget.entry_cap(), 1000);
    }

    #[test]
    fn an_entry_with_large_input_and_no_output_is_charged_for_its_input() {
        let blob = empty_blocks_zlib(800);
        let input = blob.len();
        let limits = XarLimits {
            max_entry_bytes: 1000,
            max_read_back_bytes: 3 * input,
            ..XarLimits::default()
        };
        let bytes = shared_blob_entries(&blob, 20);
        let a = parse(&bytes, &limits).expect("xar");
        let mut budget = ReadBudget::new(&limits);
        let mut ok = 0;
        for f in &a.files {
            budget.start_entry(1);
            match budget.read_entry_partial(&bytes, &a, f) {
                Ok((out, None)) => {
                    assert!(out.is_empty());
                    ok += 1;
                }
                other => assert_eq!(other, Err(BUDGET_ERR)),
            }
        }
        assert_eq!(ok, 2);
        assert!(ok <= limits.max_read_back_bytes / input);
        // The two full reads, plus the prefixes cut from what was left.
        assert!(budget.remaining() <= limits.max_read_back_bytes - 2 * input);
    }

    #[test]
    fn a_decode_failure_charges_its_input_and_a_locate_failure_nothing() {
        let limits = budget_limits();
        let bytes = single_entry(b"abc");
        let a = parse(&bytes, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        let mut budget = ReadBudget::new(&limits);
        // Heap cut off before the entry's bytes.
        assert_eq!(
            budget.read_entry_partial(bytes.get(..bytes.len() - 1).expect("cut"), &a, f),
            Err(XarEntryError::OutOfRange)
        );
        assert_eq!(budget.remaining(), 2500);

        // A stream that decodes to nothing and then fails its checksum.
        let mut blob = empty_blocks_zlib(10);
        *blob.last_mut().expect("non-empty") ^= 0xff;
        let bytes = single_entry(&blob);
        let a = parse(&bytes, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        let mut budget = ReadBudget::new(&limits);
        assert!(budget.read_entry_partial(&bytes, &a, f).is_err());
        assert_eq!(budget.remaining(), 2500 - blob.len());
    }

    type PartialResult = Result<(Vec<u8>, Option<XarEntryError>), XarEntryError>;

    /// One entry's allowance of `allowance`, over a heap of `blob`.
    fn read_with_allowance(blob: &[u8], allowance: usize) -> (PartialResult, usize) {
        let limits = XarLimits {
            max_entry_bytes: 1 << 20,
            max_read_back_bytes: allowance,
            ..XarLimits::default()
        };
        let bytes = single_entry(blob);
        let a = parse(&bytes, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        let mut budget = ReadBudget::new(&limits);
        let got = budget.read_entry_partial(&bytes, &a, f);
        (got, allowance - budget.remaining())
    }

    #[test]
    fn a_locate_failure_or_an_xz_entry_charges_nothing() {
        let limits = budget_limits();
        let bytes = single_entry(b"abc");
        let a = parse(&bytes, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        let mut budget = ReadBudget::new(&limits);
        let short = bytes.get(..bytes.len() - 1).expect("cut");
        assert_eq!(
            budget.read_entry_partial(short, &a, f),
            Err(XarEntryError::OutOfRange)
        );
        // A huge declared length is OutOfRange, not a charge.
        let huge = entries_over(b"abc", &[(0, 1 << 40)]);
        let a = parse(&huge, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        assert_eq!(
            budget.read_entry_partial(&huge, &a, f),
            Err(XarEntryError::OutOfRange)
        );
        // No heap location at all.
        let mut nowhere = f.clone();
        nowhere.offset = None;
        assert_eq!(
            budget.read_entry_partial(&huge, &a, &nowhere),
            Err(XarEntryError::NoHeapLocation)
        );
        assert_eq!(budget.remaining(), 2500);

        let xz = single_entry(b"\xFD7zXZ\x00\x00\x04");
        let a = parse(&xz, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        assert_eq!(
            budget.read_entry_partial(&xz, &a, f),
            Err(XarEntryError::UnknownEncoding)
        );
        assert_eq!(budget.remaining(), 2500);
    }

    #[test]
    fn an_entry_at_or_over_its_allowance_is_cut_and_reports_the_budget() {
        let plain = include_bytes!("../testdata/inflate/zlib_distribution_ordinary.out");
        // Equal to, then larger than, the allowance.
        for allowance in [ORDINARY_IN, ORDINARY_IN - 100] {
            let (got, charged) = read_with_allowance(ORDINARY, allowance);
            let (bytes, gap) = got.expect("a cut prefix");
            assert!(!bytes.is_empty());
            assert!(plain.starts_with(&bytes));
            assert_eq!(gap, Some(BUDGET_ERR));
            assert!(charged <= allowance, "{charged} > {allowance}");
        }
        let stored = vec![b'a'; 600];
        for allowance in [600, 400] {
            let (got, charged) = read_with_allowance(&stored, allowance);
            assert_eq!(
                got,
                Ok((stored[..allowance / 2].to_vec(), Some(BUDGET_ERR)))
            );
            assert!(charged <= allowance);
        }
    }

    #[test]
    fn a_cut_holding_a_whole_stream_is_still_a_gap() {
        let mut blob = include_bytes!("../testdata/inflate/zlib_hello.in").to_vec();
        let plain = include_bytes!("../testdata/inflate/zlib_hello.out");
        blob.extend_from_slice(&[0u8; 100]);
        // The stream sits inside the first half of a 120-byte allowance.
        let (got, charged) = read_with_allowance(&blob, 120);
        assert_eq!(got, Ok((plain.to_vec(), Some(BUDGET_ERR))));
        assert!(charged <= 120);
        // Stored: the cut is the first half, never a full read.
        let (got, _) = read_with_allowance(&[b'a'; 40], 40);
        assert_eq!(got, Ok((vec![b'a'; 20], Some(BUDGET_ERR))));
    }

    #[test]
    fn an_entry_of_half_the_allowance_is_read_whole_and_one_more_is_cut() {
        let allowance = 1000;
        let whole = vec![b'a'; allowance / 2];
        let (got, charged) = read_with_allowance(&whole, allowance);
        assert_eq!(got, Ok((whole.clone(), None)));
        assert_eq!(charged, 2 * whole.len());

        let longer = vec![b'a'; allowance / 2 + 1];
        let (got, charged) = read_with_allowance(&longer, allowance);
        assert_eq!(got, Ok((whole, Some(BUDGET_ERR))));
        assert!(charged <= allowance);
    }

    #[test]
    fn a_cut_prefix_that_decodes_to_nothing_is_refused_not_an_empty_gap() {
        let mut blob = vec![0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01];
        blob.resize(100, 0);
        let (got, charged) = read_with_allowance(&blob, 100);
        assert_eq!(got, Err(BUDGET_ERR));
        assert!(charged <= 100);
    }

    #[test]
    fn a_zero_entry_cap_reads_nothing() {
        let limits = XarLimits {
            max_entry_bytes: 0,
            ..budget_limits()
        };
        let bytes = single_entry(b"abc");
        let a = parse(&bytes, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        let mut budget = ReadBudget::new(&limits);
        assert_eq!(budget.read_entry_partial(&bytes, &a, f), Err(BUDGET_ERR));
        assert_eq!(budget.remaining(), limits.max_read_back_bytes);
    }

    #[test]
    fn entry_cost_is_the_input_length_or_a_bzip2_block() {
        let limits = budget_limits();
        let cost_of = |blob: &[u8]| {
            let bytes = single_entry(blob);
            let a = parse(&bytes, &limits).expect("xar");
            let f = a.files.first().expect("entry");
            entry_cost(&bytes, &a, f)
        };
        assert_eq!(cost_of(ORDINARY), Ok(ORDINARY_IN));
        assert_eq!(cost_of(b"abc"), Ok(3));
        let hello = include_bytes!("../testdata/bzip2/hello.in");
        assert_eq!(cost_of(hello), Ok(900_000));
        let mut small = b"BZh1".to_vec();
        small.resize(30, 0);
        assert_eq!(cost_of(&small), Ok(100_000));
        let mut large = b"BZh1".to_vec();
        large.resize(100_001, 0);
        assert_eq!(cost_of(&large), Ok(100_001));
        assert_eq!(
            cost_of(b"\xFD7zXZ\x00\x00\x04"),
            Err(XarEntryError::UnknownEncoding)
        );

        let bytes = single_entry(b"abc");
        let a = parse(&bytes, &limits).expect("xar");
        let f = a.files.first().expect("entry");
        let short = bytes.get(..bytes.len() - 1).expect("cut");
        assert_eq!(entry_cost(short, &a, f), Err(XarEntryError::OutOfRange));
        let mut nowhere = f.clone();
        nowhere.offset = None;
        assert_eq!(
            entry_cost(&bytes, &a, &nowhere),
            Err(XarEntryError::NoHeapLocation)
        );
    }

    #[test]
    fn a_bzip2_entry_is_charged_a_block_or_refused() {
        let hello = include_bytes!("../testdata/bzip2/hello.in");
        let block = 900_000;
        assert_eq!(crate::bzip2::block_size(hello), Some(block));
        // A block over half the allowance: refused, nothing charged.
        for allowance in [block - 1, 2 * block - 1] {
            let (got, charged) = read_with_allowance(hello, allowance);
            assert_eq!((got, charged), (Err(BUDGET_ERR), 0));
        }
        // A block equal to half the allowance: read, and charged the block.
        for allowance in [2 * block, 2 * block + 1] {
            let (got, charged) = read_with_allowance(hello, allowance);
            assert_eq!(got, Ok((b"hello".to_vec(), None)));
            assert!(charged >= block && charged <= allowance);
        }
    }

    #[test]
    fn bzip2_reads_are_bounded_by_the_budget_over_the_block_size() {
        let hello = include_bytes!("../testdata/bzip2/hello.in");
        let block = 900_000;
        let limits = XarLimits {
            max_entry_bytes: 1 << 20,
            max_read_back_bytes: 5 * block,
            ..XarLimits::default()
        };
        let bytes = shared_blob_entries(hello, 50);
        let a = parse(&bytes, &limits).expect("xar");
        let mut budget = ReadBudget::new(&limits);
        let mut ok = 0;
        for f in &a.files {
            budget.start_entry(1);
            let before = budget.remaining();
            if budget.read_entry_partial(&bytes, &a, f).is_ok() {
                ok += 1;
                assert!(before - budget.remaining() >= block);
            }
        }
        assert!(ok >= 1 && ok <= limits.max_read_back_bytes / block);
    }

    #[test]
    fn total_work_never_exceeds_the_archive_budget() {
        let limits = XarLimits {
            max_entry_bytes: 700,
            max_read_back_bytes: 6000,
            ..XarLimits::default()
        };
        let bytes = shared_blob_entries(ORDINARY, 30);
        let a = parse(&bytes, &limits).expect("xar");
        let mut budget = ReadBudget::new(&limits);
        let mut spent = 0;
        for (i, f) in a.files.iter().enumerate() {
            budget.start_entry(a.files.len() - i);
            let cap = budget.entry_cap();
            let before = budget.remaining();
            let allowance = before / (a.files.len() - i);
            if let Ok((out, _)) = budget.read_entry_partial(&bytes, &a, f) {
                assert!(out.len() <= cap.min(limits.max_entry_bytes));
            }
            assert!(before - budget.remaining() <= allowance);
            spent += before - budget.remaining();
            assert!(spent <= limits.max_read_back_bytes);
            assert_eq!(spent, limits.max_read_back_bytes - budget.remaining());
        }
    }

    #[test]
    fn a_bzip2_bomb_entry_is_stopped_by_the_entry_budget() {
        let limits = XarLimits {
            max_entry_bytes: 1 << 20,
            ..XarLimits::default()
        };
        assert_eq!(
            read_single(include_bytes!("../testdata/bzip2/bomb.in"), &limits),
            Err(XarEntryError::Undecodable(DecodeError::BudgetExceeded))
        );
    }

    /// libxar extracts only the first stream and ignores what follows.
    #[test]
    fn a_bzip2_entry_followed_by_junk_decodes_the_first_stream() {
        let mut blob = include_bytes!("../testdata/bzip2/hello.in").to_vec();
        blob.extend_from_slice(b"\x00\x01 trailing junk");
        assert_eq!(
            read_single(&blob, &XarLimits::default()),
            Ok(b"hello".to_vec())
        );
    }

    #[test]
    fn a_heap_entry_bomb_is_stopped_by_the_entry_budget() {
        let limits = XarLimits {
            max_entry_bytes: 64 * 1024,
            ..XarLimits::default()
        };
        let a = parse(adversarial!("heap_entry_bomb"), &limits).expect("xar");
        let f = a.files.first().expect("one entry");
        assert_eq!(
            read_entry(adversarial!("heap_entry_bomb"), &a, f, &limits),
            Err(XarEntryError::Undecodable(DecodeError::BudgetExceeded))
        );
    }

    /// A heap pointer past the end of the buffer is a completeness problem, not
    /// evidence (§10, §11.8).
    #[test]
    fn heap_pointers_outside_the_buffer_are_out_of_range() {
        for name in ["heap_past_eof", "offset_overflow"] {
            let bytes = adversarial_vectors()
                .into_iter()
                .find(|(n, _)| *n == name)
                .map(|(_, b)| b)
                .expect("vector");
            let Some(a) = parse(bytes, &XarLimits::default()) else {
                continue;
            };
            for f in &a.files {
                if f.offset.is_some() && f.length.is_some() {
                    assert_eq!(
                        read_entry(bytes, &a, f, &XarLimits::default()),
                        Err(XarEntryError::OutOfRange),
                        "{name}/{}",
                        f.path
                    );
                }
            }
        }
    }

    /// Truncation (like a bounded read stopping short) may change what is
    /// *available*, but never what an entry decodes to — anything that still
    /// reads back must be byte-identical to the whole-file read.
    #[test]
    fn truncation_changes_availability_not_content() {
        let full = pkg!("benign");
        let whole = parse(full, &XarLimits::default()).expect("xar");
        let mut recovered = 0usize;

        for n in (0..full.len()).step_by(7) {
            let Some(a) = parse(&full[..n], &XarLimits::default()) else {
                continue;
            };
            for f in &a.files {
                let Ok(bytes) = read_entry(&full[..n], &a, f, &XarLimits::default()) else {
                    continue; // unavailable at this truncation, which is fine
                };
                let reference = whole
                    .files
                    .iter()
                    .find(|w| w.path == f.path)
                    .and_then(|w| read_entry(full, &whole, w, &XarLimits::default()).ok())
                    .expect("entry should be readable from the whole package");
                assert_eq!(bytes, reference, "{} at truncation {n}", f.path);
                recovered += 1;
            }
        }
        // Guard against the test passing vacuously.
        assert!(recovered > 0, "no truncated read ever succeeded");
    }

    #[test]
    fn byte_corruption_never_panics_or_hangs() {
        let mut corpus: Vec<&[u8]> = adversarial_vectors().into_iter().map(|(_, b)| b).collect();
        corpus.push(pkg!("benign"));
        corpus.push(pkg!("product"));
        // Tight ceilings — the test only checks for panics/hangs, and the
        // wide/deep vectors are expensive to walk in full for no extra reach.
        let limits = XarLimits {
            max_toc_bytes: 64 * 1024,
            max_entries: 64,
            max_depth: 4,
            max_entry_bytes: 16 * 1024,
            ..XarLimits::default()
        };
        for bytes in corpus {
            for i in (0..bytes.len().min(900)).step_by(5) {
                for bit in [0u8, 4, 7] {
                    let mut v = bytes.to_vec();
                    if let Some(b) = v.get_mut(i) {
                        *b ^= 1 << bit;
                    }
                    let _ = parse(&v, &limits);
                }
            }
        }
    }

    #[test]
    fn numeric_text_is_strict() {
        assert_eq!(parse_u64(b"1234"), Some(1234));
        assert_eq!(parse_u64(b"  42 "), Some(42));
        assert_eq!(parse_u64(b""), None);
        assert_eq!(parse_u64(b"12a"), None);
        assert_eq!(parse_u64(b"-1"), None);
        assert_eq!(parse_u64(b"99999999999999999999999"), None);
    }

    use super::toc_xar_bytes;

    fn toc_archive(toc_body: &str) -> XarArchive {
        parse(&toc_xar_bytes(toc_body), &XarLimits::default()).expect("xar")
    }

    /// Only a `<toc>`-level `<signature>` is recorded, with its own
    /// offset/size; a nested one is ignored and never fills them in.
    #[test]
    fn only_a_top_level_signature_is_recorded() {
        let nested = toc_archive(
            r#"<file id="1"><name>x</name><signature style="RSA"><offset>1</offset><size>2</size></signature></file>"#,
        );
        assert!(nested.is_complete());
        assert!(nested.signature.is_none());

        let top =
            toc_archive(r#"<signature style="RSA"><offset>0</offset><size>256</size></signature>"#);
        let sig = top.signature.expect("top-level signature");
        assert_eq!((sig.offset, sig.size), (Some(0), Some(256)));

        let both = toc_archive(
            r#"<signature style="RSA"><offset>5</offset><size>6</size></signature><file id="1"><name>x</name><signature style="RSA"><offset>1</offset><size>2</size></signature></file>"#,
        );
        let sig = both.signature.expect("top-level signature");
        assert_eq!((sig.offset, sig.size), (Some(5), Some(6)));
    }

    /// Recording is by depth (`<xar><toc>`), not by parent name, and a later
    /// `<signature>` never overwrites the first one's fields.
    #[test]
    fn only_the_root_tocs_first_signature_is_recorded() {
        let nested_toc = toc_archive(
            r#"<file id="1"><toc><signature style="RSA"><offset>0</offset><size>8</size></signature></toc></file>"#,
        );
        assert!(nested_toc.signature.is_none());

        let bare_then_valid = toc_archive(
            r#"<signature style="RSA"/><signature style="RSA"><offset>0</offset><size>8</size></signature>"#,
        );
        let sig = bare_then_valid.signature.as_ref().expect("first signature");
        assert_eq!((sig.offset, sig.size), (None, None));
        assert!(!bare_then_valid.has_plausible_signature(u64::MAX));
    }

    #[test]
    fn plausible_signature_needs_offset_size_and_range() {
        let a =
            toc_archive(r#"<signature style="RSA"><offset>0</offset><size>10</size></signature>"#);
        let end = a.heap_start + 10;
        assert!(a.has_plausible_signature(end));
        assert!(!a.has_plausible_signature(end - 1));
        for body in [
            r#"<signature style="RSA"/>"#,
            r#"<signature style="RSA"><offset>0</offset></signature>"#,
            r#"<signature style="RSA"><offset>0</offset><size>0</size></signature>"#,
            r#"<signature style="RSA"><offset>18446744073709551615</offset><size>2</size></signature>"#,
        ] {
            assert!(
                !toc_archive(body).has_plausible_signature(u64::MAX),
                "{body}"
            );
        }
    }
}
