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
//!   [`read_entry`] dispatches on the leading bytes.
//!
//! Hand-written per §3. XML goes through [`crate::xml`], shared with the plist
//! reader so there is only one XML implementation to fuzz.

use crate::inflate::{self, InflateError};
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
}

impl Default for XarLimits {
    fn default() -> Self {
        XarLimits {
            max_toc_bytes: 8 * 1024 * 1024,
            max_entries: 10_000,
            max_depth: 4,
            max_entry_bytes: 4 * 1024 * 1024,
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

/// A `<signature>` block in the TOC.
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
    Undecodable(InflateError),
}

/// Parse a xar container's header and table of contents.
///
/// `None` only when `data` doesn't start with the xar magic (not a package).
/// Once the magic matches, every later failure yields an archive carrying a
/// [`XarHalt`] — the header and recovered entries are still evidence.
pub fn parse(data: &[u8], limits: &XarLimits) -> Option<XarArchive> {
    if be_u32(data, 0)? != XAR_MAGIC {
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
        Err(InflateError::BudgetExceeded) => {
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
    let raw = data.get(start..end).ok_or(XarEntryError::OutOfRange)?;

    // Dispatch on the bytes, not the `encoding` attribute (see module docs).
    if raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
        inflate::gzip_decompress(raw, limits.max_entry_bytes).map_err(XarEntryError::Undecodable)
    } else if raw.first().is_some_and(|b| b & 0x0f == 8) {
        // Plausible zlib CMF; if the header checks fail, treat it as stored.
        match inflate::zlib_decompress(raw, limits.max_entry_bytes) {
            Ok(v) => Ok(v),
            Err(InflateError::BadHeader) => stored(raw, limits),
            Err(e) => Err(XarEntryError::Undecodable(e)),
        }
    } else {
        stored(raw, limits)
    }
}

/// An entry stored without compression, subject to the same ceiling.
fn stored(raw: &[u8], limits: &XarLimits) -> Result<Vec<u8>, XarEntryError> {
    if raw.len() > limits.max_entry_bytes {
        return Err(XarEntryError::Undecodable(InflateError::BudgetExceeded));
    }
    Ok(raw.to_vec())
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
                    "signature" if sig.is_none() => {
                        sig = Some(XarSignature {
                            style: xml::attr(attrs, "style").unwrap_or_default(),
                            offset: None,
                            size: None,
                        });
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

                // Signature offset/size, which sit under <signature>.
                if parent == Some("signature") {
                    if let Some(s) = sig.as_mut() {
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
            Err(XarEntryError::Undecodable(InflateError::BudgetExceeded))
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
}
