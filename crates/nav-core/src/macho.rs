//! Minimal, defensive Mach-O parsing (§5.2, §12 Phase 0a): recognizes a thin
//! or fat/universal image and extracts the structural facts the
//! `macho-loader-anomaly` rule and the entropy rule need — the file range of
//! `__TEXT,__text`, dylib/rpath load paths, whether a code signature is
//! present, and any embedded entitlements plist.
//!
//! Parses attacker-controlled input under the §3/§11.9 discipline — no panics,
//! no unbounded reads, every offset bounds-checked, no external crate. Not a
//! general Mach-O reader: it walks the load command table and a signature
//! SuperBlob it can bound, and returns `None`/empty for anything it can't
//! recognize or bound.
//!
//! [`parse`]/[`parse_all`]/[`parse_all_slices`] work over an in-memory
//! buffer (typically a capped prefix) and so lose slices/signatures past its
//! end. [`scan_ranged`] instead reads exactly the regions it needs — headers,
//! load commands, code signatures — from their real offsets via
//! [`ByteSource`], so a file bigger than any in-memory capture is still fully
//! examined (§5.2, #45).

use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;

// Magic read big-endian from the first four bytes. A little-endian file (every
// current arch) stores MH_MAGIC_64 as `CF FA ED FE` => BE `0xCFFAEDFE`, the
// CIGAM ("swapped") constant. Matching all four thin constants recovers both
// word size and endianness in one path.
const MH_MAGIC: u32 = 0xfeed_face; // 32-bit, big-endian file
const MH_CIGAM: u32 = 0xcefa_edfe; // 32-bit, little-endian file
const MH_MAGIC_64: u32 = 0xfeed_facf; // 64-bit, big-endian file
const MH_CIGAM_64: u32 = 0xcffa_edfe; // 64-bit, little-endian file
const FAT_MAGIC: u32 = 0xcafe_babe; // universal binary; arch table is big-endian
const FAT_MAGIC_64: u32 = 0xcafe_babf;

const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;
const LC_LOAD_DYLIB: u32 = 0x0c;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_RPATH: u32 = 0x8000_001c;
const LC_CODE_SIGNATURE: u32 = 0x1d;

// Code signature SuperBlob magics (`<Security/CSCommon.h>` / cs_blobs.h) —
// always big-endian, independent of the Mach-O's own endianness.
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
/// `CSMAGIC_BLOBWRAPPER`: wraps the CMS (identity) signature blob.
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;

// CS_BlobIndex slot types (cs_blobs.h) identifying a blob's role within the
// SuperBlob.
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_ENTITLEMENTS: u32 = 5;
// XNU also accepts a CodeDirectory in any of 5 "alternate" slots (cs_blobs.h:
// CSSLOT_ALTERNATE_CODEDIRECTORIES..+MAX_CODE_DIRECTORIES), used for a
// signature carrying more than one digest algorithm's CodeDirectory. A
// binary's *only* CodeDirectory can legally sit here, not just in slot 0.
const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
const MAX_ALTERNATE_CODEDIRECTORIES: u32 = 5;
/// `CSSLOT_SIGNATURESLOT`: holds the CMS blob wrapper carrying the actual
/// signing identity's certificate chain, when there is one.
const CSSLOT_SIGNATURESLOT: u32 = 0x10000;

/// `CS_ADHOC`, from `<Security/CSCommon.h>`'s `CodeDirectory` flag bits:
/// ad-hoc signed, no real identity. Shared by the `codesign`-backed rules
/// (parsed from `codesign -dv` text) and `macho-loader-anomaly` (read
/// straight from a CodeDirectory's `flags` field here).
pub(crate) const CS_ADHOC: u32 = 0x2;
/// `CS_LINKER_SIGNED`, from `<Security/CSCommon.h>`'s `CodeDirectory` flag
/// bits: the automatic ad-hoc signature the linker stamps on at build time,
/// as distinct from a hand-applied one.
pub(crate) const CS_LINKER_SIGNED: u32 = 0x20000;

// Loop ceilings — far above any real Mach-O, but bound work on hostile input.
const MAX_NCMDS: u32 = 4096;
const MAX_NSECTS: u32 = 4096;
const MAX_DYLIBS: usize = 4096;
const MAX_RPATHS: usize = 256;
const MAX_LC_STR_BYTES: usize = 4096;
const MAX_CS_BLOBS: u32 = 256;
const MAX_ENTITLEMENTS_BYTES: usize = 256 * 1024;
// Bounds work on hostile input; far above what the kernel accepts (a real fat
// binary the kernel will run has been seen with dozens of bogus arch entries
// alongside the real slice, #46) — don't lower it to exclude other formats,
// an arch-count cap can hide a runnable binary.
const MAX_FAT_ARCHES: u32 = 1024;
/// A slice declaring more load-command bytes than this is unwalkable by
/// offset once its load commands extend past what [`ByteSource::held_len`]
/// already holds — [`scan_ranged`] skips the slice rather than read that much
/// by offset. Doesn't bound a slice whose load commands are already in
/// memory; there's no I/O to cap.
const MAX_SIZEOFCMDS: usize = 2 * 1024 * 1024;
/// Largest `LC_CODE_SIGNATURE` region [`scan_ranged`] will read by offset.
pub(crate) const MAX_SIGNATURE_BYTES: usize = 16 * 1024 * 1024;
/// Total bytes one [`scan_ranged`] call may read across every slice and
/// signature; once exhausted, remaining slices count as skipped.
const MAX_RANGED_BYTES: u64 = 64 * 1024 * 1024;

/// A recognized Mach-O image: `__TEXT,__text`'s file range plus the loader
/// facts (`dylibs`/`rpaths`/`has_code_signature`/`entitlements`) the
/// structural-anomaly rule scores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOImage {
    /// True if this image was selected out of a fat/universal binary.
    pub is_fat: bool,
    /// True for a 64-bit image (`MH_MAGIC_64`/`MH_CIGAM_64`).
    pub is_64: bool,
    /// Absolute file-offset range of `__TEXT,__text`, or the `__TEXT` segment's
    /// own range if the section can't be located. Offsets into the whole file —
    /// a caller with a bounded read must clip against what it holds. `None` if
    /// `__TEXT` has no on-disk content.
    pub text_range: Option<Range<u64>>,
    /// Load paths from `LC_LOAD_DYLIB` and its weak/lazy/upward/reexport
    /// variants, in load-command order. Capped at `MAX_DYLIBS`.
    pub dylibs: Vec<String>,
    /// Paths from `LC_RPATH`, in load-command order. Capped at `MAX_RPATHS`.
    pub rpaths: Vec<String>,
    /// Whether an `LC_CODE_SIGNATURE` load command is present — independent
    /// of whether its signature blob could actually be read.
    pub has_code_signature: bool,
    /// Entitlements plist bytes recovered from the embedded code signature.
    /// `None` means "couldn't determine," never "no entitlements": it covers
    /// no signature, no entitlements blob in the SuperBlob, and a signature
    /// region lying past the bytes this parser holds (a truncated capture).
    pub entitlements: Option<Vec<u8>>,
    /// Bitwise OR of `flags` (`CS_ADHOC` etc., `<Security/CSCommon.h>`) across
    /// every CodeDirectory found in the embedded code signature's
    /// SuperBlob — slot 0 and the 5 alternate CodeDirectory slots XNU also
    /// accepts (`0x1000`..`0x1005`, cs_blobs.h), since an attacker can put
    /// its only ad-hoc CodeDirectory in an alternate slot. `None` if there's
    /// no signature, no CodeDirectory found, or the signature region lies
    /// past the bytes this parser holds — never read as "not ad-hoc".
    pub code_directory_flags: Option<u32>,
    /// Whether the signature's SuperBlob contains a non-empty CMS blob
    /// wrapper (`CSSLOT_SIGNATURESLOT`/`CSMAGIC_BLOBWRAPPER`, length > 8): a
    /// real identity signature carries certificate data there, a hand
    /// ad-hoc signature has the wrapper but empty, and a linker signature
    /// has none. Only meaningful when `code_directory_flags` is `Some` —
    /// otherwise the signature region couldn't be read at all.
    pub has_cms_signature: bool,
    /// True when the whole `LC_CODE_SIGNATURE` region (`dataoff..dataoff+
    /// datasize`, slice-relative) was within the bytes this parse held.
    /// False when there's no signature, or the region wasn't held — a
    /// truncated prefix, or [`scan_ranged`] skipping it for size/budget.
    pub signature_region_read: bool,
    /// Slice-relative `LC_CODE_SIGNATURE` `(dataoff, datasize)`, so
    /// [`scan_ranged`] can find and re-read the region by absolute offset.
    /// `None` if there's no `LC_CODE_SIGNATURE` load command.
    pub code_signature: Option<(u32, u32)>,
}

/// Uniform access to file-like bytes for offset-based parsing
/// ([`scan_ranged`]): shared by `[u8]` (a whole in-memory buffer — tests, the
/// fuzz target) and [`crate::context::ScanContext`] (reads through the
/// scan's own file handle past its in-memory prefix).
pub trait ByteSource {
    /// Total length of the underlying object.
    fn source_len(&self) -> u64;
    /// Leading bytes already resident in memory — readable at no I/O cost.
    /// `0` by default. `[u8]` overrides this to its whole length (it's all
    /// memory already); [`crate::context::ScanContext`] to `content`'s
    /// length. [`read_budgeted`] only charges a read for the part of its
    /// range beyond this.
    fn held_len(&self) -> u64 {
        0
    }
    /// Whether [`Self::source_len`] is the object's true total size. `true`
    /// by default. `false` for a capture that stopped short of the real
    /// object's end (an embedded/container member extracted only up to a
    /// budget): an offset past `source_len` there may still land on real
    /// data this source just doesn't have — see [`scan_ranged_fat`].
    fn source_len_is_authoritative(&self) -> bool {
        true
    }
    /// Reads exactly `len` bytes starting at `off`, or `None` if the range
    /// doesn't fit or the read fails. Borrows straight from memory already
    /// held when the whole range lies inside it, rather than copying — a
    /// single slice's header/signature reads can number in the thousands on
    /// hostile input (§5.2, #45 perf follow-up, PR #52 review).
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

/// Parse `data` as a single Mach-O image: the thin image, or the **first**
/// walkable slice of a fat/universal binary. `None` for non-Mach-O input,
/// truncated stubs, or a Java `.class` (which shares fat's `0xCAFEBABE`).
///
/// For a fat binary this returns only one slice, which is fine for callers
/// that need a single representative view (entropy's `__TEXT` sampling). A
/// caller establishing a *verdict* on the binary must use [`parse_all`]
/// instead — judging a universal binary on one slice lets a malicious slice
/// hide behind a benign one (§5.2).
pub fn parse(data: &[u8]) -> Option<MachOImage> {
    match be_u32(data, 0) {
        Some(FAT_MAGIC) | Some(FAT_MAGIC_64) => parse_first_fat_slice(data),
        Some(magic) => {
            let (is_64, be) = thin_kind(magic)?;
            parse_thin(data, 0, is_64, be, false)
        }
        None => None,
    }
}

/// The first walkable slice of a fat/universal binary's arch table, or
/// `None` if none is — stops as soon as one is found, so a hostile table
/// with many arches (up to `MAX_FAT_ARCHES`) costs one `parse_thin` call
/// here, not one per declared arch.
fn parse_first_fat_slice(data: &[u8]) -> Option<MachOImage> {
    let (is_64, nfat) = plausible_fat_header(data, false)?;
    (0..nfat as usize).find_map(|i| {
        let obj_off = fat_arch_offset(data, is_64, i)?;
        parse_fat_slice_at(data, obj_off)
    })
}

/// Parse **every** Mach-O image in `data`: a single thin image, or all
/// architecture slices of a fat/universal binary this parser can walk, in
/// fat-table order. Empty for non-Mach-O input, a truncated stub, or a fat
/// container with no walkable slice (incl. a Java `.class`). Structure rules
/// iterate this so a fat binary is judged on all its slices, not just the
/// first (§5.2). A thin wrapper over [`parse_all_slices`] for callers that
/// don't need the skipped-arch count or a truncation-aware fat/non-fat call;
/// treats `data` as a complete read.
pub fn parse_all(data: &[u8]) -> Vec<MachOImage> {
    parse_all_slices(data, false).0
}

/// As [`parse_all`], plus the number of *declared* fat-table arches that
/// couldn't be walked (bad table entry, an offset past the bytes held, a
/// non-Mach-O slice magic, or a `parse_thin` failure) — nonzero here means a
/// slice's contents genuinely couldn't be judged, not that there was nothing
/// to judge. Always `0` for thin input or non-Mach-O input, since neither
/// declares a slice count to compare against. `truncated` must match what
/// [`is_macho_magic`] was told for the same bytes — see there for why it
/// matters for a fat header.
pub fn parse_all_slices(data: &[u8], truncated: bool) -> (Vec<MachOImage>, usize) {
    match be_u32(data, 0) {
        Some(FAT_MAGIC) | Some(FAT_MAGIC_64) => parse_fat_all(data, truncated),
        Some(magic) => match thin_kind(magic) {
            Some((is_64, be)) => (
                parse_thin(data, 0, is_64, be, false).into_iter().collect(),
                0,
            ),
            None => (Vec::new(), 0),
        },
        None => (Vec::new(), 0),
    }
}

/// Whether `data` begins with any Mach-O magic (thin, either word size/endian,
/// or fat). Cheaper and broader than [`parse`] — answers "is this a code object
/// at all", including images `parse` declines to walk.
///
/// `truncated` is whether `data` is a partial read of a larger file (§10/
/// §11.8): for a fat header, a declared arch whose offset lands past `data`
/// is only counted as a real slice when the read was truncated — otherwise a
/// short, complete read (e.g. a whole Java `.class` file) correctly finds no
/// evidence rather than being read as "couldn't check, assume Mach-O."
pub fn is_macho_magic(data: &[u8], truncated: bool) -> bool {
    match be_u32(data, 0) {
        Some(FAT_MAGIC) | Some(FAT_MAGIC_64) => plausible_fat_header(data, truncated).is_some(),
        Some(magic) => thin_kind(magic).is_some(),
        None => false,
    }
}

/// Map a first-word magic to `(is_64, big_endian)`, or `None` if it isn't a
/// thin Mach-O magic.
fn thin_kind(magic: u32) -> Option<(bool, bool)> {
    match magic {
        MH_MAGIC => Some((false, true)),
        MH_CIGAM => Some((false, false)),
        MH_MAGIC_64 => Some((true, true)),
        MH_CIGAM_64 => Some((true, false)),
        _ => None,
    }
}

/// Recognize a plausible fat/universal Mach-O header: `FAT_MAGIC`/
/// `FAT_MAGIC_64` with `0 < nfat_arch <= MAX_FAT_ARCHES`, and at least one
/// declared arch that's real evidence of a Mach-O slice rather than a Java
/// `.class` file's constant pool sharing `FAT_MAGIC` — see
/// [`fat_references_real_slice`]. Returns `(is_64, nfat_arch)`.
fn plausible_fat_header(data: &[u8], truncated: bool) -> Option<(bool, u32)> {
    let is_64 = match be_u32(data, 0)? {
        FAT_MAGIC => false,
        FAT_MAGIC_64 => true,
        _ => return None,
    };
    // fat_header (always big-endian): magic(4), nfat_arch(4).
    let nfat = be_u32(data, 4).filter(|&n| n != 0 && n <= MAX_FAT_ARCHES)?;
    fat_references_real_slice(data, is_64, nfat, truncated).then_some((is_64, nfat))
}

/// True if the fat table's `nfat` declared arches contain real evidence of a
/// Mach-O slice: an entry whose offset field we can read points at a thin
/// Mach-O magic within `data`, or — only when `truncated` — points past the
/// bytes held (the slice may lie beyond what this capture holds; "couldn't
/// check" must not become "not a Mach-O", §11.8). A Java `.class` file has
/// constant-pool bytes sitting where the arch table would be, which won't
/// point at a Mach-O magic, so a non-truncated read of one finds nothing
/// here.
fn fat_references_real_slice(data: &[u8], is_64: bool, nfat: u32, truncated: bool) -> bool {
    for i in 0..nfat as usize {
        let Some(obj_off) = fat_arch_offset(data, is_64, i) else {
            continue; // entry's own bytes lie outside what we hold
        };
        match usize::try_from(obj_off) {
            Ok(off) if off < data.len() => {
                if be_u32(data, off).and_then(thin_kind).is_some() {
                    return true;
                }
            }
            _ if truncated => return true,
            _ => {}
        }
    }
    false
}

/// Walk every arch of a fat/universal binary, collecting the slices this
/// parser can read (in fat-table order) plus how many declared arches
/// couldn't be. `(empty, 0)` for an implausible fat header (incl. a Java
/// `.class`, see [`plausible_fat_header`]) — there's no declared arch count
/// to trust in that case, so it's "not a fat binary," not "every arch
/// skipped."
fn parse_fat_all(data: &[u8], truncated: bool) -> (Vec<MachOImage>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0usize;
    let Some((is_64, nfat)) = plausible_fat_header(data, truncated) else {
        return (out, skipped);
    };

    // Distinct slice offsets walked so far: a hostile table can point
    // MAX_FAT_ARCHES (1024) entries at one offset, and each `MachOImage`
    // owns up to MAX_ENTITLEMENTS_BYTES — walking (and pushing) the same
    // slice once per referring entry would be unbounded work for one file.
    // Entries sharing an offset are one slice, not N: only the first is
    // walked and pushed; later ones reuse that outcome, so a duplicate of a
    // *walkable* slice is never counted in `skipped` (it's not unwalked —
    // it just wasn't re-walked), while a duplicate of an offset that failed
    // to walk still counts, once per declared arch, like any other failure.
    let mut seen: HashMap<u64, bool> = HashMap::new(); // offset -> walked ok?
    for i in 0..nfat as usize {
        let Some(obj_off) = fat_arch_offset(data, is_64, i) else {
            skipped += 1; // this entry's own bytes lie outside what we hold
            continue;
        };
        match seen.get(&obj_off) {
            Some(true) => {}
            Some(false) => skipped += 1,
            None => match parse_fat_slice_at(data, obj_off) {
                Some(img) => {
                    seen.insert(obj_off, true);
                    out.push(img);
                }
                None => {
                    seen.insert(obj_off, false);
                    skipped += 1;
                }
            },
        }
    }
    (out, skipped)
}

/// Read fat arch `i`'s declared object-file offset (the `fat_arch`/
/// `fat_arch_64` `offset` field), or `None` if that entry's own bytes lie
/// outside `data`. `is_64` selects the table's entry stride (`fat_arch_64`
/// is wider than `fat_arch`) as well as the offset field's own width.
fn fat_arch_offset(data: &[u8], is_64: bool, i: usize) -> Option<u64> {
    // fat_arch: cputype(4), cpusubtype(4), offset, size, align[, reserved].
    let stride: usize = if is_64 { 32 } else { 20 };
    let arch_off = 8usize.checked_add(i.checked_mul(stride)?)?;
    if is_64 {
        be_u64(data, arch_off.checked_add(8)?)
    } else {
        be_u32(data, arch_off.checked_add(8)?).map(u64::from)
    }
}

/// Parse the fat/universal slice at absolute offset `obj_off` within `data`,
/// or `None` if the offset lies outside the bytes held or doesn't begin with
/// a thin Mach-O magic. Keyed only by offset (not by which arch-table entry
/// pointed here) so callers can dedupe entries that share one offset.
fn parse_fat_slice_at(data: &[u8], obj_off: u64) -> Option<MachOImage> {
    // Slice must start within the bytes we hold (and not overflow usize).
    let base = match usize::try_from(obj_off) {
        Ok(b) if b < data.len() => b,
        _ => return None,
    };

    let (is_64_thin, be) = be_u32(data, base).and_then(thin_kind)?;
    parse_thin(data, base, is_64_thin, be, true)
}

/// Result of an offset-based scan ([`scan_ranged`]): every slice this parser
/// could walk by reading exactly the regions it needed from anywhere in the
/// source, not just an in-memory prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOScan {
    /// Whether the source begins with, or (for a fat file) references, a
    /// Mach-O image at all.
    pub is_macho: bool,
    /// Every slice this parser could walk, in fat-table order (or the single
    /// thin image).
    pub images: Vec<MachOImage>,
    /// Declared fat-table arches that couldn't be walked at all, or read
    /// failures hit while walking one (bad offset, unwalkable header, budget
    /// exhaustion) — never silently treated as clean.
    pub skipped_slices: usize,
}

impl MachOScan {
    /// True only if every slice was walkable and every slice's held code
    /// signature was read in full — nothing was skipped, and no
    /// `LC_CODE_SIGNATURE` region went unread.
    pub fn fully_examined(&self) -> bool {
        self.is_macho
            && !self.images.is_empty()
            && self.skipped_slices == 0
            && self
                .images
                .iter()
                .all(|i| !i.has_code_signature || i.signature_region_read)
    }
}

fn not_macho_scan() -> MachOScan {
    MachOScan {
        is_macho: false,
        images: Vec::new(),
        skipped_slices: 0,
    }
}

/// Bytes one [`scan_ranged`] call may still read, charged across every slice
/// and signature it reads — bounds total work on a hostile fat table, not
/// just a single slice.
struct RangeBudget {
    remaining: u64,
}

impl RangeBudget {
    fn take(&mut self, want: u64) -> bool {
        match self.remaining.checked_sub(want) {
            Some(rest) => {
                self.remaining = rest;
                true
            }
            None => false,
        }
    }
}

/// Reads `len` bytes at `off` through `src`, charging `budget` only for the
/// part of `[off, off+len)` beyond `src.held_len()` — bytes already resident
/// in memory cost nothing to re-read. Refuses the read up front if the
/// chargeable part alone would exceed the remaining budget.
fn read_budgeted<'a>(
    src: &'a (impl ByteSource + ?Sized),
    budget: &mut RangeBudget,
    off: u64,
    len: usize,
) -> Option<Cow<'a, [u8]>> {
    let end = off.checked_add(len as u64)?;
    let held = src.held_len();
    let chargeable = end.saturating_sub(held.max(off));
    if !budget.take(chargeable) {
        return None;
    }
    src.read_range(off, len)
}

/// Parse every Mach-O image in `src` by reading exactly the bytes needed from
/// their real, absolute offsets — the header and load commands of each
/// slice, and each slice's code signature (typically near EOF) — rather than
/// [`parse_all_slices`]'s in-memory prefix, which loses both for a file
/// bigger than the capture (§5.2, #45).
pub fn scan_ranged(src: &(impl ByteSource + ?Sized)) -> MachOScan {
    let source_len = src.source_len();
    let mut budget = RangeBudget {
        remaining: MAX_RANGED_BYTES,
    };

    let head_len = (8u64.saturating_add(MAX_FAT_ARCHES as u64 * 32)).min(source_len) as usize;
    let head = match read_budgeted(src, &mut budget, 0, head_len) {
        Some(head) => head,
        // The full head couldn't be read — e.g. `source_len` is stale (the
        // real object shrank after it was captured) and there's no handle to
        // serve the rest. Fall back to whatever's already held in memory
        // rather than reading a read failure as "not Mach-O" (§10/§11.8).
        None => match read_budgeted(
            src,
            &mut budget,
            0,
            src.held_len().min(head_len as u64) as usize,
        ) {
            Some(head) if head.len() >= 4 => head,
            _ => return not_macho_scan(),
        },
    };

    match be_u32(&head, 0) {
        Some(FAT_MAGIC) | Some(FAT_MAGIC_64) => {
            scan_ranged_fat(src, &head, source_len, &mut budget)
        }
        Some(magic) => match thin_kind(magic) {
            Some(_) => match scan_ranged_slice(src, 0, false, source_len, &mut budget) {
                Some(image) => MachOScan {
                    is_macho: true,
                    images: vec![image],
                    skipped_slices: 0,
                },
                // Recognized magic, but the structure itself couldn't be
                // walked (the same short-head situation, or a genuinely
                // malformed slice) — still Mach-O, not clean.
                None => MachOScan {
                    is_macho: true,
                    images: Vec::new(),
                    skipped_slices: 1,
                },
            },
            None => not_macho_scan(),
        },
        None => not_macho_scan(),
    }
}

/// Whether a declared fat-table offset could be confirmed to start a thin
/// Mach-O slice — see [`classify_slice_magic`].
enum SliceMagic {
    /// Read (or otherwise confirmed) to be a real thin Mach-O magic.
    Real,
    /// Read (or ruled out via an authoritative `source_len`) and it isn't.
    NotMacho,
    /// Couldn't tell: the read failed (I/O error, non-unix, budget), or the
    /// offset lies past a `source_len` that isn't authoritative — a real
    /// slice may still exist there. Never treated as "not Mach-O" (§10/
    /// §11.8).
    Undetermined,
}

/// Classify what's at a declared fat-table offset without assuming a read
/// failure or an out-of-bounds offset means "no slice here" — see
/// [`SliceMagic`].
fn classify_slice_magic(
    src: &(impl ByteSource + ?Sized),
    budget: &mut RangeBudget,
    off: u64,
    source_len: u64,
) -> SliceMagic {
    if off >= source_len {
        return if src.source_len_is_authoritative() {
            SliceMagic::NotMacho
        } else {
            SliceMagic::Undetermined
        };
    }
    match read_budgeted(src, budget, off, 4) {
        Some(bytes) if be_u32(&bytes, 0).and_then(thin_kind).is_some() => SliceMagic::Real,
        Some(_) => SliceMagic::NotMacho,
        None => SliceMagic::Undetermined,
    }
}

/// Walk a fat/universal binary's arch table by offset. `is_macho` only if
/// some declared offset is confirmed to hold a thin Mach-O magic, read via
/// `read_range` — which keeps a Java `.class` file (#46) non-Mach-O. If none
/// is confirmed but at least one couldn't be determined (a failed read, or
/// an offset past a non-authoritative `source_len` — e.g. a truncated
/// embedded/container member), this still reports `is_macho: true` with
/// those counted as skipped, rather than reading "couldn't check" as "clean"
/// (§10/§11.8, §5.2).
fn scan_ranged_fat(
    src: &(impl ByteSource + ?Sized),
    head: &[u8],
    source_len: u64,
    budget: &mut RangeBudget,
) -> MachOScan {
    let is_64 = match be_u32(head, 0) {
        Some(FAT_MAGIC) => false,
        Some(FAT_MAGIC_64) => true,
        _ => return not_macho_scan(),
    };
    let Some(nfat) = be_u32(head, 4).filter(|&n| n != 0 && n <= MAX_FAT_ARCHES) else {
        // A short head is either a real, complete file too small to hold
        // `nfat_arch` (authoritative `source_len < 8`: genuinely not a fat
        // binary), or a head cut short by a failed/partial read or a
        // non-authoritative length — the table may still exist there,
        // undetermined rather than clean (§10/§11.8).
        return if src.source_len_is_authoritative() && source_len < 8 {
            not_macho_scan()
        } else if head.len() < 8 {
            MachOScan {
                is_macho: true,
                images: Vec::new(),
                skipped_slices: 1,
            }
        } else {
            not_macho_scan()
        };
    };

    let offsets: Vec<Option<u64>> = (0..nfat as usize)
        .map(|i| fat_arch_offset(head, is_64, i))
        .collect();

    let magics: Vec<SliceMagic> = offsets
        .iter()
        .map(|off_opt| match off_opt {
            Some(off) => classify_slice_magic(src, budget, *off, source_len),
            // This entry's own bytes lie outside what we hold — the arch
            // table itself may have been cut short by a non-authoritative
            // capture.
            None if src.source_len_is_authoritative() => SliceMagic::NotMacho,
            None => SliceMagic::Undetermined,
        })
        .collect();

    if !magics.iter().any(|m| matches!(m, SliceMagic::Real)) {
        let undetermined = magics
            .iter()
            .filter(|m| matches!(m, SliceMagic::Undetermined))
            .count();
        return if undetermined == 0 {
            not_macho_scan()
        } else {
            MachOScan {
                is_macho: true,
                images: Vec::new(),
                skipped_slices: undetermined,
            }
        };
    }

    // Dedupe by offset exactly as `parse_fat_all` does: a duplicate of a
    // walkable slice is one slice, not re-walked or counted as skipped; a
    // duplicate of an offset that failed to walk counts again.
    let mut images = Vec::new();
    let mut skipped = 0usize;
    let mut seen: HashMap<u64, bool> = HashMap::new();
    for off_opt in &offsets {
        let Some(off) = *off_opt else {
            skipped += 1; // this entry's own bytes lie outside what we hold
            continue;
        };
        match seen.get(&off) {
            Some(true) => {}
            Some(false) => skipped += 1,
            None => match scan_ranged_slice(src, off, true, source_len, budget) {
                Some(img) => {
                    seen.insert(off, true);
                    images.push(img);
                }
                None => {
                    seen.insert(off, false);
                    skipped += 1;
                }
            },
        }
    }

    MachOScan {
        is_macho: true,
        images,
        skipped_slices: skipped,
    }
}

/// Parse the slice at absolute offset `off`: read its header and load
/// commands by offset, capped to `source_len` (a declared `sizeofcmds` can
/// overrun the object itself) and, beyond what's already held, to
/// `MAX_SIZEOFCMDS`; then its code signature by offset if one is declared
/// and fits within `MAX_SIGNATURE_BYTES`/`source_len`/the remaining budget.
/// `None` if the offset is out of bounds, the header/magic doesn't check
/// out, the declared load commands run past a non-authoritative
/// `source_len` (a truncated capture), or `sizeofcmds` is unwalkable — the
/// caller counts that as skipped.
fn scan_ranged_slice(
    src: &(impl ByteSource + ?Sized),
    off: u64,
    is_fat: bool,
    source_len: u64,
    budget: &mut RangeBudget,
) -> Option<MachOImage> {
    if off >= source_len {
        return None;
    }
    let probe_len = 32u64.min(source_len - off) as usize;
    let probe = read_budgeted(src, budget, off, probe_len)?;
    let (is_64, be) = be_u32(&probe, 0).and_then(thin_kind)?;
    let header_size: usize = if is_64 { 32 } else { 28 };
    if probe.len() < header_size {
        return None; // header itself truncated at EOF
    }
    let sizeofcmds = Reader { data: &probe, be }.u32(20)? as usize;
    let cmds_end = off
        .checked_add(header_size as u64)?
        .checked_add(sizeofcmds as u64)?;
    if cmds_end > source_len && !src.source_len_is_authoritative() {
        // Declared load commands run past a capture that stopped short of
        // the real object's end (a truncated embedded/container member) —
        // what's cut off could hold anything; skip rather than silently
        // treat it as absent (§10/§11.8).
        return None;
    }
    // Cap `cmds_end` to what the source actually has before comparing
    // against `held_len`: a slice on a complete file can declare far more
    // load-command bytes than the file itself has left, and none of that
    // excess is real I/O to bound — there's simply nothing there to read.
    let walk_end = cmds_end.min(source_len);
    if walk_end > src.held_len() && sizeofcmds > MAX_SIZEOFCMDS {
        // Far more load-command bytes than any real image declares, and at
        // least some of them require real I/O past what's already in
        // memory.
        return None;
    }

    let want = (walk_end - off) as usize;
    let buf = read_budgeted(src, budget, off, want)?;
    let mut image = parse_thin(&buf, 0, is_64, be, is_fat)?;

    image.text_range = image.text_range.and_then(|range| {
        let start = off.checked_add(range.start)?;
        let end = off.checked_add(range.end)?;
        Some(start..end)
    });

    if let Some((dataoff, datasize)) = image.code_signature {
        read_signature_ranged(src, off, dataoff, datasize, source_len, budget, &mut image);
    }

    Some(image)
}

/// Read a slice's `LC_CODE_SIGNATURE` region by its real, absolute offset and
/// fill in `image`'s signature facts — the part an in-memory prefix parse
/// can't do once the region lies past what's held. Leaves `image` unchanged
/// (`signature_region_read` stays `false`) if the region is too big, out of
/// bounds, or the budget can't cover it.
fn read_signature_ranged(
    src: &(impl ByteSource + ?Sized),
    slice_off: u64,
    dataoff: u32,
    datasize: u32,
    source_len: u64,
    budget: &mut RangeBudget,
    image: &mut MachOImage,
) {
    if datasize as usize > MAX_SIGNATURE_BYTES {
        return;
    }
    let Some(sig_off) = slice_off.checked_add(dataoff as u64) else {
        return;
    };
    let Some(sig_end) = sig_off.checked_add(datasize as u64) else {
        return;
    };
    if sig_end > source_len {
        return;
    }
    let Some(sig_bytes) = read_budgeted(src, budget, sig_off, datasize as usize) else {
        return;
    };
    let facts = extract_signature_facts_checked(&sig_bytes, 0, 0, datasize).unwrap_or_default();
    image.entitlements = facts.entitlements;
    image.code_directory_flags = facts.code_directory_flags;
    image.has_cms_signature = facts.has_cms_signature;
    image.signature_region_read = true;
}

fn parse_thin(data: &[u8], base: usize, is_64: bool, be: bool, is_fat: bool) -> Option<MachOImage> {
    let r = Reader { data, be };

    // mach_header[_64]: magic(4), cputype(4), cpusubtype(4), filetype(4),
    // ncmds(4), sizeofcmds(4), flags(4)[, reserved(4)].
    let header_size: usize = if is_64 { 32 } else { 28 };
    let ncmds = r.u32(base.checked_add(16)?)?;
    let sizeofcmds = r.u32(base.checked_add(20)?)? as usize;
    if ncmds > MAX_NCMDS {
        return None;
    }

    let cmds_start = base.checked_add(header_size)?;
    // Bound the load-command walk by the smaller of what the header declares
    // and what we captured, so a truncated read can't run off the end.
    let limit = cmds_start.checked_add(sizeofcmds)?.min(data.len());

    let mut text_range = None;
    let mut dylibs = Vec::new();
    let mut rpaths = Vec::new();
    let mut has_code_signature = false;
    let mut entitlements = None;
    let mut code_directory_flags = None;
    let mut has_cms_signature = false;
    let mut code_signature = None;
    let mut signature_region_read = false;

    let mut off = cmds_start;
    for _ in 0..ncmds {
        if off.checked_add(8)? > limit {
            break;
        }
        let cmd = r.u32(off)?;
        let cmdsize = r.u32(off.checked_add(4)?)? as usize;
        if cmdsize < 8 {
            return None; // malformed: a load command can't be smaller than its header
        }
        let cmd_end = off.checked_add(cmdsize)?;
        if cmd_end > limit {
            break;
        }

        let is_segment = (is_64 && cmd == LC_SEGMENT_64) || (!is_64 && cmd == LC_SEGMENT);
        if is_segment && text_range.is_none() {
            text_range = text_segment_range(&r, off, is_64, base);
        } else if is_dylib_load_command(cmd) {
            if dylibs.len() < MAX_DYLIBS {
                if let Some(path) = read_lc_str(&r, off, cmd_end, MAX_LC_STR_BYTES) {
                    dylibs.push(path);
                }
            }
        } else if cmd == LC_RPATH {
            if rpaths.len() < MAX_RPATHS {
                if let Some(path) = read_lc_str(&r, off, cmd_end, MAX_LC_STR_BYTES) {
                    rpaths.push(path);
                }
            }
        } else if cmd == LC_CODE_SIGNATURE {
            if has_code_signature {
                // A second LC_CODE_SIGNATURE has no legitimate meaning and no
                // documented kernel precedence — rather than guess which one
                // wins (and risk a bogus second command silently erasing the
                // real signature's facts, #37), the whole slice is malformed.
                return None;
            }
            has_code_signature = true;
            // linkedit_data_command: cmd(4), cmdsize(4), dataoff(4), datasize(4).
            if let (Some(dataoff), Some(datasize)) =
                (r.u32(off.checked_add(8)?), r.u32(off.checked_add(12)?))
            {
                code_signature = Some((dataoff, datasize));
                let facts = extract_signature_facts(data, base, dataoff, datasize);
                entitlements = facts.entitlements;
                code_directory_flags = facts.code_directory_flags;
                has_cms_signature = facts.has_cms_signature;
                signature_region_read = base
                    .checked_add(dataoff as usize)
                    .and_then(|s| s.checked_add(datasize as usize))
                    .is_some_and(|end| end <= data.len());
            }
        }

        off = cmd_end;
    }

    Some(MachOImage {
        is_fat,
        is_64,
        text_range,
        dylibs,
        rpaths,
        has_code_signature,
        entitlements,
        code_directory_flags,
        has_cms_signature,
        signature_region_read,
        code_signature,
    })
}

/// True for `LC_LOAD_DYLIB` and its weak/lazy/upward/reexport variants — all
/// share the `dylib_command` layout (an `lc_str` path at offset 8).
fn is_dylib_load_command(cmd: u32) -> bool {
    matches!(
        cmd,
        LC_LOAD_DYLIB
            | LC_LOAD_WEAK_DYLIB
            | LC_REEXPORT_DYLIB
            | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB
    )
}

/// Read an `lc_str` string field (a `dylib_command`'s name or a
/// `rpath_command`'s path): a u32 offset at `cmd_off+8`, relative to
/// `cmd_off`, NUL-terminated, running no further than `cmd_end`. `None` if
/// the offset lands outside `[cmd_off, cmd_end)`. Lossy UTF-8, capped at
/// `max_len` bytes so a missing NUL can't read unbounded content.
fn read_lc_str(r: &Reader, cmd_off: usize, cmd_end: usize, max_len: usize) -> Option<String> {
    let rel = r.u32(cmd_off.checked_add(8)?)? as usize;
    let start = cmd_off.checked_add(rel)?;
    if start >= cmd_end {
        return None;
    }
    let cap_end = cmd_end.min(start.checked_add(max_len)?);
    let bytes = r.data.get(start..cap_end)?;
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..len]).into_owned())
}

/// Facts recovered from a Mach-O's embedded code-signature SuperBlob in one
/// bounded walk — see [`extract_signature_facts`].
#[derive(Default)]
struct SignatureFacts {
    entitlements: Option<Vec<u8>>,
    code_directory_flags: Option<u32>,
    has_cms_signature: bool,
}

/// Recover the entitlements, the OR of every CodeDirectory's `flags`, and
/// whether a non-empty CMS blob wrapper is present, from a Mach-O's embedded
/// code-signature SuperBlob, in one bounded walk of its blob index.
/// `dataoff`/`datasize` are the `LC_CODE_SIGNATURE` fields (Mach-O
/// endianness); the SuperBlob itself is always big-endian. `base` is where
/// this image begins in `data`. `entitlements`/`code_directory_flags` are
/// `None` if their blob is absent or the SuperBlob is malformed; every field
/// stays at its default if the signature region lies past the bytes held (a
/// truncated capture) — the caller must not read that as a determined fact.
fn extract_signature_facts(
    data: &[u8],
    base: usize,
    dataoff: u32,
    datasize: u32,
) -> SignatureFacts {
    extract_signature_facts_checked(data, base, dataoff, datasize).unwrap_or_default()
}

/// True for the primary CodeDirectory slot (0) or any of the 5 alternate
/// CodeDirectory slots XNU also accepts (`CSSLOT_ALTERNATE_CODEDIRECTORIES`
/// through `+MAX_ALTERNATE_CODEDIRECTORIES-1`, cs_blobs.h).
fn is_codedirectory_slot(slot_type: u32) -> bool {
    slot_type == CSSLOT_CODEDIRECTORY
        || (CSSLOT_ALTERNATE_CODEDIRECTORIES
            ..CSSLOT_ALTERNATE_CODEDIRECTORIES + MAX_ALTERNATE_CODEDIRECTORIES)
            .contains(&slot_type)
}

fn extract_signature_facts_checked(
    data: &[u8],
    base: usize,
    dataoff: u32,
    datasize: u32,
) -> Option<SignatureFacts> {
    let sig_off = base.checked_add(dataoff as usize)?;
    let sig_end = sig_off.checked_add(datasize as usize)?;
    if sig_end > data.len() {
        return None; // signature region past the bytes we hold
    }
    if be_u32(data, sig_off)? != CSMAGIC_EMBEDDED_SIGNATURE {
        return None;
    }
    let count = be_u32(data, sig_off.checked_add(8)?)?;
    if count > MAX_CS_BLOBS {
        return None;
    }

    let mut facts = SignatureFacts::default();

    for i in 0..count as usize {
        // CS_BlobIndex: type(4), offset(4) — offset relative to `sig_off`.
        let entry_off = sig_off.checked_add(12)?.checked_add(i.checked_mul(8)?)?;
        if entry_off.checked_add(8)? > sig_end {
            break;
        }
        let slot_type = be_u32(data, entry_off)?;
        let rel_off = be_u32(data, entry_off.checked_add(4)?)?;
        let blob_off = sig_off.checked_add(rel_off as usize)?;
        if blob_off.checked_add(8)? > sig_end {
            continue;
        }
        let magic = be_u32(data, blob_off)?;

        if slot_type == CSSLOT_ENTITLEMENTS
            && magic == CSMAGIC_EMBEDDED_ENTITLEMENTS
            && facts.entitlements.is_none()
        {
            facts.entitlements = extract_blob_payload(data, blob_off, sig_end);
        } else if is_codedirectory_slot(slot_type) && magic == CSMAGIC_CODEDIRECTORY {
            // CodeDirectory: magic(4)@0, length(4)@4, version(4)@8, flags(4)@12.
            // OR every CD's flags together: any one of them carrying CS_ADHOC
            // means the binary is ad-hoc, wherever XNU found that CD (#37).
            if blob_off.checked_add(16)? <= sig_end {
                if let Some(flags) = be_u32(data, blob_off.checked_add(12)?) {
                    facts.code_directory_flags =
                        Some(facts.code_directory_flags.unwrap_or(0) | flags);
                }
            }
        } else if slot_type == CSSLOT_SIGNATURESLOT && magic == CSMAGIC_BLOBWRAPPER {
            // CS_GenericBlob: magic(4)@0, length(4)@4 (total incl. header).
            // length > 8 means a non-empty payload — a real identity's CMS
            // blob. An ad-hoc signature carries this wrapper too, but empty
            // (length exactly 8); a linker signature has no wrapper at all.
            if let Some(len) = be_u32(data, blob_off.checked_add(4)?) {
                if len > 8 {
                    facts.has_cms_signature = true;
                }
            }
        }
    }
    Some(facts)
}

/// Read a `CS_GenericBlob`'s payload (magic(4), length(4, total incl.
/// header), payload) at `blob_off`, capped at `MAX_ENTITLEMENTS_BYTES` and
/// never past `sig_end`/the bytes held. `None` if the declared length is
/// implausible or the payload is empty.
fn extract_blob_payload(data: &[u8], blob_off: usize, sig_end: usize) -> Option<Vec<u8>> {
    let blob_len = be_u32(data, blob_off.checked_add(4)?)? as usize;
    if blob_len < 8 {
        return None;
    }
    let payload_len = (blob_len - 8).min(MAX_ENTITLEMENTS_BYTES);
    let payload_start = blob_off.checked_add(8)?;
    let payload_end = payload_start
        .checked_add(payload_len)?
        .min(sig_end)
        .min(data.len());
    if payload_end <= payload_start {
        return None;
    }
    Some(data[payload_start..payload_end].to_vec())
}

/// If the segment command at `off` is `__TEXT`, return the absolute file range
/// of its `__text` section — or the segment's own file range as a fallback.
/// `base` is where this Mach-O image begins in `data` (0 for a thin file, the
/// fat member offset otherwise); segment/section offsets are relative to it.
fn text_segment_range(r: &Reader, off: usize, is_64: bool, base: usize) -> Option<Range<u64>> {
    // segname[16] sits at off+8 in both segment_command and segment_command_64.
    if !name_matches(r.bytes(off.checked_add(8)?, 16)?, b"__TEXT") {
        return None;
    }

    // Field offsets within the segment command (see <mach-o/loader.h>):
    //   64-bit: fileoff(8)@40, filesize(8)@48, nsects(4)@64, sections@72
    //   32-bit: fileoff(4)@32, filesize(4)@36, nsects(4)@48, sections@56
    let (seg_fileoff, seg_filesize, nsects, sects_off, sect_stride) = if is_64 {
        (
            r.u64(off.checked_add(40)?)?,
            r.u64(off.checked_add(48)?)?,
            r.u32(off.checked_add(64)?)?,
            off.checked_add(72)?,
            80usize,
        )
    } else {
        (
            r.u32(off.checked_add(32)?)? as u64,
            r.u32(off.checked_add(36)?)? as u64,
            r.u32(off.checked_add(48)?)?,
            off.checked_add(56)?,
            68usize,
        )
    };

    if nsects <= MAX_NSECTS {
        for i in 0..nsects as usize {
            let s = sects_off.checked_add(i.checked_mul(sect_stride)?)?;
            // section[_64]: sectname[16], segname[16], addr, size, offset, ...
            if name_matches(r.bytes(s, 16)?, b"__text") {
                let (sec_off, sec_len) = if is_64 {
                    (
                        r.u32(s.checked_add(48)?)? as u64,
                        r.u64(s.checked_add(40)?)?,
                    )
                } else {
                    (
                        r.u32(s.checked_add(40)?)? as u64,
                        r.u32(s.checked_add(36)?)? as u64,
                    )
                };
                return absolute_range(base, sec_off, sec_len);
            }
        }
    }

    // No `__text` section located; fall back to the whole `__TEXT` file range.
    absolute_range(base, seg_fileoff, seg_filesize)
}

/// Turn a member-relative `(offset, len)` into an absolute file range, or
/// `None` if the length is zero or the arithmetic would overflow.
fn absolute_range(base: usize, rel_off: u64, len: u64) -> Option<Range<u64>> {
    if len == 0 {
        return None;
    }
    let start = (base as u64).checked_add(rel_off)?;
    let end = start.checked_add(len)?;
    Some(start..end)
}

/// Match a fixed-width, NUL-padded name field (e.g. a 16-byte `segname`)
/// against an exact needle: the needle followed only by NUL bytes.
fn name_matches(field: &[u8], needle: &[u8]) -> bool {
    field.len() >= needle.len()
        && &field[..needle.len()] == needle
        && field[needle.len()..].iter().all(|&b| b == 0)
}

fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(off..off.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn be_u64(data: &[u8], off: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(off..off.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Endianness-aware bounded reader over a byte slice.
struct Reader<'a> {
    data: &'a [u8],
    be: bool,
}

impl<'a> Reader<'a> {
    fn bytes(&self, off: usize, len: usize) -> Option<&'a [u8]> {
        self.data.get(off..off.checked_add(len)?)
    }

    fn u32(&self, off: usize) -> Option<u32> {
        let b: [u8; 4] = self.bytes(off, 4)?.try_into().ok()?;
        Some(if self.be {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    fn u64(&self, off: usize) -> Option<u64> {
        let b: [u8; 8] = self.bytes(off, 8)?.try_into().ok()?;
        Some(if self.be {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    }
}

/// Test-only Mach-O construction, shared with the entropy rule's tests and
/// the `macho-loader-anomaly` rule's tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::{
        CSMAGIC_BLOBWRAPPER, CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_ENTITLEMENTS,
        CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_CODEDIRECTORY, CSSLOT_ENTITLEMENTS,
        CSSLOT_SIGNATURESLOT, FAT_MAGIC, LC_CODE_SIGNATURE, LC_LOAD_DYLIB, LC_RPATH, LC_SEGMENT_64,
    };
    use std::ops::Range;

    /// Wrap already-built thin images as the slices of a 32-bit fat/universal
    /// binary (`fat_arch` table + payloads). Offsets are 16-byte aligned, as a
    /// real `lipo` output would be.
    pub(crate) fn synth_fat(members: &[&[u8]]) -> Vec<u8> {
        let header_len = 8 + 20 * members.len();
        let mut offsets = Vec::with_capacity(members.len());
        let mut cursor = header_len;
        for m in members {
            let aligned = (cursor + 15) & !15;
            offsets.push(aligned);
            cursor = aligned + m.len();
        }

        let mut v = Vec::new();
        v.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        v.extend_from_slice(&(members.len() as u32).to_be_bytes());
        for (i, m) in members.iter().enumerate() {
            v.extend_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
            v.extend_from_slice(&(i as u32).to_be_bytes()); // cpusubtype (distinct)
            v.extend_from_slice(&(offsets[i] as u32).to_be_bytes()); // offset
            v.extend_from_slice(&(m.len() as u32).to_be_bytes()); // size
            v.extend_from_slice(&0u32.to_be_bytes()); // align
        }
        for (i, m) in members.iter().enumerate() {
            v.resize(offsets[i], 0); // pad to this slice's offset
            v.extend_from_slice(m);
        }
        v
    }

    /// A fat/universal binary with `count` arch-table entries that all point
    /// at the same single embedded slice — the shape a hostile fat table
    /// uses to make an offset-naive walker re-parse (and re-allocate) one
    /// slice once per referring entry.
    pub(crate) fn synth_fat_with_duplicate_offsets(member: &[u8], count: usize) -> Vec<u8> {
        let header_len = 8 + 20 * count;
        let offset = (header_len + 15) & !15;

        let mut v = Vec::new();
        v.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        v.extend_from_slice(&(count as u32).to_be_bytes());
        for i in 0..count {
            v.extend_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
            v.extend_from_slice(&(i as u32).to_be_bytes()); // cpusubtype (distinct)
            v.extend_from_slice(&(offset as u32).to_be_bytes()); // offset — same for every entry
            v.extend_from_slice(&(member.len() as u32).to_be_bytes()); // size
            v.extend_from_slice(&0u32.to_be_bytes()); // align
        }
        v.resize(offset, 0);
        v.extend_from_slice(member);
        v
    }

    /// A fat/universal binary with `bogus_count` arch entries pointing at
    /// distinct, 16 KiB-aligned zeroed regions (no thin Mach-O magic) plus one
    /// real slice (`real_member`) last in the table — the shape a real fat
    /// binary the kernel will still run can take (#46: verified with 24 bogus
    /// entries alongside one real arm64 slice).
    pub(crate) fn synth_fat_with_bogus_arches(real_member: &[u8], bogus_count: usize) -> Vec<u8> {
        synth_fat_with_bogus_arches_aligned(real_member, bogus_count, 16 * 1024)
    }

    /// As [`synth_fat_with_bogus_arches`], but with the bogus regions aligned
    /// to `page` bytes instead of a fixed 16 KiB. A fixture that only needs
    /// to be *parsed* (never mapped/executed) can pack them far tighter than
    /// the kernel-runnable shape `synth_fat_with_bogus_arches` reproduces.
    pub(crate) fn synth_fat_with_bogus_arches_aligned(
        real_member: &[u8],
        bogus_count: usize,
        page: usize,
    ) -> Vec<u8> {
        const BOGUS_SIZE: usize = 16;

        let total = bogus_count + 1;
        let header_len = 8 + 20 * total;
        let align_up = |x: usize| x.div_ceil(page) * page;

        let mut offsets = Vec::with_capacity(total);
        let mut cursor = header_len;
        for _ in 0..bogus_count {
            let aligned = align_up(cursor);
            offsets.push(aligned);
            cursor = aligned + BOGUS_SIZE;
        }
        let real_off = align_up(cursor);
        offsets.push(real_off);

        let mut v = Vec::new();
        v.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        v.extend_from_slice(&(total as u32).to_be_bytes());
        for (i, &off) in offsets.iter().enumerate() {
            let is_real = i == bogus_count;
            let cputype = if is_real {
                0x0100_0007u32
            } else {
                0x7f00_0000u32 + i as u32
            };
            let size = if is_real {
                real_member.len()
            } else {
                BOGUS_SIZE
            };
            v.extend_from_slice(&cputype.to_be_bytes());
            v.extend_from_slice(&(i as u32).to_be_bytes()); // cpusubtype (distinct)
            v.extend_from_slice(&(off as u32).to_be_bytes());
            v.extend_from_slice(&(size as u32).to_be_bytes());
            v.extend_from_slice(&0u32.to_be_bytes()); // align
        }
        for (i, &off) in offsets.iter().enumerate() {
            v.resize(off, 0);
            if i == bogus_count {
                v.extend_from_slice(real_member);
            } else {
                v.resize(off + BOGUS_SIZE, 0);
            }
        }
        v
    }

    fn seg_name(name: &[u8]) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..name.len()].copy_from_slice(name);
        b
    }

    /// Build a minimal valid little-endian 64-bit Mach-O with one `__TEXT`
    /// segment holding one `__text` section of `text_payload`. Returns the
    /// image and the absolute `__text` range within it.
    pub(crate) fn synth_macho_64(text_payload: &[u8]) -> (Vec<u8>, Range<u64>) {
        let (bytes, range, _sig_placeholder) =
            synth_macho_64_full(text_payload, &[], &[], false, None);
        (bytes, range)
    }

    /// Build a `dylib_command` (or `LC_RPATH`, sharing the same `lc_str`
    /// shape) for `path`, padded to a 4-byte cmdsize.
    fn lc_str_command(cmd: u32, path: &str) -> Vec<u8> {
        let name_off = 12u32; // rpath_command's fixed header length
        let extra_off = if cmd == LC_RPATH { 12 } else { 24 };
        let header_len = extra_off;
        let str_bytes = path.as_bytes();
        let content_len = str_bytes.len() + 1; // + NUL
        let padded = content_len.div_ceil(4) * 4;
        let cmdsize = header_len + padded;

        let mut v = Vec::new();
        v.extend_from_slice(&cmd.to_le_bytes());
        v.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        if cmd == LC_RPATH {
            v.extend_from_slice(&name_off.to_le_bytes()); // path offset
        } else {
            v.extend_from_slice(&24u32.to_le_bytes()); // dylib.name offset
            v.extend_from_slice(&0u32.to_le_bytes()); // timestamp
            v.extend_from_slice(&0u32.to_le_bytes()); // current_version
            v.extend_from_slice(&0u32.to_le_bytes()); // compatibility_version
        }
        v.extend_from_slice(str_bytes);
        v.resize(v.len() + (padded - content_len) + 1, 0); // NUL + padding
        assert_eq!(v.len(), cmdsize);
        v
    }

    /// A thin 64-bit Mach-O whose first load command is an oversized, unknown
    /// command (`filler_cmdsize` bytes, zero-filled) followed by an
    /// `LC_LOAD_DYLIB` for `dylib_path` — the shape a `sizeofcmds` well past
    /// `MAX_SIZEOFCMDS` takes when every byte of it is real and already held
    /// in memory (§5.2, #45).
    pub(crate) fn build_thin_with_filler_then_dylib(
        filler_cmdsize: usize,
        dylib_path: &str,
    ) -> Vec<u8> {
        const FILLER_CMD: u32 = 0x7fff_0000; // not LC_SEGMENT_64/dylib/rpath/codesig
        let mut filler = Vec::new();
        filler.extend_from_slice(&FILLER_CMD.to_le_bytes());
        filler.extend_from_slice(&(filler_cmdsize as u32).to_le_bytes());
        filler.resize(filler_cmdsize, 0);

        let dylib_cmd = lc_str_command(LC_LOAD_DYLIB, dylib_path);
        let cmdsize = filler.len() + dylib_cmd.len();

        let mut v = Vec::new();
        v.extend_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // magic -> BE 0xCFFAEDFE
        v.extend_from_slice(&0x0100_0007u32.to_le_bytes()); // cputype x86_64
        v.extend_from_slice(&3u32.to_le_bytes()); // cpusubtype
        v.extend_from_slice(&2u32.to_le_bytes()); // filetype MH_EXECUTE
        v.extend_from_slice(&2u32.to_le_bytes()); // ncmds: filler + dylib
        v.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v.extend_from_slice(&filler);
        v.extend_from_slice(&dylib_cmd);
        v
    }

    /// A code-signature SuperBlob holding, in slot order, one CodeDirectory
    /// blob per `(slot_type, flags)` pair in `cds` and an optional
    /// entitlements blob (`entitlements_xml`, if given), plus the
    /// `LC_CODE_SIGNATURE` command pointing at it (`dataoff` filled in by the
    /// caller once the file offset is known). `cds: &[]` omits the
    /// CodeDirectory blob(s) entirely, so existing callers that only pass
    /// entitlements produce identical bytes to before this blob was added.
    /// `cms_payload_len` adds a `CSSLOT_SIGNATURESLOT` CMS blob wrapper when
    /// `Some`: `Some(0)` is an empty wrapper (a hand ad-hoc signature),
    /// `Some(n>0)` a non-empty one (a real identity), `None` no wrapper at
    /// all (a linker signature). `None` produces byte-identical output to
    /// before this parameter was added.
    fn build_signature_blob(
        entitlements_xml: Option<&[u8]>,
        cds: &[(u32, u32)],
        cms_payload_len: Option<usize>,
    ) -> Vec<u8> {
        let mut entries: Vec<(u32, Vec<u8>)> = Vec::new();
        for &(slot_type, flags) in cds {
            // Minimal CodeDirectory: magic(4), length(4), version(4), flags(4).
            let mut cd = Vec::new();
            cd.extend_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
            cd.extend_from_slice(&16u32.to_be_bytes());
            cd.extend_from_slice(&0x0002_0400u32.to_be_bytes()); // version
            cd.extend_from_slice(&flags.to_be_bytes());
            entries.push((slot_type, cd));
        }
        if let Some(xml) = entitlements_xml {
            let mut blob = Vec::new();
            blob.extend_from_slice(&CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
            blob.extend_from_slice(&((8 + xml.len()) as u32).to_be_bytes());
            blob.extend_from_slice(xml);
            entries.push((CSSLOT_ENTITLEMENTS, blob));
        }
        if let Some(payload_len) = cms_payload_len {
            let mut blob = Vec::new();
            blob.extend_from_slice(&CSMAGIC_BLOBWRAPPER.to_be_bytes());
            blob.extend_from_slice(&((8 + payload_len) as u32).to_be_bytes());
            blob.resize(blob.len() + payload_len, 0);
            entries.push((CSSLOT_SIGNATURESLOT, blob));
        }

        let index_len = 12usize + 8 * entries.len();
        let mut index = Vec::new();
        let mut blobs = Vec::new();
        let mut cursor = index_len as u32;
        for (slot_type, blob) in &entries {
            index.extend_from_slice(&slot_type.to_be_bytes());
            index.extend_from_slice(&cursor.to_be_bytes());
            blobs.extend_from_slice(blob);
            cursor += blob.len() as u32;
        }

        let total_len = index_len + blobs.len();
        let mut sb = Vec::new();
        sb.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        sb.extend_from_slice(&(total_len as u32).to_be_bytes());
        sb.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        sb.extend_from_slice(&index);
        sb.extend_from_slice(&blobs);
        sb
    }

    /// Full synthetic builder: a `__TEXT,__text` section holding
    /// `text_payload`, an `LC_LOAD_DYLIB` per entry in `dylibs`, an
    /// `LC_RPATH` per entry in `rpaths`, and — if `code_signed` — an
    /// `LC_CODE_SIGNATURE` pointing at a trailing SuperBlob carrying
    /// `entitlements_xml` (if given). Returns the image bytes, the absolute
    /// `__text` range, and the absolute file offset of the signature blob
    /// (0 if `code_signed` is false — never a real offset since the header
    /// always occupies the first bytes).
    pub(crate) fn synth_macho_64_full(
        text_payload: &[u8],
        dylibs: &[&str],
        rpaths: &[&str],
        code_signed: bool,
        entitlements_xml: Option<&[u8]>,
    ) -> (Vec<u8>, Range<u64>, usize) {
        synth_macho_64_full_with_cd_flags(
            text_payload,
            dylibs,
            rpaths,
            code_signed,
            entitlements_xml,
            None,
        )
    }

    /// As [`synth_macho_64_full`], with an optional slot-0 CodeDirectory
    /// carrying `cd_flags` (e.g. `CS_ADHOC`) added to the signature SuperBlob.
    /// `cd_flags: None` produces byte-identical output to
    /// `synth_macho_64_full`.
    pub(crate) fn synth_macho_64_full_with_cd_flags(
        text_payload: &[u8],
        dylibs: &[&str],
        rpaths: &[&str],
        code_signed: bool,
        entitlements_xml: Option<&[u8]>,
        cd_flags: Option<u32>,
    ) -> (Vec<u8>, Range<u64>, usize) {
        let cds: Vec<(u32, u32)> = cd_flags
            .map(|flags| vec![(CSSLOT_CODEDIRECTORY, flags)])
            .unwrap_or_default();
        synth_macho_64_full_with_cds(
            text_payload,
            dylibs,
            rpaths,
            code_signed,
            entitlements_xml,
            &cds,
        )
    }

    /// As [`synth_macho_64_full`], with one CodeDirectory blob per
    /// `(slot_type, flags)` pair in `cds` added to the signature SuperBlob —
    /// e.g. `&[(CSSLOT_ALTERNATE_CODEDIRECTORIES, CS_ADHOC)]` puts the only
    /// CodeDirectory in an alternate slot instead of slot 0. `cds: &[]`
    /// produces byte-identical output to `synth_macho_64_full`.
    pub(crate) fn synth_macho_64_full_with_cds(
        text_payload: &[u8],
        dylibs: &[&str],
        rpaths: &[&str],
        code_signed: bool,
        entitlements_xml: Option<&[u8]>,
        cds: &[(u32, u32)],
    ) -> (Vec<u8>, Range<u64>, usize) {
        synth_macho_64_full_with_cds_and_cms(
            text_payload,
            dylibs,
            rpaths,
            code_signed,
            entitlements_xml,
            cds,
            None,
        )
    }

    /// As [`synth_macho_64_full_with_cds`], with a `CSSLOT_SIGNATURESLOT` CMS
    /// blob wrapper controlled by `cms_payload_len` — see
    /// [`build_signature_blob`]'s doc for what each value means.
    /// `cms_payload_len: None` produces byte-identical output to
    /// `synth_macho_64_full_with_cds`.
    pub(crate) fn synth_macho_64_full_with_cds_and_cms(
        text_payload: &[u8],
        dylibs: &[&str],
        rpaths: &[&str],
        code_signed: bool,
        entitlements_xml: Option<&[u8]>,
        cds: &[(u32, u32)],
        cms_payload_len: Option<usize>,
    ) -> (Vec<u8>, Range<u64>, usize) {
        let header_size = 32usize;
        let seg_cmd_size = 72usize + 80usize; // segment_command_64 + one section_64

        let dylib_cmds: Vec<Vec<u8>> = dylibs
            .iter()
            .map(|d| lc_str_command(LC_LOAD_DYLIB, d))
            .collect();
        let rpath_cmds: Vec<Vec<u8>> = rpaths.iter().map(|p| lc_str_command(LC_RPATH, p)).collect();
        let codesig_cmd_size = if code_signed { 16usize } else { 0 };

        let mut ncmds = 1u32; // __TEXT segment
        ncmds += dylib_cmds.len() as u32;
        ncmds += rpath_cmds.len() as u32;
        ncmds += code_signed as u32;

        let cmdsize: usize = seg_cmd_size
            + dylib_cmds.iter().map(Vec::len).sum::<usize>()
            + rpath_cmds.iter().map(Vec::len).sum::<usize>()
            + codesig_cmd_size;

        let text_off = header_size + cmdsize;

        let mut v = Vec::new();
        // --- mach_header_64 (little-endian) ---
        v.extend_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // magic -> BE 0xCFFAEDFE
        v.extend_from_slice(&0x0100_0007u32.to_le_bytes()); // cputype x86_64
        v.extend_from_slice(&3u32.to_le_bytes()); // cpusubtype
        v.extend_from_slice(&2u32.to_le_bytes()); // filetype MH_EXECUTE
        v.extend_from_slice(&ncmds.to_le_bytes());
        v.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved

        // --- LC_SEGMENT_64 for __TEXT ---
        v.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        v.extend_from_slice(&(seg_cmd_size as u32).to_le_bytes());
        v.extend_from_slice(&seg_name(b"__TEXT"));
        v.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
        v.extend_from_slice(&0u64.to_le_bytes()); // vmsize
        v.extend_from_slice(&(text_off as u64).to_le_bytes()); // fileoff
        v.extend_from_slice(&(text_payload.len() as u64).to_le_bytes()); // filesize
        v.extend_from_slice(&5u32.to_le_bytes()); // maxprot
        v.extend_from_slice(&5u32.to_le_bytes()); // initprot
        v.extend_from_slice(&1u32.to_le_bytes()); // nsects
        v.extend_from_slice(&0u32.to_le_bytes()); // flags

        // --- section_64 __text ---
        v.extend_from_slice(&seg_name(b"__text"));
        v.extend_from_slice(&seg_name(b"__TEXT"));
        v.extend_from_slice(&0u64.to_le_bytes()); // addr
        v.extend_from_slice(&(text_payload.len() as u64).to_le_bytes()); // size
        v.extend_from_slice(&(text_off as u32).to_le_bytes()); // offset
        v.extend_from_slice(&0u32.to_le_bytes()); // align
        v.extend_from_slice(&0u32.to_le_bytes()); // reloff
        v.extend_from_slice(&0u32.to_le_bytes()); // nreloc
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved3

        for c in &dylib_cmds {
            v.extend_from_slice(c);
        }
        for c in &rpath_cmds {
            v.extend_from_slice(c);
        }

        let sig_placeholder_at = v.len(); // where LC_CODE_SIGNATURE's cmd starts, if any
        if code_signed {
            // linkedit_data_command: dataoff/datasize filled in once known.
            v.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
            v.extend_from_slice(&16u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes()); // dataoff placeholder
            v.extend_from_slice(&0u32.to_le_bytes()); // datasize placeholder
        }

        assert_eq!(v.len(), text_off);
        v.extend_from_slice(text_payload);

        let mut sig_off = 0usize;
        if code_signed {
            sig_off = v.len();
            let blob = build_signature_blob(entitlements_xml, cds, cms_payload_len);
            let dataoff = sig_off as u32;
            let datasize = blob.len() as u32;
            v[sig_placeholder_at + 8..sig_placeholder_at + 12]
                .copy_from_slice(&dataoff.to_le_bytes());
            v[sig_placeholder_at + 12..sig_placeholder_at + 16]
                .copy_from_slice(&datasize.to_le_bytes());
            v.extend_from_slice(&blob);
        }

        let range = text_off as u64..(text_off + text_payload.len()) as u64;
        (v, range, sig_off)
    }

    /// A thin 64-bit Mach-O with **two** `LC_CODE_SIGNATURE` load commands:
    /// the first pointing at a real SuperBlob (`entitlements_xml`/`cd_flags`
    /// as given), the second pointing at zero-length data — the malformed
    /// shape `parse_thin` must reject outright rather than let the second,
    /// bogus command silently overwrite the first's facts (#37).
    pub(crate) fn synth_macho_64_duplicate_code_signature(
        text_payload: &[u8],
        entitlements_xml: Option<&[u8]>,
        cd_flags: Option<u32>,
    ) -> Vec<u8> {
        let header_size = 32usize;
        let seg_cmd_size = 72usize + 80usize; // segment_command_64 + one section_64
        let codesig_cmd_size = 16usize;
        let ncmds = 3u32; // __TEXT segment + two LC_CODE_SIGNATURE
        let cmdsize = seg_cmd_size + codesig_cmd_size * 2;
        let text_off = header_size + cmdsize;

        let mut v = Vec::new();
        // --- mach_header_64 (little-endian) ---
        v.extend_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // magic -> BE 0xCFFAEDFE
        v.extend_from_slice(&0x0100_0007u32.to_le_bytes()); // cputype x86_64
        v.extend_from_slice(&3u32.to_le_bytes()); // cpusubtype
        v.extend_from_slice(&2u32.to_le_bytes()); // filetype MH_EXECUTE
        v.extend_from_slice(&ncmds.to_le_bytes());
        v.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved

        // --- LC_SEGMENT_64 for __TEXT ---
        v.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        v.extend_from_slice(&(seg_cmd_size as u32).to_le_bytes());
        v.extend_from_slice(&seg_name(b"__TEXT"));
        v.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
        v.extend_from_slice(&0u64.to_le_bytes()); // vmsize
        v.extend_from_slice(&(text_off as u64).to_le_bytes()); // fileoff
        v.extend_from_slice(&(text_payload.len() as u64).to_le_bytes()); // filesize
        v.extend_from_slice(&5u32.to_le_bytes()); // maxprot
        v.extend_from_slice(&5u32.to_le_bytes()); // initprot
        v.extend_from_slice(&1u32.to_le_bytes()); // nsects
        v.extend_from_slice(&0u32.to_le_bytes()); // flags

        // --- section_64 __text ---
        v.extend_from_slice(&seg_name(b"__text"));
        v.extend_from_slice(&seg_name(b"__TEXT"));
        v.extend_from_slice(&0u64.to_le_bytes()); // addr
        v.extend_from_slice(&(text_payload.len() as u64).to_le_bytes()); // size
        v.extend_from_slice(&(text_off as u32).to_le_bytes()); // offset
        v.extend_from_slice(&0u32.to_le_bytes()); // align
        v.extend_from_slice(&0u32.to_le_bytes()); // reloff
        v.extend_from_slice(&0u32.to_le_bytes()); // nreloc
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved3

        // First LC_CODE_SIGNATURE: dataoff/datasize filled in once the trailing
        // SuperBlob's offset is known.
        let first_sig_cmd_at = v.len();
        v.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
        v.extend_from_slice(&(codesig_cmd_size as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // dataoff placeholder
        v.extend_from_slice(&0u32.to_le_bytes()); // datasize placeholder

        // Second LC_CODE_SIGNATURE: the duplicate. `parse_thin` must bail on
        // seeing this command before ever reading its fields, so they're left
        // as zero.
        v.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
        v.extend_from_slice(&(codesig_cmd_size as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // dataoff
        v.extend_from_slice(&0u32.to_le_bytes()); // datasize

        assert_eq!(v.len(), text_off);
        v.extend_from_slice(text_payload);

        let sig_off = v.len();
        let cds: Vec<(u32, u32)> = cd_flags
            .map(|flags| vec![(CSSLOT_CODEDIRECTORY, flags)])
            .unwrap_or_default();
        let blob = build_signature_blob(entitlements_xml, &cds, None);
        v[first_sig_cmd_at + 8..first_sig_cmd_at + 12]
            .copy_from_slice(&(sig_off as u32).to_le_bytes());
        v[first_sig_cmd_at + 12..first_sig_cmd_at + 16]
            .copy_from_slice(&(blob.len() as u32).to_le_bytes());
        v.extend_from_slice(&blob);

        v
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{
        synth_fat, synth_fat_with_bogus_arches, synth_fat_with_duplicate_offsets, synth_macho_64,
        synth_macho_64_duplicate_code_signature, synth_macho_64_full,
        synth_macho_64_full_with_cd_flags, synth_macho_64_full_with_cds,
        synth_macho_64_full_with_cds_and_cms,
    };
    use super::*;

    #[test]
    fn parse_all_walks_every_fat_slice() {
        let (a, _, _) = synth_macho_64_full(b"aaaa", &["/usr/lib/a.dylib"], &[], false, None);
        let (b, _, _) = synth_macho_64_full(b"bbbb", &["/tmp/b.dylib"], &[], false, None);
        let fat = synth_fat(&[&a, &b]);

        let imgs = parse_all(&fat);
        assert_eq!(imgs.len(), 2, "both slices must be walked");
        assert!(imgs[0].is_fat && imgs[1].is_fat);
        assert_eq!(imgs[0].dylibs, vec!["/usr/lib/a.dylib".to_string()]);
        assert_eq!(imgs[1].dylibs, vec!["/tmp/b.dylib".to_string()]);

        // `parse` still yields the first slice for single-view callers.
        assert_eq!(
            parse(&fat).unwrap().dylibs,
            vec!["/usr/lib/a.dylib".to_string()]
        );
    }

    #[test]
    fn parse_returns_only_the_first_walkable_fat_slice() {
        let (a, _, _) = synth_macho_64_full(b"aaaa", &["/usr/lib/a.dylib"], &[], false, None);
        let (b, _, _) = synth_macho_64_full(b"bbbb", &["/tmp/b.dylib"], &[], false, None);
        let fat = synth_fat(&[&a, &b]);
        assert_eq!(
            parse(&fat).unwrap().dylibs,
            vec!["/usr/lib/a.dylib".to_string()]
        );
    }

    #[test]
    fn many_fat_arches_sharing_one_offset_parse_once_and_are_not_skipped() {
        // A hostile fat table can point MAX_FAT_ARCHES entries at the same
        // slice — that's one slice, not one per entry, and a duplicate of a
        // walkable slice must not count toward `skipped`.
        let (member, _, _) = synth_macho_64_full(b"shared slice", &[], &[], false, None);
        let fat = synth_fat_with_duplicate_offsets(&member, 1024);
        let (images, skipped) = parse_all_slices(&fat, false);
        assert_eq!(images.len(), 1);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn parses_thin_64_and_locates_text() {
        let payload = b"\x00\x01\x02\x03some machine code here";
        let (image, expected) = synth_macho_64(payload);
        let parsed = parse(&image).expect("should parse as Mach-O");
        assert!(parsed.is_64);
        assert!(!parsed.is_fat);
        assert_eq!(parsed.text_range, Some(expected));
    }

    #[test]
    fn text_range_points_at_the_real_payload() {
        let payload: Vec<u8> = (0..=255u8).collect();
        let (image, _) = synth_macho_64(&payload);
        let range = parse(&image).unwrap().text_range.unwrap();
        let slice = &image[range.start as usize..range.end as usize];
        assert_eq!(slice, payload.as_slice());
    }

    #[test]
    fn rejects_non_macho() {
        assert!(parse(b"#!/bin/sh\necho hi\n").is_none());
        assert!(parse(b"").is_none());
        assert!(parse(b"\x00\x01").is_none());
        assert!(parse(&[0u8; 4096]).is_none());
    }

    #[test]
    fn magic_detection_matches_what_parse_accepts() {
        let (image, _) = synth_macho_64(b"code");
        assert!(is_macho_magic(&image, false));
        // Fat magic alone, with no arch table entry pointing at a real slice,
        // is not enough (that's exactly what let a Java `.class` file through).
        assert!(!is_macho_magic(
            &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 1],
            false
        ));
        // Everything that is plainly not a code object.
        assert!(!is_macho_magic(b"#!/bin/sh\n", false));
        assert!(!is_macho_magic(b"xar!", false));
        assert!(!is_macho_magic(b"just some text", false));
        assert!(!is_macho_magic(b"\x1f\x8b\x08\x00", false));
        assert!(!is_macho_magic(b"", false));
        assert!(!is_macho_magic(b"\xCF\xFA", false));
    }

    #[test]
    fn rejects_java_class_sharing_fat_magic() {
        // 0xCAFEBABE followed by a Java-style minor/major version, not a real
        // fat arch table — must not be mistaken for a universal binary.
        let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE];
        v.extend_from_slice(&0x0000_0034u32.to_be_bytes()); // minor=0, major=52
        v.extend_from_slice(&[0u8; 64]);
        assert!(parse(&v).is_none());
    }

    #[test]
    fn java_class_headers_are_not_macho() {
        // CAFEBABE + (minor=0, major=52) and (minor=0, major=65) — real Java
        // major versions (JDK 1.1 onward is 45+). The bytes following the
        // magic are all zero, so every arch-table entry this reads either
        // points at offset 0 (the CAFEBABE bytes themselves, not a thin
        // Mach-O magic) or falls outside the 64-byte constant-pool stand-in —
        // never real evidence of a slice.
        for major in [0x34u32, 0x41] {
            let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE];
            v.extend_from_slice(&major.to_be_bytes());
            v.extend_from_slice(&[0u8; 64]);
            assert!(!is_macho_magic(&v, false), "major {major:#x}");
            assert!(parse_all(&v).is_empty(), "major {major:#x}");
        }
    }

    #[test]
    fn truncated_java_like_header_with_offset_past_eof_is_lenient() {
        // Same CAFEBABE + major=52 shape, but the first arch entry's offset
        // field is set past the end of the (short) buffer. A non-truncated
        // read of this shape can only mean "not a fat binary" (#46); a
        // truncated one can't rule out a real slice lying past what was
        // captured, so it must not be read as "not a Mach-O" (§10/§11.8).
        let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE];
        v.extend_from_slice(&0x0000_0034u32.to_be_bytes()); // minor=0, major=52
        v.extend_from_slice(&[0u8; 64]);
        // First fat_arch's offset field: bytes 16..20 (arch_off=8, +8).
        let past_eof = v.len() as u32 + 1000;
        v[16..20].copy_from_slice(&past_eof.to_be_bytes());
        assert!(
            !is_macho_magic(&v, false),
            "complete read finds no evidence"
        );
        assert!(is_macho_magic(&v, true), "truncated read stays lenient");
    }

    #[test]
    fn a_real_fat_header_with_a_handful_of_arches_is_still_macho() {
        let (a, _, _) = synth_macho_64_full(b"aaaa", &[], &[], false, None);
        let (b, _, _) = synth_macho_64_full(b"bbbb", &[], &[], false, None);
        let fat = synth_fat(&[&a, &b]);
        assert!(is_macho_magic(&fat, false));
        assert_eq!(parse_all(&fat).len(), 2);
    }

    #[test]
    fn many_bogus_arches_alongside_one_real_slice_is_still_macho() {
        // #46: the kernel runs a fat binary with far more arch entries than
        // any real toolchain emits, as long as one slice is real — an
        // arch-count cap alone must not be the discriminator.
        let (real, _, _) = synth_macho_64_full(b"real slice", &[], &[], false, None);
        let fat = synth_fat_with_bogus_arches(&real, 24);
        assert!(is_macho_magic(&fat, false));
        let (images, skipped) = parse_all_slices(&fat, false);
        assert_eq!(images.len(), 1);
        assert_eq!(skipped, 24);
    }

    #[test]
    fn truncated_header_does_not_panic() {
        // A valid magic followed by nothing — exercises the bounds checks.
        for len in 0..48usize {
            let mut v = vec![0xCF, 0xFA, 0xED, 0xFE];
            v.truncate(len.min(4));
            v.resize(len, 0);
            let _ = parse(&v); // must not panic
        }
    }

    #[test]
    fn collects_dylibs_and_rpaths_in_order() {
        let (image, _, _) = synth_macho_64_full(
            b"code",
            &["/usr/lib/libSystem.B.dylib", "@rpath/libFoo.dylib"],
            &["@executable_path/../Frameworks", "/tmp/evil"],
            false,
            None,
        );
        let parsed = parse(&image).unwrap();
        assert_eq!(
            parsed.dylibs,
            vec![
                "/usr/lib/libSystem.B.dylib".to_string(),
                "@rpath/libFoo.dylib".to_string()
            ]
        );
        assert_eq!(
            parsed.rpaths,
            vec![
                "@executable_path/../Frameworks".to_string(),
                "/tmp/evil".to_string()
            ]
        );
        assert!(!parsed.has_code_signature);
        assert_eq!(parsed.entitlements, None);
    }

    #[test]
    fn detects_code_signature_without_entitlements() {
        let (image, _, _) = synth_macho_64_full(b"code", &[], &[], true, None);
        let parsed = parse(&image).unwrap();
        assert!(parsed.has_code_signature);
        assert_eq!(parsed.entitlements, None);
    }

    #[test]
    fn extracts_entitlements_xml() {
        let xml = br#"<?xml version="1.0"?><plist><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;
        let (image, _, _) = synth_macho_64_full(b"code", &[], &[], true, Some(xml));
        let parsed = parse(&image).unwrap();
        assert!(parsed.has_code_signature);
        assert_eq!(parsed.entitlements.as_deref(), Some(&xml[..]));
    }

    #[test]
    fn truncated_signature_region_yields_none_not_panic() {
        let xml = b"<plist><dict/></plist>";
        let (mut image, _, sig_off) = synth_macho_64_full(b"code", &[], &[], true, Some(xml));
        // Chop the file off partway through the signature blob — a truncated
        // 8 MiB capture is exactly this shape.
        image.truncate(sig_off + 4);
        let parsed = parse(&image).unwrap();
        assert!(parsed.has_code_signature); // the load command itself is intact
        assert_eq!(parsed.entitlements, None); // but the blob region is gone
    }

    #[test]
    fn oversized_declared_datasize_does_not_panic_or_overread() {
        let xml = b"<plist><dict/></plist>";
        let (mut image, _, sig_off) = synth_macho_64_full(b"code", &[], &[], true, Some(xml));
        // Corrupt LC_CODE_SIGNATURE's datasize to claim far more than the
        // file actually holds.
        let lc_off = image
            .windows(4)
            .position(|w| w == LC_CODE_SIGNATURE.to_le_bytes())
            .expect("LC_CODE_SIGNATURE present");
        image[lc_off + 12..lc_off + 16].copy_from_slice(&u32::MAX.to_le_bytes());
        let parsed = parse(&image); // must not panic
        if let Some(img) = parsed {
            assert_eq!(img.entitlements, None);
        }
        let _ = sig_off;
    }

    #[test]
    fn code_directory_flags_are_read_back() {
        let (adhoc, _, _) =
            synth_macho_64_full_with_cd_flags(b"code", &[], &[], true, None, Some(CS_ADHOC));
        assert_eq!(parse(&adhoc).unwrap().code_directory_flags, Some(CS_ADHOC));

        let (identity, _, _) =
            synth_macho_64_full_with_cd_flags(b"code", &[], &[], true, None, Some(0x10000));
        assert_eq!(
            parse(&identity).unwrap().code_directory_flags,
            Some(0x10000)
        );
    }

    #[test]
    fn cms_signature_presence_requires_a_non_empty_wrapper() {
        let cds = [(CSSLOT_CODEDIRECTORY, 0u32)];

        let (no_cms, _, _) =
            synth_macho_64_full_with_cds_and_cms(b"code", &[], &[], true, None, &cds, None);
        assert!(!parse(&no_cms).unwrap().has_cms_signature);

        let (empty_cms, _, _) =
            synth_macho_64_full_with_cds_and_cms(b"code", &[], &[], true, None, &cds, Some(0));
        assert!(!parse(&empty_cms).unwrap().has_cms_signature);

        let (real_cms, _, _) =
            synth_macho_64_full_with_cds_and_cms(b"code", &[], &[], true, None, &cds, Some(4));
        assert!(parse(&real_cms).unwrap().has_cms_signature);
    }

    #[test]
    fn no_code_directory_blob_is_none_not_zero() {
        let (image, _, _) = synth_macho_64_full(b"code", &[], &[], true, None);
        assert_eq!(parse(&image).unwrap().code_directory_flags, None);
    }

    /// A second `LC_CODE_SIGNATURE` has no legal meaning — rather than guess
    /// which one the kernel would honor, the whole slice is malformed and a
    /// thin file yields no image at all (#37).
    #[test]
    fn duplicate_code_signature_command_makes_the_thin_slice_malformed() {
        let entitlements = br#"<?xml version="1.0"?><plist><dict>
            <key>com.apple.security.cs.disable-library-validation</key><true/>
        </dict></plist>"#;
        let image =
            synth_macho_64_duplicate_code_signature(b"code", Some(entitlements), Some(CS_ADHOC));
        assert!(
            parse(&image).is_none(),
            "a duplicate LC_CODE_SIGNATURE must not silently keep or erase the first \
             signature's facts"
        );
    }

    /// As above, but as one slice of a fat binary: the malformed slice must
    /// count as skipped rather than disappear silently or take down the
    /// sibling slice (#37).
    #[test]
    fn duplicate_code_signature_in_one_fat_slice_is_skipped() {
        let (clean, _, _) =
            synth_macho_64_full(b"clean", &["/usr/lib/libSystem.B.dylib"], &[], false, None);
        let bad = synth_macho_64_duplicate_code_signature(b"bad", None, Some(CS_ADHOC));
        let fat = synth_fat(&[&clean, &bad]);

        let (images, skipped) = parse_all_slices(&fat, false);
        assert_eq!(images.len(), 1);
        assert_eq!(skipped, 1);
    }

    /// XNU accepts a CodeDirectory in any of 5 alternate slots
    /// (`CSSLOT_ALTERNATE_CODEDIRECTORIES`..+4), not just slot 0 — an
    /// attacker can put its only, ad-hoc CD there (#37).
    #[test]
    fn ad_hoc_flag_from_alternate_codedirectory_slot_only() {
        let (image, _, _) = synth_macho_64_full_with_cds(
            b"code",
            &[],
            &[],
            true,
            None,
            &[(CSSLOT_ALTERNATE_CODEDIRECTORIES, CS_ADHOC)],
        );
        let flags = parse(&image).unwrap().code_directory_flags.unwrap();
        assert_ne!(flags & CS_ADHOC, 0);
    }

    /// A CodeDirectory in slot 0 saying "real identity" must not shadow an
    /// ad-hoc one sitting in an alternate slot — the OR must catch it (#37).
    #[test]
    fn ad_hoc_flag_from_slot_0_plus_alternate_is_ored_in() {
        let (image, _, _) = synth_macho_64_full_with_cds(
            b"code",
            &[],
            &[],
            true,
            None,
            &[
                (CSSLOT_CODEDIRECTORY, 0x10000), // slot 0: identity, no CS_ADHOC
                (CSSLOT_ALTERNATE_CODEDIRECTORIES, CS_ADHOC), // alternate: ad-hoc
            ],
        );
        let flags = parse(&image).unwrap().code_directory_flags.unwrap();
        assert_ne!(
            flags & CS_ADHOC,
            0,
            "any CD being ad-hoc must OR in as ad-hoc"
        );
    }

    /// A signature region fully held, but whose CodeDirectory blob is cut
    /// short by `datasize` (`blob_off + 16 > sig_end`) — distinct from a
    /// truncated *capture*: the parse of the header/load-commands must still
    /// succeed, and the unreadable CD must not fabricate flags.
    #[test]
    fn code_directory_cut_short_by_datasize_yields_none_not_panic() {
        let (mut image, _, _) =
            synth_macho_64_full_with_cd_flags(b"code", &[], &[], true, None, Some(CS_ADHOC));
        let lc_off = image
            .windows(4)
            .position(|w| w == LC_CODE_SIGNATURE.to_le_bytes())
            .expect("LC_CODE_SIGNATURE present");
        // index (12 + 8*1 entry = 20 bytes) + 12 bytes into the 16-byte CD
        // blob: sig_end lands inside the CD, short of the flags field.
        let new_datasize = 20u32 + 12;
        image[lc_off + 12..lc_off + 16].copy_from_slice(&new_datasize.to_le_bytes());
        let parsed = parse(&image).expect("full header/load-commands still parse");
        assert_eq!(parsed.code_directory_flags, None);
    }

    #[test]
    fn dylib_and_rpath_counts_are_capped() {
        // MAX_RPATHS is 256 — build one more and confirm the parser doesn't
        // choke or unbounded-allocate; it just stops collecting.
        let many: Vec<String> = (0..300).map(|i| format!("/tmp/{i}")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let (image, _, _) = synth_macho_64_full(b"code", &[], &refs, false, None);
        let parsed = parse(&image).unwrap();
        assert!(parsed.rpaths.len() <= MAX_RPATHS);
    }

    #[test]
    fn parse_all_slices_counts_unwalkable_arches() {
        let (good, _, _) = synth_macho_64_full(b"good", &[], &[], false, None);
        let garbage: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0];
        let fat = synth_fat(&[&good, garbage]);
        let (images, skipped) = parse_all_slices(&fat, false);
        assert_eq!(images.len(), 1);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn thin_and_two_clean_slices_report_zero_skipped() {
        let (thin, _) = synth_macho_64(b"code");
        assert_eq!(parse_all_slices(&thin, false), (parse_all(&thin), 0));

        let (a, _, _) = synth_macho_64_full(b"aaaa", &[], &[], false, None);
        let (b, _, _) = synth_macho_64_full(b"bbbb", &[], &[], false, None);
        let fat = synth_fat(&[&a, &b]);
        let (images, skipped) = parse_all_slices(&fat, false);
        assert_eq!(images.len(), 2);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn an_implausible_fat_header_reports_zero_skipped_not_all_skipped() {
        // Java-.class-shaped header: not a fat binary at all, so this reads
        // as "nothing declared," not "every arch skipped."
        let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE];
        v.extend_from_slice(&0x0000_0034u32.to_be_bytes());
        v.extend_from_slice(&[0u8; 64]);
        assert_eq!(parse_all_slices(&v, false), (Vec::new(), 0));
    }

    #[test]
    fn a_fat_table_entry_pointing_past_eof_is_skipped_and_counted() {
        let (good, _, _) = synth_macho_64_full(b"good", &[], &[], false, None);
        let mut fat = synth_fat(&[&good, &good]);
        let total_len = fat.len() as u32;
        // Corrupt the second fat_arch's offset field (bytes 36..40: the
        // second 20-byte fat_arch entry starts at 28, offset is its 3rd u32)
        // to point past EOF.
        fat[36..40].copy_from_slice(&(total_len + 1000).to_be_bytes());
        let (images, skipped) = parse_all_slices(&fat, false);
        assert_eq!(images.len(), 1);
        assert_eq!(skipped, 1);
    }

    /// Strips the two fields that legitimately differ between a whole-buffer
    /// prefix parse and an offset-based one (the latter actually reads the
    /// signature by offset) so the rest of `MachOImage` can be compared.
    fn strip_ranged_only_fields(img: &MachOImage) -> MachOImage {
        let mut img = img.clone();
        img.signature_region_read = false;
        img.code_signature = None;
        img
    }

    fn assert_scan_ranged_agrees(data: &[u8]) {
        let (prefix_images, prefix_skipped) = parse_all_slices(data, false);
        let ranged = scan_ranged(data);
        assert_eq!(ranged.images.len(), prefix_images.len());
        assert_eq!(ranged.skipped_slices, prefix_skipped);
        let ranged_stripped: Vec<_> = ranged.images.iter().map(strip_ranged_only_fields).collect();
        let prefix_stripped: Vec<_> = prefix_images.iter().map(strip_ranged_only_fields).collect();
        assert_eq!(ranged_stripped, prefix_stripped);
    }

    /// `scan_ranged` must find the same slices, in the same shape, as the
    /// existing in-memory prefix parse on every buffer small enough that the
    /// two have nothing to disagree about (§5.2, #45).
    #[test]
    fn scan_ranged_agrees_with_parse_all_slices_on_existing_synthetic_images() {
        let (thin, _) = synth_macho_64(b"code");
        assert_scan_ranged_agrees(&thin);

        let (a, _, _) = synth_macho_64_full(b"aaaa", &["/usr/lib/a.dylib"], &[], true, None);
        let (b, _, _) = synth_macho_64_full(b"bbbb", &["/tmp/b.dylib"], &[], false, None);
        assert_scan_ranged_agrees(&synth_fat(&[&a, &b]));

        let (real, _, _) = synth_macho_64_full(
            b"real slice",
            &["/usr/lib/libSystem.B.dylib"],
            &[],
            false,
            None,
        );
        assert_scan_ranged_agrees(&synth_fat_with_bogus_arches(&real, 24));

        let garbage: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0];
        assert_scan_ranged_agrees(&synth_fat(&[&real, garbage]));
    }

    /// A Java `.class`-shaped, complete (non-truncated) header must not be
    /// read as Mach-O by the offset-based path either (#46).
    #[test]
    fn scan_ranged_java_class_like_fat_header_is_not_macho() {
        let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE];
        v.extend_from_slice(&0x0000_0034u32.to_be_bytes()); // minor=0, major=52
        v.extend_from_slice(&[0u8; 64]);
        let scan = scan_ranged(&v[..]);
        assert!(!scan.is_macho);
        assert!(scan.images.is_empty());
    }

    /// A `ByteSource` that reports a `source_len` bigger than the bytes it
    /// can actually serve — the shape a stale, larger `file_len` takes after
    /// the real object shrank underneath a loaded `ScanContext` with no
    /// handle left to serve the difference (§10/§11.8, PR #52 review).
    struct StaleLenSource<'a> {
        data: &'a [u8],
        claimed_len: u64,
    }

    impl ByteSource for StaleLenSource<'_> {
        fn source_len(&self) -> u64 {
            self.claimed_len
        }

        fn held_len(&self) -> u64 {
            self.data.len() as u64
        }

        fn read_range(&self, off: u64, len: usize) -> Option<Cow<'_, [u8]>> {
            self.data.read_range(off, len)
        }
    }

    /// A stale `source_len` far bigger than what's actually held must not
    /// make `scan_ranged` read a real magic as "not Mach-O": the full head
    /// read fails (nothing to serve past the held bytes), but the magic
    /// itself is still recognized from what is held, so the result stays
    /// `is_macho: true` with the unwalkable slice counted as skipped — never
    /// a clean bill of health (§10/§11.8, PR #52 review).
    #[test]
    fn scan_ranged_recognizes_a_thin_magic_when_the_full_head_read_fails() {
        let src = StaleLenSource {
            data: &[0xFE, 0xED, 0xFA, 0xCF], // MH_MAGIC_64
            claimed_len: u64::MAX,
        };
        let scan = scan_ranged(&src);
        assert!(scan.is_macho, "a real magic must not read as not Mach-O");
        assert!(scan.images.is_empty());
        assert_eq!(scan.skipped_slices, 1);
        assert!(!scan.fully_examined());
    }

    /// Same shape with a fat magic: the retry only recovers the magic
    /// itself, not even `nfat_arch` — still undetermined, not clean.
    #[test]
    fn scan_ranged_recognizes_a_fat_magic_when_the_full_head_read_fails_before_nfat() {
        let src = StaleLenSource {
            data: &[0xCA, 0xFE, 0xBA, 0xBE], // FAT_MAGIC, nfat_arch unreadable
            claimed_len: u64::MAX,
        };
        let scan = scan_ranged(&src);
        assert!(
            scan.is_macho,
            "a real fat magic must not read as not Mach-O"
        );
        assert!(scan.images.is_empty());
        assert_eq!(scan.skipped_slices, 1);
        assert!(!scan.fully_examined());
    }

    /// A complete 4-byte file starting `CAFEBABE` is too short to be a real
    /// fat header at all — it must not be read as an unwalkable Mach-O
    /// (§10/§11.8: this is "checked and clean," not "couldn't check").
    #[test]
    fn scan_ranged_short_complete_file_with_fat_magic_is_not_macho() {
        let data: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE];
        let scan = scan_ranged(data);
        assert!(!scan.is_macho);
        assert_eq!(scan.skipped_slices, 0);
    }

    /// A `ByteSource` wrapping `data` but reporting a caller-chosen
    /// `held_len` instead of `data.len()` — lets a test exercise the
    /// offset-read path (bytes genuinely past what's in memory) against a
    /// plain in-memory buffer, which would otherwise report its whole length
    /// as held (§5.2, #45).
    struct LimitedHeldSource<'a> {
        data: &'a [u8],
        held: u64,
    }

    impl ByteSource for LimitedHeldSource<'_> {
        fn source_len(&self) -> u64 {
            self.data.source_len()
        }

        fn held_len(&self) -> u64 {
            self.held
        }

        fn read_range(&self, off: u64, len: usize) -> Option<Cow<'_, [u8]>> {
            self.data.read_range(off, len)
        }
    }

    /// A slice declaring more load-command bytes than `MAX_SIZEOFCMDS`, past
    /// what's held in memory, is unwalkable by offset — it must count as
    /// skipped, not silently vanish or take the sibling slice down with it.
    #[test]
    fn scan_ranged_counts_an_oversized_sizeofcmds_slice_as_skipped_past_the_held_bytes() {
        let (good, _, _) =
            synth_macho_64_full(b"good", &["/usr/lib/libSystem.B.dylib"], &[], false, None);
        let (mut bad, _, _) = synth_macho_64_full(b"bad", &[], &[], false, None);
        let huge = (MAX_SIZEOFCMDS as u32) + 1;
        bad[20..24].copy_from_slice(&huge.to_le_bytes()); // sizeofcmds, LE u32 @ offset 20
        let fat = synth_fat(&[&good, &bad]);

        let scan = scan_ranged(&LimitedHeldSource {
            data: &fat,
            held: 0,
        });
        assert!(scan.is_macho);
        assert_eq!(scan.images.len(), 1);
        assert_eq!(scan.skipped_slices, 1);
    }

    /// A thin Mach-O with a >2 MiB filler load command followed by a real
    /// `LC_LOAD_DYLIB`, entirely inside the in-memory prefix: `MAX_SIZEOFCMDS`
    /// must not stop this from walking to the dylib (§5.2, #45).
    #[test]
    fn scan_ranged_walks_past_an_oversized_filler_command_when_all_held() {
        let filler_len = MAX_SIZEOFCMDS + 4096;
        let bytes = tests_support::build_thin_with_filler_then_dylib(filler_len, "/tmp/evil.dylib");
        assert!(bytes.len() < crate::context::MAX_CONTENT_BYTES);

        let scan = scan_ranged(&bytes[..]);
        assert!(scan.is_macho);
        let image = scan.images.first().expect("the thin slice must be walked");
        assert_eq!(image.dylibs, vec!["/tmp/evil.dylib".to_string()]);
    }

    /// A thin Mach-O whose declared `sizeofcmds` overruns the whole (complete,
    /// non-truncated) file, not just `MAX_SIZEOFCMDS`: none of that excess is
    /// real I/O to bound, so the slice must still be walked up to EOF rather
    /// than skipped outright (§5.2, #45).
    #[test]
    fn scan_ranged_walks_a_thin_slice_whose_sizeofcmds_overruns_the_whole_file() {
        let (mut bytes, _, _) =
            synth_macho_64_full(b"evil", &["/tmp/evil.dylib"], &[], false, None);
        let huge = 0x1000_0000u32; // far beyond both MAX_SIZEOFCMDS and the file itself
        bytes[20..24].copy_from_slice(&huge.to_le_bytes()); // sizeofcmds, LE u32 @ offset 20

        let scan = scan_ranged(&bytes[..]);
        assert!(scan.is_macho);
        assert_eq!(scan.skipped_slices, 0);
        let image = scan
            .images
            .first()
            .expect("the thin slice must still be walked");
        assert_eq!(image.dylibs, vec!["/tmp/evil.dylib".to_string()]);
    }

    /// An ≤8 MiB fat file of decoy slices, each declaring `sizeofcmds` near
    /// `MAX_SIZEOFCMDS`, followed by one real, malicious slice: the whole
    /// file is held in memory, so none of it should be charged against the
    /// ranged budget, leaving it for the real slice (§5.2, #45).
    #[test]
    fn scan_ranged_decoy_slices_within_the_held_prefix_do_not_exhaust_the_budget() {
        const DECOY_COUNT: usize = 32;
        const DECOY_HEADER_LEN: usize = 32; // mach_header_64
        let (real, _, _) = synth_macho_64_full(b"evil", &["/tmp/evil.dylib"], &[], false, None);

        let nfat = DECOY_COUNT + 1;
        let header_len = 8 + 20 * nfat;
        let decoys_start = (header_len + 15) & !15;
        let real_off = decoys_start + DECOY_COUNT * DECOY_HEADER_LEN;

        let mut fat = Vec::new();
        fat.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        fat.extend_from_slice(&(nfat as u32).to_be_bytes());
        for i in 0..DECOY_COUNT {
            let off = decoys_start + i * DECOY_HEADER_LEN;
            fat.extend_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
            fat.extend_from_slice(&(i as u32).to_be_bytes()); // cpusubtype (distinct)
            fat.extend_from_slice(&(off as u32).to_be_bytes()); // offset
            fat.extend_from_slice(&(DECOY_HEADER_LEN as u32).to_be_bytes()); // size
            fat.extend_from_slice(&0u32.to_be_bytes()); // align
        }
        fat.extend_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
        fat.extend_from_slice(&(DECOY_COUNT as u32).to_be_bytes()); // cpusubtype
        fat.extend_from_slice(&(real_off as u32).to_be_bytes()); // offset
        fat.extend_from_slice(&(real.len() as u32).to_be_bytes()); // size
        fat.extend_from_slice(&0u32.to_be_bytes()); // align

        fat.resize(decoys_start, 0);
        for _ in 0..DECOY_COUNT {
            // A minimal, hollow (ncmds=0) mach_header_64 declaring a huge
            // sizeofcmds — real bytes, no load commands to actually walk.
            fat.extend_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // magic
            fat.extend_from_slice(&[0u8; 16]); // cputype, cpusubtype, filetype, ncmds=0
            fat.extend_from_slice(&(MAX_SIZEOFCMDS as u32).to_le_bytes()); // sizeofcmds
            fat.extend_from_slice(&[0u8; 8]); // flags, reserved
        }
        assert_eq!(fat.len(), real_off);
        fat.extend_from_slice(&real);

        // Pad well past every decoy's declared (header + sizeofcmds) span so
        // the whole file — decoys included — is genuinely all held.
        let min_len = decoys_start + DECOY_HEADER_LEN + MAX_SIZEOFCMDS + 4096;
        fat.resize(fat.len().max(min_len), 0);
        assert!(
            fat.len() < 8 * 1024 * 1024,
            "fixture must stay an <=8 MiB file"
        );

        let scan = scan_ranged(&fat[..]);
        assert!(scan.is_macho);
        let evil = scan
            .images
            .iter()
            .find(|img| img.dylibs.contains(&"/tmp/evil.dylib".to_string()))
            .expect("the real slice, last in the table, must still be examined");
        assert_eq!(evil.dylibs, vec!["/tmp/evil.dylib".to_string()]);
    }

    /// A `ByteSource` wrapper that counts every byte actually served, so a
    /// test can confirm `scan_ranged` never reads past its own budget.
    struct CountingSource<'a> {
        data: &'a [u8],
        served: std::cell::Cell<u64>,
    }

    impl ByteSource for CountingSource<'_> {
        fn source_len(&self) -> u64 {
            self.data.source_len()
        }

        fn read_range(&self, off: u64, len: usize) -> Option<Cow<'_, [u8]>> {
            let bytes = self.data.read_range(off, len)?;
            self.served.set(self.served.get() + bytes.len() as u64);
            Some(bytes)
        }
    }

    /// A hostile fat table of `MAX_FAT_ARCHES` distinct offsets, each
    /// pointing at its own big-ish (but otherwise ordinary) valid slice, must
    /// stop reading once `MAX_RANGED_BYTES` is exhausted rather than walk
    /// every declared arch — and must never read more than that budget while
    /// doing it (#45; the fat-table analogue of #46's bogus-arch flood).
    #[test]
    fn scan_ranged_hostile_fat_table_stops_at_the_ranged_budget() {
        // One real slice with a single, deliberately huge LC_RPATH so each
        // copy of it is "big-ish" (~80 KiB) without needing thousands of
        // load commands.
        let huge_rpath = format!("/{}", "a".repeat(79_800));
        let (slice, _, _) = synth_macho_64_full(b"code", &[], &[&huge_rpath], false, None);

        let count = MAX_FAT_ARCHES as usize;
        let header_len = 8 + 20 * count;
        let stride = (slice.len() + 15) & !15; // 16-byte aligned, as `synth_fat` does
        let mut offsets = Vec::with_capacity(count);
        let mut cursor = (header_len + 15) & !15;
        for _ in 0..count {
            offsets.push(cursor);
            cursor += stride;
        }

        let total_slice_bytes = count as u64 * stride as u64;
        assert!(
            total_slice_bytes > MAX_RANGED_BYTES,
            "the fixture must actually exceed the budget to exercise it"
        );

        let mut fat = Vec::new();
        fat.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        fat.extend_from_slice(&(count as u32).to_be_bytes());
        for (i, &off) in offsets.iter().enumerate() {
            fat.extend_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
            fat.extend_from_slice(&(i as u32).to_be_bytes()); // cpusubtype (distinct)
            fat.extend_from_slice(&(off as u32).to_be_bytes()); // offset
            fat.extend_from_slice(&(slice.len() as u32).to_be_bytes()); // size
            fat.extend_from_slice(&0u32.to_be_bytes()); // align
        }
        for &off in &offsets {
            fat.resize(off, 0);
            fat.extend_from_slice(&slice);
        }

        let counting = CountingSource {
            data: &fat,
            served: std::cell::Cell::new(0),
        };
        let scan = scan_ranged(&counting);

        assert!(scan.is_macho);
        assert!(
            scan.images.len() < count,
            "the budget must leave some declared arches unread"
        );
        assert_eq!(scan.images.len() + scan.skipped_slices, count);
        assert!(
            counting.served.get() <= MAX_RANGED_BYTES,
            "read {} bytes against a {MAX_RANGED_BYTES}-byte budget",
            counting.served.get()
        );
    }

    /// A signature region whose `dataoff + datasize` runs past the source's
    /// total length must not be read — `signature_region_read` stays false,
    /// distinct from `has_code_signature` staying true (the load command
    /// itself is intact).
    #[test]
    fn scan_ranged_signature_past_source_len_is_not_read() {
        let (mut image, _, sig_off) = synth_macho_64_full(b"code", &[], &[], true, None);
        let lc_off = image
            .windows(4)
            .position(|w| w == LC_CODE_SIGNATURE.to_le_bytes())
            .expect("LC_CODE_SIGNATURE present");
        let real_len = (image.len() - sig_off) as u32;
        let huge = real_len + 1000; // runs 1000 bytes past the end of the file
        image[lc_off + 12..lc_off + 16].copy_from_slice(&huge.to_le_bytes());

        let scan = scan_ranged(&image[..]);
        assert!(scan.is_macho);
        let img = scan.images.first().expect("thin slice should still parse");
        assert!(img.has_code_signature);
        assert!(!img.signature_region_read);
    }
}
