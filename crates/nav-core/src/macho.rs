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

// CS_BlobIndex slot types (cs_blobs.h) identifying a blob's role within the
// SuperBlob.
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_ENTITLEMENTS: u32 = 5;

// Loop ceilings — far above any real Mach-O, but bound work on hostile input.
const MAX_NCMDS: u32 = 4096;
const MAX_NSECTS: u32 = 4096;
const MAX_DYLIBS: usize = 4096;
const MAX_RPATHS: usize = 256;
const MAX_LC_STR_BYTES: usize = 4096;
const MAX_CS_BLOBS: u32 = 256;
const MAX_ENTITLEMENTS_BYTES: usize = 256 * 1024;

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
    /// The `flags` field of the slot-0 CodeDirectory in the embedded code
    /// signature's SuperBlob (`CS_ADHOC` etc., `<Security/CSCommon.h>`).
    /// `None` if there's no signature, no CodeDirectory found, or the
    /// signature region lies past the bytes this parser holds — never read as
    /// "not ad-hoc".
    pub code_directory_flags: Option<u32>,
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
    parse_all(data).into_iter().next()
}

/// Parse **every** Mach-O image in `data`: a single thin image, or all
/// architecture slices of a fat/universal binary this parser can walk, in
/// fat-table order. Empty for non-Mach-O input, a truncated stub, or a fat
/// container with no walkable slice (incl. a Java `.class`). Structure rules
/// iterate this so a fat binary is judged on all its slices, not just the
/// first (§5.2).
pub fn parse_all(data: &[u8]) -> Vec<MachOImage> {
    match be_u32(data, 0) {
        Some(FAT_MAGIC) | Some(FAT_MAGIC_64) => parse_fat_all(data),
        Some(magic) => match thin_kind(magic) {
            Some((is_64, be)) => parse_thin(data, 0, is_64, be, false).into_iter().collect(),
            None => Vec::new(),
        },
        None => Vec::new(),
    }
}

/// Whether `data` begins with any Mach-O magic (thin, either word size/endian,
/// or fat). Cheaper and broader than [`parse`] — answers "is this a code object
/// at all", including images `parse` declines to walk.
pub fn is_macho_magic(data: &[u8]) -> bool {
    match be_u32(data, 0) {
        Some(FAT_MAGIC) | Some(FAT_MAGIC_64) => plausible_fat_header(data).is_some(),
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

/// Real universal binaries carry a handful of architecture slices; a Java
/// `.class` file shares `FAT_MAGIC` with its minor/major version sitting
/// where `nfat_arch` would be, and major versions are 45 and up (JDK 1.1
/// onward) — so a plausible fat header caps `nfat_arch` well below that.
const MAX_PLAUSIBLE_FAT_ARCHES: u32 = 19;

/// Recognize a plausible fat/universal Mach-O header: `FAT_MAGIC`/
/// `FAT_MAGIC_64` with a small, nonzero `nfat_arch` — rejecting a Java
/// `.class` file, which shares `FAT_MAGIC` but not this shape. Returns
/// `(is_64, nfat_arch)`.
fn plausible_fat_header(data: &[u8]) -> Option<(bool, u32)> {
    let is_64 = match be_u32(data, 0)? {
        FAT_MAGIC => false,
        FAT_MAGIC_64 => true,
        _ => return None,
    };
    // fat_header (always big-endian): magic(4), nfat_arch(4).
    match be_u32(data, 4) {
        Some(n) if n != 0 && n <= MAX_PLAUSIBLE_FAT_ARCHES => Some((is_64, n)),
        _ => None,
    }
}

/// Walk every arch of a fat/universal binary, collecting the slices this
/// parser can read (in fat-table order). Empty for an implausible fat header
/// (incl. a Java `.class`, see [`plausible_fat_header`]).
fn parse_fat_all(data: &[u8]) -> Vec<MachOImage> {
    let mut out = Vec::new();
    let Some((is_64, nfat)) = plausible_fat_header(data) else {
        return out;
    };
    for i in 0..nfat as usize {
        if let Some(img) = fat_member(data, is_64, i) {
            out.push(img);
        }
    }
    out
}

/// Parse fat arch `i`'s slice, or `None` if its table entry or object offset
/// can't be read within bounds (a bad entry skips just that arch).
fn fat_member(data: &[u8], is_64: bool, i: usize) -> Option<MachOImage> {
    // fat_arch: cputype(4), cpusubtype(4), offset, size, align[, reserved].
    let arch_stride: usize = if is_64 { 32 } else { 20 };
    let arch_off = 8usize.checked_add(i.checked_mul(arch_stride)?)?;
    let obj_off = if is_64 {
        be_u64(data, arch_off.checked_add(8)?)?
    } else {
        be_u32(data, arch_off.checked_add(8)?)? as u64
    };

    // Slice must start within the bytes we hold (and not overflow usize).
    let base = match usize::try_from(obj_off) {
        Ok(b) if b < data.len() => b,
        _ => return None,
    };

    let (is_64_thin, be) = be_u32(data, base).and_then(thin_kind)?;
    parse_thin(data, base, is_64_thin, be, true)
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
            has_code_signature = true;
            // linkedit_data_command: cmd(4), cmdsize(4), dataoff(4), datasize(4).
            if let (Some(dataoff), Some(datasize)) =
                (r.u32(off.checked_add(8)?), r.u32(off.checked_add(12)?))
            {
                let facts = extract_signature_facts(data, base, dataoff, datasize);
                entitlements = facts.entitlements;
                code_directory_flags = facts.code_directory_flags;
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
}

/// Recover the entitlements plist and the slot-0 CodeDirectory's `flags` from
/// a Mach-O's embedded code-signature SuperBlob, in one bounded walk of its
/// blob index. `dataoff`/`datasize` are the `LC_CODE_SIGNATURE` fields
/// (Mach-O endianness); the SuperBlob itself is always big-endian. `base` is
/// where this image begins in `data`. Either field of the result is `None` if
/// its blob is absent or the SuperBlob is malformed; both are `None` if the
/// signature region lies past the bytes held (a truncated capture) — the
/// caller must not read either `None` as a determined fact.
fn extract_signature_facts(
    data: &[u8],
    base: usize,
    dataoff: u32,
    datasize: u32,
) -> SignatureFacts {
    extract_signature_facts_checked(data, base, dataoff, datasize).unwrap_or_default()
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
        } else if slot_type == CSSLOT_CODEDIRECTORY
            && magic == CSMAGIC_CODEDIRECTORY
            && facts.code_directory_flags.is_none()
        {
            // CodeDirectory: magic(4)@0, length(4)@4, version(4)@8, flags(4)@12.
            if blob_off.checked_add(16)? <= sig_end {
                facts.code_directory_flags = be_u32(data, blob_off.checked_add(12)?);
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
        CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_ENTITLEMENTS, CSMAGIC_EMBEDDED_SIGNATURE,
        CSSLOT_CODEDIRECTORY, CSSLOT_ENTITLEMENTS, FAT_MAGIC, LC_CODE_SIGNATURE, LC_LOAD_DYLIB,
        LC_RPATH, LC_SEGMENT_64,
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

    /// A code-signature SuperBlob holding, in slot order, an optional slot-0
    /// CodeDirectory (`cd_flags`, if given) and an optional entitlements blob
    /// (`entitlements_xml`, if given), plus the `LC_CODE_SIGNATURE` command
    /// pointing at it (`dataoff` filled in by the caller once the file offset
    /// is known). `cd_flags: None` omits the CodeDirectory blob entirely, so
    /// existing callers that only pass entitlements produce identical bytes
    /// to before this blob was added.
    fn build_signature_blob(entitlements_xml: Option<&[u8]>, cd_flags: Option<u32>) -> Vec<u8> {
        let mut entries: Vec<(u32, Vec<u8>)> = Vec::new();
        if let Some(flags) = cd_flags {
            // Minimal CodeDirectory: magic(4), length(4), version(4), flags(4).
            let mut cd = Vec::new();
            cd.extend_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
            cd.extend_from_slice(&16u32.to_be_bytes());
            cd.extend_from_slice(&0x0002_0400u32.to_be_bytes()); // version
            cd.extend_from_slice(&flags.to_be_bytes());
            entries.push((CSSLOT_CODEDIRECTORY, cd));
        }
        if let Some(xml) = entitlements_xml {
            let mut blob = Vec::new();
            blob.extend_from_slice(&CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
            blob.extend_from_slice(&((8 + xml.len()) as u32).to_be_bytes());
            blob.extend_from_slice(xml);
            entries.push((CSSLOT_ENTITLEMENTS, blob));
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
            let blob = build_signature_blob(entitlements_xml, cd_flags);
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
}

#[cfg(test)]
mod tests {
    use super::tests_support::{
        synth_fat, synth_macho_64, synth_macho_64_full, synth_macho_64_full_with_cd_flags,
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
        assert!(is_macho_magic(&image));
        // Fat magic counts even though this stub has no usable arch table.
        assert!(is_macho_magic(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 1]));
        // Everything that is plainly not a code object.
        assert!(!is_macho_magic(b"#!/bin/sh\n"));
        assert!(!is_macho_magic(b"xar!"));
        assert!(!is_macho_magic(b"just some text"));
        assert!(!is_macho_magic(b"\x1f\x8b\x08\x00"));
        assert!(!is_macho_magic(b""));
        assert!(!is_macho_magic(b"\xCF\xFA"));
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
        // major versions (JDK 1.1 onward is 45+) land well past
        // MAX_PLAUSIBLE_FAT_ARCHES, unlike any real universal binary's arch
        // count.
        for major in [0x34u32, 0x41] {
            let mut v = vec![0xCA, 0xFE, 0xBA, 0xBE];
            v.extend_from_slice(&major.to_be_bytes());
            v.extend_from_slice(&[0u8; 64]);
            assert!(!is_macho_magic(&v), "major {major:#x}");
            assert!(parse_all(&v).is_empty(), "major {major:#x}");
        }
    }

    #[test]
    fn a_real_fat_header_with_a_handful_of_arches_is_still_macho() {
        let (a, _, _) = synth_macho_64_full(b"aaaa", &[], &[], false, None);
        let (b, _, _) = synth_macho_64_full(b"bbbb", &[], &[], false, None);
        let fat = synth_fat(&[&a, &b]);
        assert!(is_macho_magic(&fat));
        assert_eq!(parse_all(&fat).len(), 2);
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
            synth_macho_64_full_with_cd_flags(b"code", &[], &[], true, None, Some(0x2));
        assert_eq!(parse(&adhoc).unwrap().code_directory_flags, Some(0x2));

        let (identity, _, _) =
            synth_macho_64_full_with_cd_flags(b"code", &[], &[], true, None, Some(0x10000));
        assert_eq!(
            parse(&identity).unwrap().code_directory_flags,
            Some(0x10000)
        );
    }

    #[test]
    fn no_code_directory_blob_is_none_not_zero() {
        let (image, _, _) = synth_macho_64_full(b"code", &[], &[], true, None);
        assert_eq!(parse(&image).unwrap().code_directory_flags, None);
    }

    #[test]
    fn code_directory_pointing_out_of_bounds_yields_none_not_panic() {
        let (mut image, _, sig_off) =
            synth_macho_64_full_with_cd_flags(b"code", &[], &[], true, None, Some(0x2));
        // Chop the file off inside the CodeDirectory blob, same shape as a
        // truncated capture — must not panic and must not fabricate flags.
        image.truncate(sig_off + 8);
        let parsed = parse(&image); // must not panic
        if let Some(img) = parsed {
            assert_eq!(img.code_directory_flags, None);
        }
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
}
