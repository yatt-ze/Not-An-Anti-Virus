//! Minimal, defensive Mach-O parsing (§5.2, §12 Phase 0a): recognize a thin or
//! fat/universal image and locate the file range of `__TEXT,__text`, so the
//! entropy rule can score packed *code* rather than whole files.
//!
//! Parses attacker-controlled input under the §3/§11.9 discipline — no panics,
//! no unbounded reads, every offset bounds-checked, no external crate. Not a
//! general Mach-O reader: it walks only as far as `__TEXT,__text` and returns
//! `None` for anything it can't recognize or bound, so the caller falls
//! through to the script/text rules.

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

// Loop ceilings — far above any real Mach-O, but bound work on hostile input.
const MAX_FAT_ARCHES: u32 = 64;
const MAX_NCMDS: u32 = 4096;
const MAX_NSECTS: u32 = 4096;

/// A recognized Mach-O image and the one thing this parser exists to find:
/// the file range of `__TEXT,__text`.
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
}

/// Parse `data` as a Mach-O image. `Some` only if it begins with a thin or fat
/// header this parser can walk within bounds; `None` for non-Mach-O input,
/// truncated stubs, or a Java `.class` (which shares fat's `0xCAFEBABE`).
pub fn parse(data: &[u8]) -> Option<MachOImage> {
    match be_u32(data, 0)? {
        FAT_MAGIC => parse_fat(data, false),
        FAT_MAGIC_64 => parse_fat(data, true),
        magic => {
            let (is_64, be) = thin_kind(magic)?;
            parse_thin(data, 0, is_64, be, false)
        }
    }
}

/// Whether `data` begins with any Mach-O magic (thin, either word size/endian,
/// or fat). Cheaper and broader than [`parse`] — answers "is this a code object
/// at all", including images `parse` declines to walk.
pub fn is_macho_magic(data: &[u8]) -> bool {
    match be_u32(data, 0) {
        Some(FAT_MAGIC) | Some(FAT_MAGIC_64) => true,
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

fn parse_fat(data: &[u8], is_64: bool) -> Option<MachOImage> {
    // fat_header (always big-endian): magic(4), nfat_arch(4).
    let nfat = be_u32(data, 4)?;
    // A zero/implausible count also rejects a Java `.class` (version number
    // where nfat_arch would be).
    if nfat == 0 || nfat > MAX_FAT_ARCHES {
        return None;
    }

    // fat_arch: cputype(4), cpusubtype(4), offset, size, align[, reserved].
    let arch_stride: usize = if is_64 { 32 } else { 20 };
    for i in 0..nfat as usize {
        let arch_off = 8usize.checked_add(i.checked_mul(arch_stride)?)?;
        let obj_off = if is_64 {
            be_u64(data, arch_off.checked_add(8)?)?
        } else {
            be_u32(data, arch_off.checked_add(8)?)? as u64
        };

        let base = match usize::try_from(obj_off) {
            Ok(b) if b < data.len() => b,
            // Slice starts beyond the bytes we hold (or overflows usize) —
            // can't read this member; try the next arch.
            _ => continue,
        };

        if let Some((is_64_thin, be)) = be_u32(data, base).and_then(thin_kind) {
            if let Some(img) = parse_thin(data, base, is_64_thin, be, true) {
                return Some(img);
            }
        }
    }
    None
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
        if is_segment {
            if let Some(range) = text_segment_range(&r, off, is_64, base) {
                return Some(MachOImage {
                    is_fat,
                    is_64,
                    text_range: Some(range),
                });
            }
        }
        off = cmd_end;
    }

    // A valid Mach-O we walked cleanly, but with no scorable `__TEXT` content.
    Some(MachOImage {
        is_fat,
        is_64,
        text_range: None,
    })
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

/// Test-only Mach-O construction, shared with the entropy rule's tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::LC_SEGMENT_64;
    use std::ops::Range;

    /// Build a minimal valid little-endian 64-bit Mach-O with one `__TEXT`
    /// segment holding one `__text` section of `text_payload`. Returns the
    /// image and the absolute `__text` range within it.
    pub(crate) fn synth_macho_64(text_payload: &[u8]) -> (Vec<u8>, Range<u64>) {
        fn seg_name(name: &[u8]) -> [u8; 16] {
            let mut b = [0u8; 16];
            b[..name.len()].copy_from_slice(name);
            b
        }

        let header_size = 32usize;
        let seg_cmd_size = 72usize; // segment_command_64
        let sect_size = 80usize; // section_64
        let cmdsize = seg_cmd_size + sect_size;
        // Payload goes right after the load commands.
        let text_off = header_size + cmdsize;

        let mut v = Vec::new();
        // --- mach_header_64 (little-endian) ---
        v.extend_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // magic -> BE 0xCFFAEDFE
        v.extend_from_slice(&0x0100_0007u32.to_le_bytes()); // cputype x86_64
        v.extend_from_slice(&3u32.to_le_bytes()); // cpusubtype
        v.extend_from_slice(&2u32.to_le_bytes()); // filetype MH_EXECUTE
        v.extend_from_slice(&1u32.to_le_bytes()); // ncmds
        v.extend_from_slice(&(cmdsize as u32).to_le_bytes()); // sizeofcmds
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved

        // --- LC_SEGMENT_64 for __TEXT ---
        v.extend_from_slice(&LC_SEGMENT_64.to_le_bytes()); // cmd
        v.extend_from_slice(&(cmdsize as u32).to_le_bytes()); // cmdsize
        v.extend_from_slice(&seg_name(b"__TEXT")); // segname[16]
        v.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
        v.extend_from_slice(&0u64.to_le_bytes()); // vmsize
        v.extend_from_slice(&(text_off as u64).to_le_bytes()); // fileoff
        v.extend_from_slice(&(text_payload.len() as u64).to_le_bytes()); // filesize
        v.extend_from_slice(&5u32.to_le_bytes()); // maxprot
        v.extend_from_slice(&5u32.to_le_bytes()); // initprot
        v.extend_from_slice(&1u32.to_le_bytes()); // nsects
        v.extend_from_slice(&0u32.to_le_bytes()); // flags

        // --- section_64 __text ---
        v.extend_from_slice(&seg_name(b"__text")); // sectname[16]
        v.extend_from_slice(&seg_name(b"__TEXT")); // segname[16]
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

        assert_eq!(v.len(), text_off);
        v.extend_from_slice(text_payload);

        let range = text_off as u64..(text_off + text_payload.len()) as u64;
        (v, range)
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::synth_macho_64;
    use super::*;

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
    fn truncated_header_does_not_panic() {
        // A valid magic followed by nothing — exercises the bounds checks.
        for len in 0..48usize {
            let mut v = vec![0xCF, 0xFA, 0xED, 0xFE];
            v.truncate(len.min(4));
            v.resize(len, 0);
            let _ = parse(&v); // must not panic
        }
    }
}
