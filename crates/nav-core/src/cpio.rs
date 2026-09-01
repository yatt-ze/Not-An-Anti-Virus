//! Bounded cpio reading, for `.pkg` install scripts (§5.2, §6.1). A package
//! keeps its `preinstall`/`postinstall` scripts in a cpio archive in the xar
//! heap; `pkgbuild` writes **odc** (magic `070707`, 76-byte octal header), not
//! the `newc` most cpio code assumes, so both are handled.
//!
//! **Never writes to disk.** It returns borrowed slices, and names are
//! returned verbatim, not sanitized: `../../../etc/passwd` is a finding for a
//! rule to weigh, not a path this code opens — callers must keep it that way.
//!
//! Hand-written per §3: no panics, every field bounds-checked, explicit
//! ceilings on entry count and total bytes.

/// Header sizes and magics for the two families this reader accepts.
const ODC_MAGIC: &[u8] = b"070707";
const ODC_HEADER: usize = 76;
const NEWC_MAGIC: &[u8] = b"070701";
/// `070702` is `newc` with a CRC field; the layout is identical and the
/// checksum covers file data we do not verify, so it parses the same way.
const NEWC_CRC_MAGIC: &[u8] = b"070702";
const NEWC_HEADER: usize = 110;

/// The name marking the end of an archive.
const TRAILER: &[u8] = b"TRAILER!!!";

/// Ceilings on what a single archive may yield. Far below §6.2's extraction
/// limits: a real `Scripts` archive is under ten small files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpioLimits {
    pub max_entries: usize,
    pub max_total_bytes: usize,
}

impl Default for CpioLimits {
    fn default() -> Self {
        CpioLimits {
            max_entries: 1024,
            max_total_bytes: 4 * 1024 * 1024,
        }
    }
}

/// One archive member. `data` borrows from the archive buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpioEntry<'a> {
    /// Recorded name, trailing NUL removed, invalid UTF-8 replaced. Not
    /// sanitized or normalized — see module docs.
    pub name: String,
    /// True if the name was not valid UTF-8 (itself unusual in an installer).
    pub name_lossy: bool,
    /// Raw mode field, including file-type bits.
    pub mode: u32,
    pub data: &'a [u8],
}

impl CpioEntry<'_> {
    /// True if the file-type bits mark this a regular file (dirs/devices carry
    /// no script content).
    pub fn is_regular_file(&self) -> bool {
        self.mode & 0o170000 == 0o100000
    }
}

/// Why a walk stopped before the trailer. Not "the archive is bad" — the §6.2
/// `scan-halted` shape; the caller degrades completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpioHalt {
    /// Ran out of bytes partway through an entry.
    Truncated,
    /// A header partway in was unreadable (bad magic, non-numeric field).
    Malformed,
    /// Hit [`CpioLimits::max_entries`].
    EntryLimit,
    /// Hit [`CpioLimits::max_total_bytes`].
    ByteLimit,
}

/// A parsed archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpioArchive<'a> {
    pub entries: Vec<CpioEntry<'a>>,
    /// `None` when the walk reached the trailer cleanly. `Some` means
    /// `entries` is a partial view and the caller must say so.
    pub halted: Option<CpioHalt>,
}

impl CpioArchive<'_> {
    /// Whether the archive was read end to end (§10, §11.8).
    pub fn is_complete(&self) -> bool {
        self.halted.is_none()
    }
}

/// Parse a cpio archive.
///
/// `None` if `data` doesn't begin with a recognized cpio magic (not cpio).
/// Anything that starts as cpio but fails later yields a [`CpioArchive`] with
/// the entries read so far plus a [`CpioHalt`].
pub fn parse<'a>(data: &'a [u8], limits: &CpioLimits) -> Option<CpioArchive<'a>> {
    // Confirm it's cpio before committing to a partial result.
    let first = data.get(..6)?;
    if first != ODC_MAGIC && first != NEWC_MAGIC && first != NEWC_CRC_MAGIC {
        return None;
    }

    let mut entries: Vec<CpioEntry<'a>> = Vec::new();
    let mut total: usize = 0;
    let mut off: usize = 0;

    // Past this point never return `None` (which means "not cpio") — a
    // mid-archive failure breaks with a `CpioHalt` instead (§10/§11.8).
    let halted = loop {
        let Some(magic_end) = off.checked_add(6) else {
            break Some(CpioHalt::Malformed);
        };
        let Some(magic) = data.get(off..magic_end) else {
            break Some(CpioHalt::Truncated);
        };

        let parsed = if magic == ODC_MAGIC {
            read_odc(data, off)
        } else if magic == NEWC_MAGIC || magic == NEWC_CRC_MAGIC {
            read_newc(data, off)
        } else {
            break Some(CpioHalt::Malformed);
        };

        let Some(hdr) = parsed else {
            // "Bytes ran out" vs. "bytes are wrong" — only one suggests tampering.
            break Some(if data.len().saturating_sub(off) < NEWC_HEADER {
                CpioHalt::Truncated
            } else {
                CpioHalt::Malformed
            });
        };

        let Some(name_bytes) = data.get(hdr.name_start..hdr.name_end) else {
            break Some(CpioHalt::Truncated);
        };
        // The recorded namesize includes a trailing NUL.
        let name_bytes = name_bytes.strip_suffix(b"\0").unwrap_or(name_bytes);

        if name_bytes == TRAILER {
            break None; // clean end of archive
        }
        if entries.len() >= limits.max_entries {
            break Some(CpioHalt::EntryLimit);
        }
        let Some(running) = total.checked_add(hdr.filesize) else {
            break Some(CpioHalt::Malformed);
        };
        if running > limits.max_total_bytes {
            break Some(CpioHalt::ByteLimit);
        }

        let Some(data_end) = hdr.data_start.checked_add(hdr.filesize) else {
            break Some(CpioHalt::Malformed);
        };
        let Some(body) = data.get(hdr.data_start..data_end) else {
            break Some(CpioHalt::Truncated);
        };

        let name_lossy = std::str::from_utf8(name_bytes).is_err();
        entries.push(CpioEntry {
            name: String::from_utf8_lossy(name_bytes).into_owned(),
            name_lossy,
            mode: hdr.mode,
            data: body,
        });
        total = running;

        let Some(next) = hdr.next_offset(data_end) else {
            break Some(CpioHalt::Malformed);
        };
        // Every iteration must advance, or a zero-size entry could spin.
        if next <= off {
            break Some(CpioHalt::Malformed);
        }
        off = next;
    };

    Some(CpioArchive { entries, halted })
}

/// The fields this reader needs out of a header, plus where the entry's
/// name and data begin.
struct Header {
    mode: u32,
    filesize: usize,
    name_start: usize,
    name_end: usize,
    data_start: usize,
    /// Alignment applied after the name and after the data (1 for odc,
    /// 4 for newc).
    align: usize,
}

impl Header {
    fn next_offset(&self, data_end: usize) -> Option<usize> {
        align_up(data_end, self.align)
    }
}

/// odc: magic(6) dev(6) ino(6) mode(6) uid(6) gid(6) nlink(6) rdev(6)
/// mtime(11) namesize(6) filesize(11), zero-padded octal, then name + data
/// with no padding. Every field is parsed strictly, including the unused ones
/// — garbage anywhere is malformed (the real-archive test vectors prove this
/// doesn't reject genuine output).
fn read_odc(data: &[u8], off: usize) -> Option<Header> {
    let h = data.get(off..off.checked_add(ODC_HEADER)?)?;
    // (start, width) of each numeric field after the 6-byte magic.
    const FIELDS: [(usize, usize); 10] = [
        (6, 6),   // dev
        (12, 6),  // ino
        (18, 6),  // mode
        (24, 6),  // uid
        (30, 6),  // gid
        (36, 6),  // nlink
        (42, 6),  // rdev
        (48, 11), // mtime
        (59, 6),  // namesize
        (65, 11), // filesize
    ];
    let mut values = [0u64; FIELDS.len()];
    for (slot, &(start, width)) in values.iter_mut().zip(FIELDS.iter()) {
        *slot = parse_radix(h.get(start..start.checked_add(width)?)?, 8)?;
    }
    let mode = *values.get(2)?;
    let namesize = *values.get(8)?;
    let filesize = *values.get(9)?;

    // A namesize of zero cannot even hold the terminating NUL.
    if namesize == 0 {
        return None;
    }
    let name_start = off.checked_add(ODC_HEADER)?;
    let name_end = name_start.checked_add(usize::try_from(namesize).ok()?)?;
    Some(Header {
        mode: u32::try_from(mode).ok()?,
        filesize: usize::try_from(filesize).ok()?,
        name_start,
        name_end,
        data_start: name_end,
        align: 1,
    })
}

/// newc: magic(6) then 13 eight-digit hex fields. Name and data are each
/// 4-byte aligned. All 13 fields must parse, as with odc.
fn read_newc(data: &[u8], off: usize) -> Option<Header> {
    let h = data.get(off..off.checked_add(NEWC_HEADER)?)?;
    let mut values = [0u64; 13];
    for (i, slot) in values.iter_mut().enumerate() {
        let start = 6usize.checked_add(i.checked_mul(8)?)?;
        *slot = parse_radix(h.get(start..start.checked_add(8)?)?, 16)?;
    }
    let mode = *values.get(1)?;
    let filesize = *values.get(6)?;
    let namesize = *values.get(11)?;

    if namesize == 0 {
        return None;
    }
    let name_start = off.checked_add(NEWC_HEADER)?;
    let name_end = name_start.checked_add(usize::try_from(namesize).ok()?)?;
    Some(Header {
        mode: u32::try_from(mode).ok()?,
        filesize: usize::try_from(filesize).ok()?,
        name_start,
        name_end,
        data_start: align_up(name_end, 4)?,
        align: 4,
    })
}

fn align_up(v: usize, align: usize) -> Option<usize> {
    if align <= 1 {
        return Some(v);
    }
    let rem = v % align;
    if rem == 0 {
        Some(v)
    } else {
        v.checked_add(align - rem)
    }
}

/// Parse a fixed-width ASCII numeric field. Stricter than `from_str_radix`
/// (which accepts a leading `+`): digits only.
fn parse_radix(field: &[u8], radix: u32) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &c in field {
        let d = char::from(c).to_digit(radix)?;
        v = v.checked_mul(u64::from(radix))?.checked_add(u64::from(d))?;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! vector {
        ($name:literal) => {
            include_bytes!(concat!("../testdata/cpio/", $name, ".cpio")).as_slice()
        };
    }

    fn all_vectors() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("odc_valid", vector!("odc_valid")),
            ("newc_valid", vector!("newc_valid")),
            ("real_scripts", vector!("real_scripts")),
            ("system_odc", vector!("system_odc")),
            ("system_newc", vector!("system_newc")),
            ("bad_magic", vector!("bad_magic")),
            ("odc_non_octal", vector!("odc_non_octal")),
            ("newc_non_hex", vector!("newc_non_hex")),
            ("odc_namesize_zero", vector!("odc_namesize_zero")),
            ("odc_namesize_huge", vector!("odc_namesize_huge")),
            ("odc_filesize_huge", vector!("odc_filesize_huge")),
            ("newc_namesize_huge", vector!("newc_namesize_huge")),
            ("newc_filesize_huge", vector!("newc_filesize_huge")),
            ("odc_truncated_header", vector!("odc_truncated_header")),
            ("odc_truncated_name", vector!("odc_truncated_name")),
            ("odc_truncated_data", vector!("odc_truncated_data")),
            ("odc_no_trailer", vector!("odc_no_trailer")),
            ("empty", vector!("empty")),
            ("odc_trailer_only", vector!("odc_trailer_only")),
            ("odc_name_traversal", vector!("odc_name_traversal")),
            ("odc_name_absolute", vector!("odc_name_absolute")),
            ("odc_name_non_utf8", vector!("odc_name_non_utf8")),
            ("odc_entry_bomb", vector!("odc_entry_bomb")),
        ]
    }

    #[test]
    fn reads_a_synthetic_odc_archive() {
        let a = parse(vector!("odc_valid"), &CpioLimits::default()).expect("should be cpio");
        assert!(a.is_complete());
        assert_eq!(a.entries.len(), 1);
        assert_eq!(a.entries[0].name, "preinstall");
        assert_eq!(a.entries[0].data, b"#!/bin/sh\nexit 0\n");
        assert!(a.entries[0].is_regular_file());
    }

    #[test]
    fn reads_a_synthetic_newc_archive() {
        let a = parse(vector!("newc_valid"), &CpioLimits::default()).expect("should be cpio");
        assert!(a.is_complete());
        assert_eq!(a.entries.len(), 1);
        assert_eq!(a.entries[0].name, "preinstall");
        assert_eq!(a.entries[0].data, b"#!/bin/sh\nexit 0\n");
    }

    /// The archive a real `pkgbuild` package carries — synthetic headers can't
    /// prove we read what the real tool emits.
    #[test]
    fn reads_the_real_pkgbuild_scripts_archive() {
        let a = parse(vector!("real_scripts"), &CpioLimits::default()).expect("should be cpio");
        assert!(a.is_complete(), "halted: {:?}", a.halted);
        let names: Vec<&str> = a.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec![".", "./preinstall"]);

        let script = a
            .entries
            .iter()
            .find(|e| e.name == "./preinstall")
            .expect("preinstall present");
        assert!(script.is_regular_file());
        let text = String::from_utf8_lossy(script.data);
        assert!(text.contains("curl -fsSL"));
        assert!(text.contains("base64 -d"));
        assert!(text.contains("osascript -e"));
        // The directory entry carries no data.
        let dir = a.entries.iter().find(|e| e.name == ".").expect("dir entry");
        assert!(!dir.is_regular_file());
        assert!(dir.data.is_empty());
    }

    /// Archives written by `/usr/bin/cpio` itself, in both formats.
    #[test]
    fn reads_archives_written_by_the_system_tool() {
        for name in ["system_odc", "system_newc"] {
            let bytes: &[u8] = if name == "system_odc" {
                vector!("system_odc")
            } else {
                vector!("system_newc")
            };
            let a = parse(bytes, &CpioLimits::default()).unwrap_or_else(|| panic!("{name}"));
            assert!(a.is_complete(), "{name} halted: {:?}", a.halted);
            let mut names: Vec<&str> = a.entries.iter().map(|e| e.name.as_str()).collect();
            names.sort_unstable();
            assert_eq!(names, vec!["postinstall", "preinstall"], "{name}");
            for e in &a.entries {
                assert_eq!(
                    String::from_utf8_lossy(e.data),
                    format!("#!/bin/sh\necho {}\n", e.name),
                    "{name}/{}",
                    e.name
                );
            }
        }
    }

    /// The full chain: `.pkg` heap bytes are gzip, and only after inflating a
    /// cpio archive. Testing the layers separately would miss a mismatch.
    #[test]
    fn gzip_then_cpio_recovers_the_install_script() {
        let heap_bytes = include_bytes!("../testdata/gzip/real_scripts.in").as_slice();
        let archive_bytes = crate::inflate::gzip_decompress(heap_bytes, 1 << 20)
            .expect("heap entry should be a gzip stream");
        let a = parse(&archive_bytes, &CpioLimits::default()).expect("should inflate to cpio");
        assert!(a.is_complete());
        let script = a
            .entries
            .iter()
            .find(|e| e.name.ends_with("preinstall"))
            .expect("preinstall present");
        assert!(String::from_utf8_lossy(script.data).contains("curl -fsSL"));
    }

    #[test]
    fn non_cpio_input_is_not_a_cpio_archive() {
        assert!(parse(b"", &CpioLimits::default()).is_none());
        assert!(parse(b"#!/bin/sh\n", &CpioLimits::default()).is_none());
        assert!(parse(vector!("empty"), &CpioLimits::default()).is_none());
        // Right shape, wrong magic.
        assert!(parse(vector!("bad_magic"), &CpioLimits::default()).is_none());
    }

    #[test]
    fn an_archive_of_only_a_trailer_is_complete_and_empty() {
        let a = parse(vector!("odc_trailer_only"), &CpioLimits::default()).expect("cpio");
        assert!(a.is_complete());
        assert!(a.entries.is_empty());
    }

    /// A truncated or malformed archive must surface as a halt, never a clean
    /// short read (§10, §11.8).
    #[test]
    fn damage_halts_rather_than_reporting_a_clean_archive() {
        for name in [
            "odc_truncated_header",
            "odc_truncated_name",
            "odc_truncated_data",
            "odc_no_trailer",
            "odc_non_octal",
            "newc_non_hex",
            "odc_namesize_zero",
            "odc_namesize_huge",
            "odc_filesize_huge",
            "newc_namesize_huge",
            "newc_filesize_huge",
        ] {
            let bytes = all_vectors()
                .into_iter()
                .find(|(n, _)| *n == name)
                .map(|(_, b)| b)
                .expect("vector present");
            match parse(bytes, &CpioLimits::default()) {
                None => {} // not cpio at all is also acceptable
                Some(a) => assert!(
                    !a.is_complete(),
                    "{name}: damaged archive reported as complete with {} entries",
                    a.entries.len()
                ),
            }
        }
    }

    /// Corrupts `ino`, a field this reader never consumes — pins the
    /// all-fields strictness in `read_odc`/`read_newc`.
    #[test]
    fn garbage_in_an_unused_field_is_still_malformed() {
        for (name, bytes) in [
            ("odc_non_octal", vector!("odc_non_octal")),
            ("newc_non_hex", vector!("newc_non_hex")),
        ] {
            let a = parse(bytes, &CpioLimits::default())
                .unwrap_or_else(|| panic!("{name}: magic is intact, so this is still cpio"));
            assert_eq!(a.halted, Some(CpioHalt::Malformed), "{name}");
            assert!(a.entries.is_empty(), "{name}");
        }
    }

    #[test]
    fn entry_limit_halts_the_walk() {
        let limits = CpioLimits {
            max_entries: 16,
            ..CpioLimits::default()
        };
        let a = parse(vector!("odc_entry_bomb"), &limits).expect("cpio");
        assert_eq!(a.halted, Some(CpioHalt::EntryLimit));
        assert_eq!(a.entries.len(), 16);
    }

    #[test]
    fn byte_limit_halts_the_walk() {
        let limits = CpioLimits {
            max_total_bytes: 4,
            ..CpioLimits::default()
        };
        // odc_valid's single entry is 17 bytes, over the 4-byte ceiling.
        let a = parse(vector!("odc_valid"), &limits).expect("cpio");
        assert_eq!(a.halted, Some(CpioHalt::ByteLimit));
        assert!(a.entries.is_empty());
    }

    /// Names are reported exactly as recorded — a traversal or absolute name
    /// is evidence for a rule, and must survive intact to be scored.
    #[test]
    fn hostile_names_are_reported_verbatim() {
        let a = parse(vector!("odc_name_traversal"), &CpioLimits::default()).expect("cpio");
        assert_eq!(
            a.entries.first().map(|e| e.name.as_str()),
            Some("../../../etc/passwd")
        );

        let a = parse(vector!("odc_name_absolute"), &CpioLimits::default()).expect("cpio");
        assert_eq!(
            a.entries.first().map(|e| e.name.as_str()),
            Some("/etc/passwd")
        );

        let a = parse(vector!("odc_name_non_utf8"), &CpioLimits::default()).expect("cpio");
        let e = a.entries.first().expect("one entry");
        assert!(e.name_lossy, "invalid UTF-8 in a name should be flagged");
        assert!(e.name.contains('\u{FFFD}'));
    }

    /// A truncated archive may still parse cleanly (block padding after the
    /// trailer), but no prefix may yield *more* entries than the whole
    /// archive — the signature of a reader running off its buffer.
    #[test]
    fn no_prefix_yields_more_than_the_whole_archive() {
        for (name, bytes) in all_vectors() {
            let full = parse(bytes, &CpioLimits::default())
                .map(|a| a.entries.len())
                .unwrap_or(0);
            for n in 0..bytes.len().min(600) {
                let Some(a) = parse(&bytes[..n], &CpioLimits::default()) else {
                    continue;
                };
                assert!(
                    a.entries.len() <= full,
                    "{name}: prefix of {n} bytes yielded {} entries, whole archive has {full}",
                    a.entries.len()
                );
            }
        }
    }

    #[test]
    fn byte_corruption_never_panics_or_hangs() {
        for (_, bytes) in all_vectors() {
            for i in (0..bytes.len().min(400)).step_by(3) {
                for bit in [0u8, 3, 7] {
                    let mut v = bytes.to_vec();
                    if let Some(b) = v.get_mut(i) {
                        *b ^= 1 << bit;
                    }
                    let _ = parse(&v, &CpioLimits::default());
                }
            }
        }
    }

    #[test]
    fn numeric_fields_reject_anything_but_digits() {
        assert_eq!(parse_radix(b"000755", 8), Some(0o755));
        assert_eq!(parse_radix(b"0000001C", 16), Some(28));
        assert_eq!(parse_radix(b"", 8), None);
        assert_eq!(parse_radix(b"00 755", 8), None);
        assert_eq!(parse_radix(b"+00755", 8), None); // from_str_radix would accept
        assert_eq!(parse_radix(b"00075\0", 8), None);
        assert_eq!(parse_radix(b"000778", 8), None); // 8 is not an octal digit
        assert_eq!(parse_radix(b"FFFFFFFF", 16), Some(0xFFFF_FFFF));
    }
}
