//! Containers the engine cannot look inside, or could not read in full
//! (§6.2, §10, §11.8).

use super::{zip_member, Rule, RuleOutcome};
use crate::context::{ContentSource, ScanContext};
use crate::macho::ByteSource;
use crate::model::{MatchedSignal, SignalCategory};
use crate::zip;

/// Id of the signal [`UninspectedContainerRule`] emits.
pub const UNINSPECTED_CONTAINER_ID: &str = "uninspected-container";

/// Where a disk-image magic sits.
#[derive(Clone, Copy)]
enum Anchor {
    Start(u64),
    /// Offset back from the end of the file.
    End(u64),
}

/// Mountable disk-image formats and their magics, probed in order. UDIF's
/// 4-byte `koly` is deliberately not version-checked; HFS+/HFSX include the
/// version word because the bare signature false-matches other files.
const IMAGE_FORMATS: &[(&str, Anchor, &[u8])] = &[
    ("UDIF", Anchor::End(512), b"koly"),
    ("sparse", Anchor::Start(0), b"sprs"),
    ("raw GPT", Anchor::Start(512), b"EFI PART"),
    ("raw APFS", Anchor::Start(32), b"NXSB"),
    ("raw HFS+", Anchor::Start(1024), b"H+\x00\x04"),
    ("raw HFS+", Anchor::Start(1024), b"HX\x00\x05"),
    ("ISO 9660", Anchor::Start(0x8001), b"CD001"),
];

/// Flags a mountable disk image, or a zip not read in full, as not
/// inspected. Weight 0: it only marks the scan incomplete so the file never
/// reads as clean (§10, §11.8).
#[derive(Debug, Default, Clone, Copy)]
pub struct UninspectedContainerRule;

/// The disk-image format of `ctx`. Outer `None`: length unknown or an
/// in-range probe could not be read. Inner `None`: not a disk image. A probe
/// that falls outside the file is "not this format", not a read failure.
pub(super) fn disk_image_format(ctx: &ScanContext) -> Option<Option<&'static str>> {
    let len = ctx.file_len?;
    for &(name, anchor, magic) in IMAGE_FORMATS {
        let offset = match anchor {
            Anchor::Start(o) => o,
            Anchor::End(back) => match len.checked_sub(back) {
                Some(o) => o,
                None => continue,
            },
        };
        if offset.saturating_add(magic.len() as u64) > len {
            continue;
        }
        if ctx.read_at(offset, magic.len())? == magic {
            return Some(Some(name));
        }
    }
    Some(None)
}

/// True when `ctx` is ZIP-format ([`zip::is_zip_format`]): a local file
/// header at 0, or an end record with entries whose comment reaches the end
/// of the file (prefixed, self-extracting and commented zips). Reads the
/// last 64 KiB from the file. `None` if an in-range probe could not be read.
fn is_zip(ctx: &ScanContext) -> Option<bool> {
    let len = ctx.file_len?;
    let head = ctx.read_at(0, len.min(4) as usize)?;
    let tail_len = len.min(zip::END_SEARCH_LEN as u64);
    let tail = ctx.read_at(len - tail_len, tail_len as usize)?;
    Some(zip::is_zip_format(&head, &tail))
}

/// True for a real file at `<...>/X.app/Contents/...` (§6.2): apps ship ZIP
/// resources, so those are not flagged. Embedded content is never exempt.
pub(super) fn inside_app_bundle(ctx: &ScanContext) -> bool {
    if ctx.source != ContentSource::File {
        return false;
    }
    // Judge where the file really is, not how its path is spelled (`..`,
    // symlinks, relative paths).
    let Ok(real) = std::fs::canonicalize(&ctx.path) else {
        return false;
    };
    let mut parts = real.components().map(|c| c.as_os_str()).peekable();
    while let Some(name) = parts.next() {
        let b = name.as_encoded_bytes();
        let is_app = b.len() > 4 && b[b.len() - 4..].eq_ignore_ascii_case(b".app");
        if is_app && parts.peek().is_some_and(|n| *n == "Contents") {
            return true;
        }
    }
    false
}

/// Gaps shown in the description before the rest are counted.
const SHOWN_GAPS: usize = 3;

fn not_fully_inspected(gaps: &[String]) -> String {
    let mut shown = gaps[..gaps.len().min(SHOWN_GAPS)].join("; ");
    if gaps.len() > SHOWN_GAPS {
        shown.push_str(&format!("; {} more", gaps.len() - SHOWN_GAPS));
    }
    format!("ZIP-format file not fully inspected ({shown}) — extract it and scan the files")
}

impl UninspectedContainerRule {
    fn signal(&self, ctx: &ScanContext, description: String) -> MatchedSignal {
        ctx.mark_incomplete(self.id());
        MatchedSignal {
            id: self.id().to_string(),
            weight: 0,
            description,
            category: self.category(),
        }
    }
}

impl Rule for UninspectedContainerRule {
    fn id(&self) -> &'static str {
        UNINSPECTED_CONTAINER_ID
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::Informational
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        if ctx.content.is_none() {
            return Err(RuleOutcome::NotApplicable);
        }
        // Truncated embedded content has no real end to probe.
        if ctx.truncated && !ctx.source_len_is_authoritative() {
            return Err(RuleOutcome::NotApplicable);
        }
        match disk_image_format(ctx) {
            None => Err(RuleOutcome::NotApplicable),
            Some(Some(format)) => Ok(Some(self.signal(
                ctx,
                format!(
                    "disk image ({format}) not inspected — mount it read-only and scan the volume"
                ),
            ))),
            Some(None) => match is_zip(ctx) {
                None => Err(RuleOutcome::NotApplicable),
                Some(false) => Ok(None),
                Some(true) if inside_app_bundle(ctx) => Ok(None),
                Some(true) => match zip_member::inspection(ctx) {
                    None => Ok(Some(self.signal(
                        ctx,
                        "ZIP-format file (archive or document) over the read limit, not inspected — extract it and scan the files"
                            .to_string(),
                    ))),
                    Some(read) if read.gaps.is_empty() => Ok(None),
                    Some(read) => Ok(Some(self.signal(ctx, not_fully_inspected(&read.gaps)))),
                },
            },
        }
    }

    /// Reads the file's tail itself, so a truncated prefix does not matter.
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::MAX_CONTENT_BYTES;
    use crate::model::{Recommendation, ScanCompleteness};
    use crate::scan::scan_context;
    use crate::test_support::{sparse_temp_file, write_at};

    fn embedded(buf: Vec<u8>) -> ScanContext {
        ScanContext::from_embedded_bytes("x.dmg", buf, false)
    }

    fn with_koly_at(len: usize, at: usize) -> ScanContext {
        let mut buf = vec![0u8; len];
        buf[at..at + 4].copy_from_slice(b"koly");
        embedded(buf)
    }

    fn fires(ctx: &ScanContext) -> bool {
        UninspectedContainerRule.evaluate(ctx).unwrap().is_some()
    }

    fn with_magic_at(len: usize, at: usize, magic: &[u8]) -> ScanContext {
        let mut buf = vec![0u8; len];
        buf[at..at + magic.len()].copy_from_slice(magic);
        embedded(buf)
    }

    fn format_of(ctx: &ScanContext) -> Option<&'static str> {
        disk_image_format(ctx).expect("readable")
    }

    #[test]
    fn truncated_embedded_content_is_not_applicable() {
        let mut buf = vec![0u8; 1024];
        buf[512..516].copy_from_slice(b"koly");
        let ctx = ScanContext::from_embedded_bytes("x.dmg", buf, true);
        assert_eq!(
            UninspectedContainerRule.evaluate(&ctx).unwrap_err(),
            RuleOutcome::NotApplicable
        );
    }

    #[test]
    fn each_format_is_detected_and_named() {
        let cases: &[(&str, usize, &[u8])] = &[
            ("UDIF", 0x9000 - 512, b"koly"),
            ("sparse", 0, b"sprs"),
            ("raw GPT", 512, b"EFI PART"),
            ("raw APFS", 32, b"NXSB"),
            ("raw HFS+", 1024, b"H+\x00\x04"),
            ("raw HFS+", 1024, b"HX\x00\x05"),
            ("ISO 9660", 0x8001, b"CD001"),
        ];
        for &(name, at, magic) in cases {
            let ctx = with_magic_at(0x9000, at, magic);
            assert_eq!(format_of(&ctx), Some(name), "{name}");
            let sig = UninspectedContainerRule.evaluate(&ctx).unwrap().unwrap();
            assert!(sig.description.starts_with(&format!("disk image ({name})")));
        }
    }

    #[test]
    fn near_misses_are_not_disk_images() {
        let cases: &[(usize, &[u8])] = &[
            (0, b"spro"),
            (512, b"EFI PARU"),
            (32, b"NXSC"),
            (1024, b"H+\x00\x05"),
            (1024, b"HX\x00\x04"),
            (1024, b"H+\x00\x03"),
            (0x8001, b"CD002"),
        ];
        for &(at, magic) in cases {
            let ctx = with_magic_at(0x9000, at, magic);
            assert_eq!(format_of(&ctx), None, "{magic:?} at {at}");
        }
    }

    #[test]
    fn buffers_too_short_for_a_probe_are_not_disk_images() {
        // Magic ends exactly at the buffer end vs. one byte short of it.
        assert_eq!(
            format_of(&with_magic_at(0x8001 + 5, 0x8001, b"CD001")),
            Some("ISO 9660")
        );
        let mut short = vec![0u8; 0x8001 + 4];
        short[0x8001..].copy_from_slice(b"CD00");
        assert_eq!(format_of(&embedded(short)), None);
        assert_eq!(format_of(&embedded(b"EFI PART".to_vec())), None);
        assert_eq!(format_of(&embedded(Vec::new())), None);
    }

    #[test]
    fn trailer_signature_fires() {
        let ctx = with_koly_at(1024, 1024 - 512);
        assert!(fires(&ctx));
        assert!(ctx.marked_incomplete("uninspected-container"));
    }

    #[test]
    fn signature_elsewhere_does_not_fire() {
        for at in [0, 1024 - 511, 1024 - 4] {
            assert!(!fires(&with_koly_at(1024, at)), "koly at {at}");
        }
    }

    #[test]
    fn short_and_plain_inputs_do_not_fire() {
        assert!(!fires(&with_koly_at(511, 0)));
        assert!(!fires(&embedded(b"#!/bin/sh\necho hi\n".repeat(100))));
        assert!(!fires(&embedded(Vec::new())));
    }

    #[test]
    fn tail_past_the_content_cap_is_read() {
        let len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("udif-tail", len);
        write_at(&path, len - 512, b"koly");
        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(UninspectedContainerRule)];
        let result = scan_context(&ctx, &rules);
        let _ = std::fs::remove_file(&path);
        assert_eq!(result.signals.len(), 1);
        assert_eq!(result.completeness, ScanCompleteness::Partial);
    }

    fn eocd(comment_len: u16, prefix: usize) -> Vec<u8> {
        let mut buf = vec![0u8; prefix];
        buf.extend_from_slice(b"PK\x05\x06");
        // One entry in total (offset 10), so it is not an empty archive.
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        buf.extend_from_slice(&comment_len.to_le_bytes());
        buf
    }

    #[test]
    fn zip_local_header_fires() {
        let ctx = embedded(b"PK\x03\x04rest".to_vec());
        assert!(fires(&ctx));
        assert!(ctx.marked_incomplete("uninspected-container"));
        let sig = UninspectedContainerRule.evaluate(&ctx).unwrap().unwrap();
        assert!(sig.description.starts_with("ZIP-format file"));
    }

    #[test]
    fn zip_end_record_with_empty_comment_fires() {
        assert!(fires(&embedded(eocd(0, 0))));
        assert!(fires(&embedded(eocd(0, 100))));
    }

    #[test]
    fn zip_end_record_with_a_comment_reaching_the_end_fires() {
        let mut commented = eocd(5, 100);
        commented.extend(b"hello");
        assert!(fires(&embedded(commented)));
    }

    #[test]
    fn zip_end_record_with_a_comment_or_elsewhere_does_not_fire() {
        assert!(!fires(&embedded(eocd(5, 100))));
        let mut late = eocd(0, 100);
        late.push(0);
        assert!(!fires(&embedded(late)));
    }

    #[test]
    fn short_and_random_inputs_are_not_zip() {
        for buf in [
            Vec::new(),
            b"PK\x03".to_vec(),
            b"PK\x05\x06".to_vec(),
            crate::test_support::xorshift_bytes(4096),
        ] {
            assert!(!fires(&embedded(buf)));
        }
    }

    /// A fresh, empty temp directory, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(tag: &str) -> TempDir {
        let p = crate::test_support::write_temp_file(tag, b"");
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    fn file_in(dir: &std::path::Path, rel: &str, body: &[u8]) -> ScanContext {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
        ScanContext::load(&path)
    }

    #[test]
    fn zip_inside_app_bundle_is_exempt_only_for_real_files() {
        let tmp = temp_dir("zip-app");
        let dir = &tmp.0;
        let zip = b"PK\x03\x04rest";
        assert!(!fires(&file_in(dir, "X.app/Contents/Resources/r.zip", zip)));
        assert!(!fires(&file_in(dir, "y.APP/Contents/r.zip", zip)));
        assert!(fires(&file_in(dir, "r.zip", zip)));
        assert!(fires(&file_in(dir, "X.app/Other/r.zip", zip)));
        assert!(fires(&file_in(dir, "X.app/r.zip", zip)));
        let label = ScanContext::from_embedded_bytes("X.app/Contents/r.zip", zip.to_vec(), false);
        assert!(fires(&label));
        let mut dmg = vec![0u8; 1024];
        dmg[512..516].copy_from_slice(b"koly");
        assert!(fires(&file_in(dir, "X.app/Contents/Resources/i.dmg", &dmg)));
        // The spelling of the path must not create an exemption.
        let dotdot = dir.join("X.app/Contents/../../r.zip");
        assert!(fires(&ScanContext::load(&dotdot)));
        let link = dir.join("X.app/Contents/Resources/link.zip");
        std::os::unix::fs::symlink(dir.join("r.zip"), &link).unwrap();
        assert!(fires(&ScanContext::load(&link)));
    }

    #[test]
    fn empty_zip_is_not_flagged() {
        assert!(!fires(&embedded(
            b"PK\x05\x06".iter().copied().chain([0; 18]).collect()
        )));
    }

    #[test]
    fn fixture_disk_image_scans_partial_and_indeterminate() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/suspicious/dropper_in_disk_image.dmg");
        let result = crate::scan::scan_file(&path);
        assert!(result
            .signals
            .iter()
            .any(|s| s.id == "uninspected-container"));
        assert_eq!(result.completeness, ScanCompleteness::Partial);
        assert_eq!(result.recommendation, Recommendation::NoAction);
        assert_eq!(result.score, 0);
        assert_eq!(
            crate::presentation::for_result(&result),
            crate::presentation::INDETERMINATE
        );
    }
}
