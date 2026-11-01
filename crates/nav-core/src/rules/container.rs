//! Containers the engine cannot look inside (§10, §11.8).

use super::{Rule, RuleOutcome};
use crate::context::{ContentSource, ScanContext};
use crate::macho::ByteSource;
use crate::model::{MatchedSignal, SignalCategory};

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

/// Flags a mountable disk image as not inspected. Weight 0: it only marks
/// the scan incomplete so the file never reads as clean (§10, §11.8).
#[derive(Debug, Default, Clone, Copy)]
pub struct UninspectedContainerRule;

/// The disk-image format of `ctx`. Outer `None`: length unknown or an
/// in-range probe could not be read. Inner `None`: not a disk image. A probe
/// that falls outside the file is "not this format", not a read failure.
fn disk_image_format(ctx: &ScanContext) -> Option<Option<&'static str>> {
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

/// Size of an end-of-central-directory record with an empty comment.
const ZIP_EOCD_LEN: u64 = 22;

/// True when `ctx` is ZIP-format: a local file header at 0, or an empty-comment
/// end record in the last 22 bytes. Known gap: a prefixed zip with an archive
/// comment is not found. `None` if an in-range probe could not be read.
fn is_zip(ctx: &ScanContext) -> Option<bool> {
    let len = ctx.file_len?;
    if len >= 4 && ctx.read_at(0, 4)? == b"PK\x03\x04" {
        return Some(true);
    }
    if len >= ZIP_EOCD_LEN {
        let eocd = ctx.read_at(len - ZIP_EOCD_LEN, ZIP_EOCD_LEN as usize)?;
        return Some(&eocd[..4] == b"PK\x05\x06" && eocd[20..] == [0, 0]);
    }
    Some(false)
}

/// True for a real file at `<...>/X.app/Contents/...` (§6.2): apps ship ZIP
/// resources, so those are not flagged. Embedded content is never exempt.
fn inside_app_bundle(ctx: &ScanContext) -> bool {
    if ctx.source != ContentSource::File {
        return false;
    }
    let parts: Vec<_> = ctx.path.components().collect();
    parts.windows(2).any(|w| {
        let name = w[0].as_os_str().to_string_lossy();
        name.len() > 4
            && name.to_ascii_lowercase().ends_with(".app")
            && w[1].as_os_str() == "Contents"
    })
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
            Some(None) if inside_app_bundle(ctx) => Ok(None),
            Some(None) => match is_zip(ctx) {
                None => Err(RuleOutcome::NotApplicable),
                Some(false) => Ok(None),
                Some(true) => Ok(Some(self.signal(
                    ctx,
                    "ZIP-format file (archive or document) not inspected — extract it and scan the files"
                        .to_string(),
                ))),
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
        buf.extend_from_slice(&[0u8; 16]);
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

    /// A fresh temp directory path (not yet created).
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let p = crate::test_support::write_temp_file(tag, b"");
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn file_in(dir: &std::path::Path, rel: &str, body: &[u8]) -> ScanContext {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
        ScanContext::load(&path)
    }

    #[test]
    fn zip_inside_app_bundle_is_exempt_only_for_real_files() {
        let dir = temp_dir("zip-app");
        let zip = b"PK\x03\x04rest";
        assert!(!fires(&file_in(
            &dir,
            "X.app/Contents/Resources/r.zip",
            zip
        )));
        assert!(!fires(&file_in(&dir, "y.APP/Contents/r.zip", zip)));
        assert!(fires(&file_in(&dir, "r.zip", zip)));
        assert!(fires(&file_in(&dir, "X.app/Other/r.zip", zip)));
        assert!(fires(&file_in(&dir, "X.app/r.zip", zip)));
        let label = ScanContext::from_embedded_bytes("X.app/Contents/r.zip", zip.to_vec(), false);
        assert!(fires(&label));
        let mut dmg = vec![0u8; 1024];
        dmg[512..516].copy_from_slice(b"koly");
        assert!(fires(&file_in(
            &dir,
            "X.app/Contents/Resources/i.dmg",
            &dmg
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fixture_zip_scans_partial() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/suspicious/dropper_in_zip.zip");
        let result = crate::scan::scan_file(&path);
        assert!(result
            .signals
            .iter()
            .any(|s| s.id == "uninspected-container"));
        assert_eq!(result.completeness, ScanCompleteness::Partial);
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
