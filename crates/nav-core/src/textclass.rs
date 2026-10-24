//! Script/text vs. opaque-binary classification shared by content rules (§5.2).

use std::path::Path;

/// Below this many bytes a sample is too small to act on: an entropy figure
/// is too noisy, and the printable-prefix fallback can't judge.
pub(crate) const MIN_SAMPLE_BYTES: usize = 256;

/// Known binary formats: the mime types a data URI may carry them under, and
/// the magic bytes their content starts with.
pub(crate) const BINARY_MAGICS: &[(&[&[u8]], &[u8])] = &[
    (&[b"image/png"], b"\x89PNG"),
    (&[b"image/jpeg"], b"\xFF\xD8\xFF"),
    (&[b"image/gif"], b"GIF8"),
    (&[b"image/webp"], b"RIFF"),
    (&[b"font/woff", b"application/font-woff"], b"wOFF"),
    (&[b"font/woff2"], b"wOF2"),
    (&[b"application/pdf"], b"%PDF"),
    (&[b"application/zip"], b"PK\x03\x04"),
    (&[b"application/gzip", b"application/x-gzip"], b"\x1f\x8b"),
];

/// How [`classify_text`] read a file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TextClass {
    /// Opaque binary blob.
    NotText,
    /// Script or text. `container_evidence` is set only for the
    /// printable-prefix fallback, when the prefix has a C0 control byte other
    /// than tab, LF, CR, FF or ESC (NUL included), or a known binary magic;
    /// shebang and script-extension files never carry it.
    Text { container_evidence: bool },
}

/// True if `prefix` starts like a known binary container.
pub(crate) fn starts_with_binary_magic(prefix: &[u8]) -> bool {
    BINARY_MAGICS.iter().any(|(_, m)| prefix.starts_with(m))
        || prefix.starts_with(b"II*\0")
        || prefix.starts_with(b"MM\0*")
        || prefix.get(4..8) == Some(b"ftyp")
}

/// C0 control bytes that are rare in text but frame serialized formats
/// (protobuf tags, lengths); tab, LF, CR, FF and ESC occur in ordinary text.
fn is_serialization_control(b: u8) -> bool {
    b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0C | 0x1B)
}

/// Extensions that mark a file as a script regardless of content.
const SCRIPT_EXTS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "command",
    "scpt",
    "applescript",
    "js",
    "jxa",
    "py",
    "rb",
    "pl",
    "php",
    "ps1",
];

/// Classify `content`/`path` as script/text (which could carry an obfuscated
/// payload) or an opaque binary blob (§5.2).
pub(crate) fn classify_text(content: &[u8], path: &Path) -> TextClass {
    let strong = content.starts_with(b"#!")
        || path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| SCRIPT_EXTS.iter().any(|e| e.eq_ignore_ascii_case(ext)));
    if strong {
        return TextClass::Text {
            container_evidence: false,
        };
    }

    // Extensionless but overwhelmingly printable leading bytes: a text file
    // with a binary blob spliced in.
    let prefix = &content[..content.len().min(512)];
    if prefix.len() < MIN_SAMPLE_BYTES {
        return TextClass::NotText;
    }
    let printable = prefix
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\t' || b == b'\r' || (0x20..=0x7e).contains(&b))
        .count();
    if printable * 100 / prefix.len() < 85 {
        return TextClass::NotText;
    }
    TextClass::Text {
        container_evidence: prefix.iter().any(|&b| is_serialization_control(b))
            || starts_with_binary_magic(prefix),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix_with(at: usize, byte: u8) -> Vec<u8> {
        let mut v = vec![b'a'; 512];
        for i in (63..512).step_by(64) {
            v[i] = b'\n';
        }
        v[at] = byte;
        v
    }

    fn evidence(content: &[u8], path: &str) -> Option<bool> {
        match classify_text(content, Path::new(path)) {
            TextClass::Text { container_evidence } => Some(container_evidence),
            TextClass::NotText => None,
        }
    }

    #[test]
    fn serialization_controls_are_evidence() {
        for b in 0u8..0x20 {
            if matches!(b, 0x09 | 0x0A | 0x0C | 0x0D | 0x1B) {
                continue;
            }
            assert_eq!(
                evidence(&prefix_with(100, b), "model"),
                Some(true),
                "byte {b:#04x}"
            );
        }
    }

    #[test]
    fn ordinary_text_bytes_are_not_evidence() {
        for b in [0x09u8, 0x0A, 0x0C, 0x0D, 0x1B, 0x7F, 0x80] {
            assert_eq!(
                evidence(&prefix_with(100, b), "model"),
                Some(false),
                "byte {b:#04x}"
            );
        }
    }

    #[test]
    fn protobuf_header_is_evidence() {
        let mut v = b"\x08\x08\x12\x07pytorch\x1a\x052.1.0:".to_vec();
        for i in 0.. {
            let n = format!("/encoder/layer.{i}/attention/self/query/MatMul");
            v.extend([0x0a, n.len() as u8]);
            v.extend(n.as_bytes());
            if v.len() >= 512 {
                break;
            }
        }
        assert_eq!(evidence(&v, "model"), Some(true));
    }

    #[test]
    fn shebang_and_script_extension_never_carry_evidence() {
        let mut sh = b"#!/bin/sh\n".to_vec();
        sh.resize(512, b'a');
        sh[100] = 0x08;
        assert_eq!(evidence(&sh, "model"), Some(false));
        assert_eq!(evidence(&prefix_with(100, 0x08), "run.sh"), Some(false));
    }

    #[test]
    fn control_byte_after_prefix_is_ignored() {
        let mut v = prefix_with(100, b'a');
        v.extend([b'a'; 100]);
        v.push(0x08);
        assert_eq!(evidence(&v, "model"), Some(false));
    }
}
