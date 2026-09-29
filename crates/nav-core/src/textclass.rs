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
    /// printable-prefix fallback, when the prefix has a NUL or a known
    /// binary magic; shebang and script-extension files never carry it.
    Text { container_evidence: bool },
}

/// True if `prefix` starts like a known binary container.
pub(crate) fn starts_with_binary_magic(prefix: &[u8]) -> bool {
    BINARY_MAGICS.iter().any(|(_, m)| prefix.starts_with(m))
        || prefix.starts_with(b"II*\0")
        || prefix.starts_with(b"MM\0*")
        || prefix.get(4..8) == Some(b"ftyp")
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
        container_evidence: prefix.contains(&0) || starts_with_binary_magic(prefix),
    }
}
