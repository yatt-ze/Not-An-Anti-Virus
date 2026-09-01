//! The evidence a rule gets to look at. A `ScanContext` is built once per scan
//! from a bounded read, so every rule sees the same evidence and none re-reads
//! the filesystem on its own (which would make TOCTOU — §11.7 — unreasonable).

use std::io::Read;
use std::path::{Path, PathBuf};

/// Cap on how much of a file is read into memory for content rules. Static
/// analysis never needs the whole file, and an unbounded read of hostile input
/// is what §3/§11.9 warn against.
pub const MAX_CONTENT_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

/// Where a [`ScanContext`]'s bytes came from. Rules must consult this before
/// reading meaning into `path`: container-extracted content has no file behind
/// it, so a filesystem check would be testing a label this crate invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentSource {
    /// `path` names a real file read from disk.
    File,
    /// Bytes extracted from inside a container (§5.2, §6.1). `path` is a display
    /// label like `installer.pkg!Scripts/preinstall` and names nothing on disk,
    /// so path/filesystem rules must report `NotApplicable`.
    Embedded,
}

pub struct ScanContext {
    /// The file this content came from, or — when `source` is
    /// [`ContentSource::Embedded`] — a display label that names nothing on
    /// disk.
    pub path: PathBuf,
    /// Bounded prefix of file content. `None` if the file couldn't be read
    /// at all (permissions, FDA gap on macOS, race) — rules must treat that
    /// as "not applicable," never as "clean."
    pub content: Option<Vec<u8>>,
    /// True if `content` was truncated relative to the file's actual size.
    pub truncated: bool,
    pub file_len: Option<u64>,
    pub source: ContentSource,
}

impl ScanContext {
    pub fn load(path: &Path) -> Self {
        let file_len = std::fs::metadata(path).ok().map(|m| m.len());

        let content = std::fs::File::open(path).ok().and_then(|mut f| {
            let mut buf = Vec::new();
            let cap = MAX_CONTENT_BYTES as u64;
            let mut limited = (&mut f).take(cap);
            limited.read_to_end(&mut buf).ok()?;
            Some(buf)
        });

        let truncated = match (&content, file_len) {
            (Some(c), Some(len)) => (c.len() as u64) < len,
            _ => false,
        };

        ScanContext {
            path: path.to_path_buf(),
            content,
            truncated,
            file_len,
            source: ContentSource::File,
        }
    }

    /// Build a context over bytes that never existed as a file — how container
    /// members get scored (Phase 0a writes nothing to disk). `label` is for
    /// display only; [`ContentSource::Embedded`] stops rules treating it as a
    /// path. Set `truncated` when extraction stopped at a budget (§10, §11.8).
    pub fn from_embedded_bytes(
        label: impl Into<PathBuf>,
        content: Vec<u8>,
        truncated: bool,
    ) -> Self {
        let len = content.len() as u64;
        ScanContext {
            path: label.into(),
            content: Some(content),
            truncated,
            file_len: Some(len),
            source: ContentSource::Embedded,
        }
    }

    /// True when this content came from a real file on disk.
    pub fn is_file_backed(&self) -> bool {
        self.source == ContentSource::File
    }

    pub fn readable(&self) -> bool {
        self.content.is_some()
    }
}
