//! The evidence a rule gets to look at. A `ScanContext` is built once per scan
//! from a bounded read, so every rule sees the same evidence and none re-reads
//! the filesystem on its own (which would make TOCTOU — §11.7 — unreasonable).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Cap on how much of a file is read into memory for content rules. Static
/// analysis never needs the whole file, and an unbounded read of hostile input
/// is what §3/§11.9 warn against.
pub const MAX_CONTENT_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

/// A best-effort stable identity for a file on disk, captured at load so an
/// external check (codesign/spctl) can confirm it still names the same object
/// it read (§11.7). It narrows, not closes, the TOCTOU window: the re-stat runs
/// *after* the tool, so it catches the ordinary "swap the path and leave it
/// swapped" race, but not a swap reverted before the re-stat, nor — given
/// `mtime` granularity and inode reuse — a same-size, same-mtime swap into a
/// reused inode. Not a security guarantee; fd-based scanning (§11.7) is the
/// real close, deferred to Phase 0b+.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectIdentity {
    pub dev: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_secs: i64,
    pub mtime_nanos: i64,
}

impl ObjectIdentity {
    /// Snapshot the identity of the file at `path`, or `None` if it can't be
    /// stat'd (missing, permission, race).
    pub fn of_path(path: &Path) -> Option<Self> {
        Some(Self::from_metadata(&std::fs::metadata(path).ok()?))
    }

    #[cfg(unix)]
    fn from_metadata(md: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: md.dev(),
            inode: md.ino(),
            size: md.size(),
            mtime_secs: md.mtime(),
            mtime_nanos: md.mtime_nsec(),
        }
    }

    #[cfg(not(unix))]
    fn from_metadata(md: &std::fs::Metadata) -> Self {
        let (secs, nanos) = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| (d.as_secs() as i64, d.subsec_nanos() as i64))
            .unwrap_or((0, 0));
        Self {
            dev: 0,
            inode: 0,
            size: md.len(),
            mtime_secs: secs,
            mtime_nanos: nanos,
        }
    }
}

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
    /// Identity of the file when its bytes were read, for a real file — used to
    /// confirm a later path-based tool (codesign/spctl) sees the same object
    /// (§11.7). `None` for embedded content or when the stat failed at load.
    pub identity: Option<ObjectIdentity>,
    pub source: ContentSource,
    /// Memoized `codesign -dv` spawn (§5.2) — `None` means the spawn failed
    /// or the platform can't run it. Several rules ask about the same file.
    /// `pub(crate)` so test helpers elsewhere can build a `ScanContext` by
    /// struct literal; use [`ScanContext::codesign_dv`] to read it.
    pub(crate) codesign_dv_cache: OnceLock<Option<(bool, String)>>,
    /// Memoized `spctl` assessment spawn (§5.2), same reasoning as above.
    pub(crate) spctl_cache: OnceLock<Option<String>>,
}

impl ScanContext {
    pub fn load(path: &Path) -> Self {
        // Open first, then derive identity and length from the *opened* file
        // (fstat on the handle) and read the bytes through that same handle, so
        // the captured identity describes the object whose bytes were actually
        // scanned — not a separate pre-open `stat` an attacker could race in
        // the gap before the read (§11.7). A path swapped before the open is
        // simply a different object opened, read, and identified consistently.
        let opened = std::fs::File::open(path).ok().and_then(|mut f| {
            let md = f.metadata().ok()?;
            let identity = ObjectIdentity::from_metadata(&md);
            let mut buf = Vec::new();
            (&mut f)
                .take(MAX_CONTENT_BYTES as u64)
                .read_to_end(&mut buf)
                .ok()?;
            Some((buf, identity, md.len()))
        });

        let (content, identity, file_len) = match opened {
            Some((buf, identity, len)) => (Some(buf), Some(identity), Some(len)),
            None => (None, None, None),
        };

        let truncated = match (&content, file_len) {
            (Some(c), Some(len)) => (c.len() as u64) < len,
            _ => false,
        };

        ScanContext {
            path: path.to_path_buf(),
            content,
            truncated,
            file_len,
            identity,
            source: ContentSource::File,
            codesign_dv_cache: OnceLock::new(),
            spctl_cache: OnceLock::new(),
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
            identity: None,
            source: ContentSource::Embedded,
            codesign_dv_cache: OnceLock::new(),
            spctl_cache: OnceLock::new(),
        }
    }

    /// True when this content came from a real file on disk.
    pub fn is_file_backed(&self) -> bool {
        self.source == ContentSource::File
    }

    pub fn readable(&self) -> bool {
        self.content.is_some()
    }

    /// Runs `spawn` at most once per scan and returns the cached
    /// `codesign -dv` result. `None` means the spawn failed, doesn't apply on
    /// this platform, or the file changed identity between the content read
    /// and the tool call (§11.7) — in which case the result can't be trusted.
    pub fn codesign_dv(
        &self,
        spawn: impl FnOnce() -> Option<(bool, String)>,
    ) -> Option<(bool, String)> {
        self.codesign_dv_cache
            .get_or_init(|| self.spawn_if_object_stable(spawn))
            .clone()
    }

    /// Runs `spawn` at most once per scan and returns the cached `spctl`
    /// assessment output. `None` means the spawn failed, doesn't apply on
    /// this platform, or the object changed under the path (§11.7).
    pub fn spctl_assessment(&self, spawn: impl FnOnce() -> Option<String>) -> Option<String> {
        self.spctl_cache
            .get_or_init(|| self.spawn_if_object_stable(spawn))
            .clone()
    }

    /// Run a path-based external check bound to the scanned object's identity,
    /// the same guarantee [`Self::codesign_dv`]/[`Self::spctl_assessment`] give
    /// through their caches — for a check that isn't memoized on the context
    /// (e.g. `codesign --verify`). The result is dropped (`None`) if the file
    /// changed identity since load, so a tool that inspected a swapped object
    /// is treated as inconclusive, not trusted (§11.7). Embedded content and
    /// files whose identity couldn't be captured pass through unchanged.
    pub fn run_object_bound<T>(&self, spawn: impl FnOnce() -> Option<T>) -> Option<T> {
        self.spawn_if_object_stable(spawn)
    }

    /// Run a path-based external check, then drop its result if the file no
    /// longer matches the identity captured at load — the tool would have
    /// inspected a different object than the one this scan read, so its verdict
    /// is inconclusive, not clean (§10/§11.7/§11.8). Embedded content and files
    /// whose identity couldn't be captured pass through unchanged.
    fn spawn_if_object_stable<T>(&self, spawn: impl FnOnce() -> Option<T>) -> Option<T> {
        let out = spawn()?;
        match self.identity {
            Some(at_load) if ObjectIdentity::of_path(&self.path) != Some(at_load) => None,
            _ => Some(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(tag: &str, body: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "nav-ctx-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::File::create(&p).unwrap().write_all(body).unwrap();
        p
    }

    /// A signing result is trusted only while the scanned object is unchanged:
    /// if the path is swapped/rewritten between the content read and the tool
    /// call, the tool inspected a different object, so its verdict is dropped
    /// rather than trusted (§11.7, NAV-003).
    #[test]
    fn signing_result_is_dropped_when_the_object_changes_underneath() {
        let path = temp_file("toctou", b"original bytes");
        let ctx = ScanContext::load(&path);
        assert!(ctx.identity.is_some());

        // Stable object: the external result passes through.
        assert_eq!(
            ctx.codesign_dv(|| Some((false, "stable".to_string()))),
            Some((false, "stable".to_string()))
        );

        // Swap the object at the path (different size => different identity),
        // then a fresh context's signing check must not trust its own spawn.
        std::fs::write(&path, b"a wholly different, longer set of bytes").unwrap();
        let ctx2 = ScanContext::load(&path);
        std::fs::write(&path, b"changed again after load").unwrap();
        assert_eq!(
            ctx2.codesign_dv(|| Some((true, "attacker".to_string()))),
            None
        );
        assert_eq!(ctx2.spctl_assessment(|| Some("attacker".to_string())), None);
        // The un-memoized guard (used by `codesign --verify`) drops its result
        // the same way.
        assert_eq!(
            ctx2.run_object_bound(|| Some("attacker-verify".to_string())),
            None
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The captured identity describes the object that was actually opened and
    /// read — its `size` matches both the reported length and the bytes read,
    /// because all three come from the one `fstat` on the handle the read went
    /// through, not a separate pre-open `stat` (§11.7).
    #[test]
    fn identity_is_derived_from_the_opened_and_read_object() {
        let path = temp_file("fd-identity", b"twelve bytes");
        let ctx = ScanContext::load(&path);
        let id = ctx.identity.expect("a readable file has an identity");
        assert_eq!(id.size, ctx.file_len.expect("length from the same fstat"));
        assert_eq!(id.size, ctx.content.as_ref().unwrap().len() as u64);
        assert!(!ctx.truncated);
        let _ = std::fs::remove_file(&path);
    }

    /// Embedded content has no file identity, so the stability check never
    /// suppresses a result for it.
    #[test]
    fn embedded_content_is_unaffected_by_the_stability_check() {
        let ctx =
            ScanContext::from_embedded_bytes("x.pkg!Scripts/preinstall", vec![1, 2, 3], false);
        assert!(ctx.identity.is_none());
        assert_eq!(
            ctx.codesign_dv(|| Some((true, "ok".to_string()))),
            Some((true, "ok".to_string()))
        );
        assert_eq!(
            ctx.run_object_bound(|| Some("ok".to_string())),
            Some("ok".to_string())
        );
    }
}
