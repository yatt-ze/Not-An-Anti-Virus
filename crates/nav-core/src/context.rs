//! The evidence a rule gets to look at. A `ScanContext` is built once per scan
//! from a bounded read, so every rule sees the same evidence and none re-reads
//! the filesystem on its own (which would make TOCTOU — §11.7 — unreasonable).
//! Reads past that prefix ([`ScanContext::read_at`], [`ScanContext::for_each_window`])
//! go through the context's own file handle, never a fresh open by path (§11.7).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Cap on how much of a file is read into memory for content rules. Static
/// analysis never needs the whole file, and an unbounded read of hostile input
/// is what §3/§11.9 warn against.
pub const MAX_CONTENT_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

/// Largest single range [`ScanContext::read_at`] will serve in one call.
pub const MAX_RANGE_READ: usize = 16 * 1024 * 1024; // 16 MiB

/// Size of each window [`ScanContext::for_each_window`] reads per iteration.
pub const STREAM_CHUNK: usize = 1024 * 1024; // 1 MiB

/// Most bytes [`ScanContext::for_each_window`] will stream in one call.
pub const MAX_STREAM_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

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
    /// The handle `content` was read through, for a real file — kept so
    /// [`ScanContext::read_at`] and [`ScanContext::for_each_window`] read the
    /// same object `identity` describes, never a fresh open by path (§11.7).
    /// `None` for embedded content or when the open/read failed.
    pub(crate) file: Option<std::fs::File>,
    /// Memoized `codesign -dv` spawn (§5.2) — `None` means the spawn failed
    /// or the platform can't run it. Several rules ask about the same file.
    /// `pub(crate)` so test helpers elsewhere can build a `ScanContext` by
    /// struct literal; use [`ScanContext::codesign_dv`] to read it.
    pub(crate) codesign_dv_cache: OnceLock<Option<(bool, String)>>,
    /// Memoized `spctl` assessment spawn (§5.2), same reasoning as above.
    pub(crate) spctl_cache: OnceLock<Option<String>>,
    /// Memoized offset-based Mach-O scan (§5.2, #45) — several rules ask
    /// about the same file. `pub(crate)` for the same reason as the caches
    /// above; use [`ScanContext::macho`] to read it.
    pub(crate) macho_cache: OnceLock<crate::macho::MachOScan>,
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
            Some((f, buf, identity, md.len()))
        });

        let (file, content, identity, file_len) = match opened {
            Some((f, buf, identity, len)) => (Some(f), Some(buf), Some(identity), Some(len)),
            None => (None, None, None, None),
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
            file,
            codesign_dv_cache: OnceLock::new(),
            spctl_cache: OnceLock::new(),
            macho_cache: OnceLock::new(),
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
            file: None,
            codesign_dv_cache: OnceLock::new(),
            spctl_cache: OnceLock::new(),
            macho_cache: OnceLock::new(),
        }
    }

    /// True when this content came from a real file on disk.
    pub fn is_file_backed(&self) -> bool {
        self.source == ContentSource::File
    }

    pub fn readable(&self) -> bool {
        self.content.is_some()
    }

    /// Reads exactly `len` bytes starting at `offset`. Served from `content`
    /// when the whole range lies inside it; otherwise read through the file
    /// handle captured at [`Self::load`] (§11.7) — never a fresh open by path.
    ///
    /// Returns `None` if `len > MAX_RANGE_READ`, if `offset + len` overflows
    /// or exceeds the file's length, or if there is no file to fall back to
    /// (embedded content, or a platform with no `read_at`-style syscall) once
    /// the range extends past `content`.
    pub fn read_at(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        if len > MAX_RANGE_READ {
            return None;
        }
        let file_len = self.file_len?;
        let end = offset.checked_add(len as u64)?;
        if end > file_len {
            return None;
        }

        if let Some(content) = &self.content {
            if end <= content.len() as u64 {
                let start = offset as usize;
                return Some(content[start..start + len].to_vec());
            }
        }

        self.read_at_file(offset, len)
    }

    #[cfg(unix)]
    fn read_at_file(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let file = self.file.as_ref()?;
        let mut buf = vec![0u8; len];
        file.read_exact_at(&mut buf, offset).ok()?;
        Some(buf)
    }

    #[cfg(not(unix))]
    fn read_at_file(&self, _offset: u64, _len: usize) -> Option<Vec<u8>> {
        None
    }

    /// Streams `range` to `f` as successive overlapping windows: each window
    /// is the previous window's last `overlap` bytes followed by up to
    /// `STREAM_CHUNK` new bytes, so any byte string of length `<= overlap + 1`
    /// lying in `range` appears whole in at least one window. At most one
    /// window is alive at a time. `overlap` must be `< STREAM_CHUNK`
    /// (debug-asserted; clamped in release). `f`'s bool argument is `true`
    /// only for the window that ends at `range.end` — the true end of the
    /// streamed range, as opposed to a window edge that a later window will
    /// still extend.
    ///
    /// Returns `true` only if the whole range was delivered. Returns `false`,
    /// having delivered whatever it already had, if the range is inverted,
    /// `range.end` exceeds the file's length, the range is longer than
    /// `MAX_STREAM_BYTES` (checked up front — nothing is delivered in that
    /// case), or a chunk read fails. An empty range returns `true` without
    /// calling `f`.
    pub fn for_each_window(
        &self,
        range: std::ops::Range<u64>,
        overlap: usize,
        mut f: impl FnMut(&[u8], bool),
    ) -> bool {
        debug_assert!(overlap < STREAM_CHUNK);
        let overlap = overlap.min(STREAM_CHUNK.saturating_sub(1));

        if range.start == range.end {
            return true;
        }
        if range.start > range.end {
            return false;
        }
        if range.end - range.start > MAX_STREAM_BYTES {
            return false;
        }
        let Some(file_len) = self.file_len else {
            return false;
        };
        if range.end > file_len {
            return false;
        }

        let mut carry: Vec<u8> = Vec::new();
        let mut pos = range.start;
        while pos < range.end {
            let want = STREAM_CHUNK.min((range.end - pos) as usize);
            let Some(chunk) = self.read_at(pos, want) else {
                return false;
            };
            let mut window = carry;
            window.extend_from_slice(&chunk);
            pos += want as u64;
            let is_last = pos == range.end;
            f(&window, is_last);
            let keep = overlap.min(window.len());
            carry = window[window.len() - keep..].to_vec();
        }
        true
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

    /// Runs [`crate::macho::scan_ranged`] against this context at most once
    /// per scan and returns the cached result — the offset-based Mach-O scan
    /// several rules ask about (§5.2, #45). An unreadable context (no
    /// `file_len`) scans as `is_macho: false` rather than panicking.
    pub fn macho(&self) -> &crate::macho::MachOScan {
        self.macho_cache
            .get_or_init(|| crate::macho::scan_ranged(self))
    }
}

impl crate::macho::ByteSource for ScanContext {
    fn source_len(&self) -> u64 {
        self.file_len.unwrap_or(0)
    }

    fn held_len(&self) -> u64 {
        self.content.as_ref().map_or(0, |c| c.len() as u64)
    }

    fn source_len_is_authoritative(&self) -> bool {
        // A real file's `file_len` is always the true stat'd size, even
        // though `content` is capped. Embedded content's `file_len` is just
        // how much was captured — the real member may be bigger — but only
        // when extraction actually stopped short (`truncated`).
        !(self.source == ContentSource::Embedded && self.truncated)
    }

    fn read_range(&self, off: u64, len: usize) -> Option<Vec<u8>> {
        self.read_at(off, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

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

    /// A zero-filled (sparse) temp file of exactly `total_len` bytes, for
    /// tests that need a file bigger than `MAX_CONTENT_BYTES` without writing
    /// that many bytes.
    fn sparse_temp_file(tag: &str, total_len: u64) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "nav-ctx-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let f = std::fs::File::create(&p).unwrap();
        f.set_len(total_len).unwrap();
        p
    }

    fn write_at(path: &Path, offset: u64, bytes: &[u8]) {
        let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.seek(SeekFrom::Start(offset)).unwrap();
        f.write_all(bytes).unwrap();
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

    #[test]
    fn read_at_inside_content_returns_the_right_bytes() {
        let path = temp_file("read-at-inside", b"hello world");
        let ctx = ScanContext::load(&path);
        assert_eq!(ctx.read_at(0, 5), Some(b"hello".to_vec()));
        assert_eq!(ctx.read_at(6, 5), Some(b"world".to_vec()));
        let _ = std::fs::remove_file(&path);
    }

    /// A range entirely past `content` (but within the file) is served from
    /// the file handle, not the bounded prefix (§11.7).
    #[test]
    fn read_at_past_the_content_cap_reads_through_the_file() {
        let total_len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("read-at-past-cap", total_len);
        let marker = b"MARKER-PAST-THE-PREFIX-CAP";
        let marker_offset = MAX_CONTENT_BYTES as u64 + 100;
        write_at(&path, marker_offset, marker);

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        assert_eq!(
            ctx.read_at(marker_offset, marker.len()),
            Some(marker.to_vec())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_at_straddling_the_content_boundary_returns_correct_bytes() {
        let total_len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("read-at-straddle", total_len);
        let straddle = b"BOUNDARY-STRADDLING-BYTES";
        let straddle_offset = MAX_CONTENT_BYTES as u64 - 10;
        write_at(&path, straddle_offset, straddle);

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        assert_eq!(
            ctx.read_at(straddle_offset, straddle.len()),
            Some(straddle.to_vec())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_at_rejects_out_of_range_requests() {
        let path = temp_file("read-at-bounds", b"hello world");
        let ctx = ScanContext::load(&path);

        // Past EOF.
        assert_eq!(ctx.read_at(100, 5), None);
        // Larger than a single range read is allowed to serve.
        assert_eq!(ctx.read_at(0, MAX_RANGE_READ + 1), None);
        // offset + len overflows u64.
        assert_eq!(ctx.read_at(u64::MAX, 5), None);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_at_past_embedded_bytes_is_none() {
        let ctx =
            ScanContext::from_embedded_bytes("x.pkg!Scripts/preinstall", vec![1, 2, 3], false);
        assert_eq!(ctx.read_at(0, 3), Some(vec![1, 2, 3]));
        assert_eq!(ctx.read_at(2, 5), None);
    }

    /// A byte string that straddles a `STREAM_CHUNK` boundary must still land
    /// whole inside one window when `overlap >= marker.len() - 1`, and the
    /// windows together must account for every byte in `range` exactly once.
    #[test]
    fn for_each_window_delivers_a_marker_straddling_a_chunk_boundary() {
        let total_len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("for-each-window", total_len);
        let marker = b"CHUNK-BOUNDARY-MARKER";
        let boundary = 3 * STREAM_CHUNK as u64;
        let marker_offset = boundary - 5;
        write_at(&path, marker_offset, marker);

        let ctx = ScanContext::load(&path);
        let overlap = marker.len() - 1;
        let range = 0..total_len;

        let mut call_count = 0u64;
        let mut total_new_bytes = 0u64;
        let mut found_marker = false;
        let ok = ctx.for_each_window(range.clone(), overlap, |window, is_last| {
            if window.windows(marker.len()).any(|w| w == marker) {
                found_marker = true;
            }
            let new_bytes = if call_count == 0 {
                window.len()
            } else {
                window.len() - overlap
            };
            total_new_bytes += new_bytes as u64;
            call_count += 1;
            assert_eq!(is_last, total_new_bytes == range.end - range.start);
        });

        assert!(ok);
        assert!(
            found_marker,
            "marker straddling a chunk boundary must appear whole in some window"
        );
        assert_eq!(total_new_bytes, range.end - range.start);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn for_each_window_rejects_a_range_past_eof() {
        let path = temp_file("for-each-window-eof", b"hello world");
        let ctx = ScanContext::load(&path);
        assert!(!ctx.for_each_window(0..1000, 0, |_, _| {}));
        let _ = std::fs::remove_file(&path);
    }

    /// The `MAX_STREAM_BYTES` length check runs before any read, so a range
    /// too long to stream never invokes `f` even once.
    #[test]
    fn for_each_window_rejects_a_range_longer_than_max_stream_bytes_without_reading() {
        let ctx = ScanContext::from_embedded_bytes("x", vec![1, 2, 3], false);
        let mut calls = 0u32;
        let ok = ctx.for_each_window(0..(MAX_STREAM_BYTES + 1), 0, |_, _| {
            calls += 1;
        });
        assert!(!ok);
        assert_eq!(calls, 0);
    }
}
