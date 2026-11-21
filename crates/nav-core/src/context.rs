//! The evidence a rule gets to look at. A `ScanContext` is built once per scan
//! from a bounded read, so every rule sees the same evidence and none re-reads
//! the filesystem on its own (which would make TOCTOU — §11.7 — unreasonable).
//! Reads past that prefix ([`ScanContext::read_at`], [`ScanContext::for_each_window`])
//! go through the context's own file handle, never a fresh open by path (§11.7).

use std::borrow::Cow;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// Open `path` read-only and return the handle only if it is a regular file.
/// The open is `O_NONBLOCK`, so a FIFO swapped in after the walker's check
/// can't block it; a FIFO, device or other non-regular file yields `None`, the
/// same as an unreadable one (§11.7, §11.8).
pub(crate) fn open_regular(path: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    // O_NOCTTY: a tty swapped in must not become our controlling terminal.
    opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    let f = opts.open(path).ok()?;
    f.metadata().ok()?.is_file().then_some(f)
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
    /// Memoized signer check (`codesign --verify --all-architectures
    /// -R=...`, §5.2): exit code and stderr. `None` as for the caches above.
    pub(crate) signer_check_cache: OnceLock<Option<(Option<i32>, String)>>,
    /// Memoized strict Apple-anchor check exit code (§5.2, #106).
    pub(crate) strict_anchor_cache: OnceLock<Option<i32>>,
    /// Memoized offset-based Mach-O scan (§5.2, #45) — several rules ask
    /// about the same file. `pub(crate)` for the same reason as the caches
    /// above; use [`ScanContext::macho`] to read it.
    pub(crate) macho_cache: OnceLock<crate::macho::MachOScan>,
    /// Memoized ZIP read (§6.2, #86): the member rule and the container rule
    /// both use it. `None` inside: not read.
    pub(crate) zip_cache: OnceLock<Option<crate::rules::ZipInspection>>,
    /// Memoized ZIP-format detection, shared by the same two rules.
    pub(crate) zip_format_cache: OnceLock<Option<bool>>,
    /// Ids of rules that evaluated but could not cover everything they should
    /// have this scan (§10/§11.8). Keyed per rule so one rule's gap can't
    /// clobber another's.
    pub(crate) incomplete_rules: std::sync::Mutex<Vec<&'static str>>,
    /// Bytes this scan read from disk; see [`Self::bytes_read`].
    pub(crate) bytes_read: AtomicU64,
    /// Bytes container readers decompressed; see [`Self::decoded_bytes`].
    pub(crate) decoded_bytes: AtomicU64,
    /// Bytes this scan may still read or decode (§11.12); see
    /// [`Self::allowance_left`].
    pub(crate) allowance: AtomicU64,
    /// Set when work was refused for want of allowance.
    pub(crate) allowance_hit: AtomicBool,
}

impl ScanContext {
    pub fn load(path: &Path) -> Self {
        Self::load_if(path, u64::MAX, |_| true).expect("admit always accepts")
    }

    /// Like [`Self::load`], but calls `admit` with the opened file's length
    /// before reading anything, and returns `None` without reading if it
    /// refuses. A file that can't be opened or stat'd is never refused. The
    /// scan may read and decode at most `allowance` bytes, prefix included.
    pub(crate) fn load_if(
        path: &Path,
        allowance: u64,
        admit: impl FnOnce(u64) -> bool,
    ) -> Option<Self> {
        let unreadable = || ScanContext {
            allowance: AtomicU64::new(allowance),
            ..Self::empty(path.to_path_buf(), ContentSource::File)
        };
        // Identity and length come from the *opened* handle, and the bytes are
        // read through it, so a pre-open `stat` can't be raced (§11.7).
        let Some(mut f) = open_regular(path) else {
            return Some(unreadable());
        };
        let Ok(md) = f.metadata() else {
            return Some(unreadable());
        };
        if !admit(md.len()) {
            return None;
        }
        let file_len = md.len();
        let cap = allowance.min(MAX_CONTENT_BYTES as u64);
        let mut buf = Vec::new();
        let read = (&mut f).take(cap).read_to_end(&mut buf);
        // On error `buf` still holds what was read before it; charge that.
        let loaded = buf.len() as u64;
        let ctx = ScanContext {
            bytes_read: AtomicU64::new(loaded),
            allowance: AtomicU64::new(allowance - loaded),
            // A file exactly `cap` long was read in full; one that stats 0 can't tell.
            allowance_hit: AtomicBool::new(
                cap < MAX_CONTENT_BYTES as u64 && loaded == cap && loaded != file_len,
            ),
            ..unreadable()
        };
        if read.is_err() {
            return Some(ctx);
        }
        Some(ScanContext {
            truncated: loaded < file_len,
            content: Some(buf),
            file_len: Some(file_len),
            identity: Some(ObjectIdentity::from_metadata(&md)),
            file: Some(f),
            ..ctx
        })
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
            content: Some(content),
            truncated,
            file_len: Some(len),
            ..Self::empty(label.into(), ContentSource::Embedded)
        }
    }

    /// No content, no file, empty caches: the base every constructor fills
    /// in, so the field list lives in one place.
    fn empty(path: PathBuf, source: ContentSource) -> Self {
        ScanContext {
            path,
            content: None,
            truncated: false,
            file_len: None,
            identity: None,
            source,
            file: None,
            codesign_dv_cache: OnceLock::new(),
            spctl_cache: OnceLock::new(),
            signer_check_cache: OnceLock::new(),
            strict_anchor_cache: OnceLock::new(),
            macho_cache: OnceLock::new(),
            zip_cache: OnceLock::new(),
            zip_format_cache: OnceLock::new(),
            incomplete_rules: std::sync::Mutex::new(Vec::new()),
            bytes_read: AtomicU64::new(0),
            decoded_bytes: AtomicU64::new(0),
            allowance: AtomicU64::new(u64::MAX),
            allowance_hit: AtomicBool::new(false),
        }
    }

    /// True when this content came from a real file on disk.
    pub fn is_file_backed(&self) -> bool {
        self.source == ContentSource::File
    }

    /// True when [`Self::read_at`]/[`Self::for_each_window`] can actually
    /// reach bytes past `content`: a real, opened file. A rule deciding whether
    /// it can stream/range-read past the prefix should check this, not
    /// [`Self::is_file_backed`] alone.
    pub fn supports_ranged_reads(&self) -> bool {
        self.file.is_some()
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
        self.read_range_cow(offset, len).map(Cow::into_owned)
    }

    /// Core of [`Self::read_at`] and [`ByteSource::read_range`]: borrows
    /// straight from `content` when the whole range is already held there,
    /// so a caller making many small ranged reads (`macho::scan_ranged`)
    /// doesn't copy on every one of them (§5.2).
    fn read_range_cow(&self, offset: u64, len: usize) -> Option<Cow<'_, [u8]>> {
        match self.locate(offset, len)? {
            Some(held) => Some(Cow::Borrowed(held)),
            None => self.read_at_file(offset, len).map(Cow::Owned),
        }
    }

    /// Validates `[offset, offset + len)` for a ranged read: `None` if `len >
    /// MAX_RANGE_READ`, it overflows or passes `file_len`; else the held
    /// bytes, or `Some(None)` when the range must be read from the file.
    fn locate(&self, offset: u64, len: usize) -> Option<Option<&[u8]>> {
        if len > MAX_RANGE_READ {
            return None;
        }
        let end = offset.checked_add(len as u64)?;
        if end > self.file_len? {
            return None;
        }
        let held = self.content.as_deref().and_then(|c| {
            let start = usize::try_from(offset).ok()?;
            c.get(start..start.checked_add(len)?)
        });
        Some(held)
    }

    fn read_at_file(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        if !self.supports_ranged_reads() || !self.spend(len as u64) {
            return None;
        }
        let mut buf = vec![0u8; len];
        self.read_spent_into(offset, &mut buf)?;
        Some(buf)
    }

    fn read_file_into(&self, offset: u64, buf: &mut [u8]) -> Option<()> {
        if !self.supports_ranged_reads() || !self.spend(buf.len() as u64) {
            return None;
        }
        self.read_spent_into(offset, buf)
    }

    /// The disk read behind [`Self::read_file_into`], its allowance already
    /// spent.
    fn read_spent_into(&self, offset: u64, buf: &mut [u8]) -> Option<()> {
        use std::os::unix::fs::FileExt;
        let file = self.file.as_ref()?;
        // Charged on attempt: a read that fails partway may still have read.
        self.bytes_read
            .fetch_add(buf.len() as u64, Ordering::Relaxed);
        file.read_exact_at(buf, offset).ok()
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

        // A window is `[pos - carry, pos + want)`: borrowed from `content`
        // while its chunk is held there, else assembled in `buf`, carry first.
        let mut buf: Vec<u8> = Vec::new();
        let mut prev_held: Option<&[u8]> = None;
        let mut prev_len = 0usize;
        let mut carry = 0usize;
        let mut pos = range.start;
        while pos < range.end {
            let want = STREAM_CHUNK.min((range.end - pos) as usize);
            let len = carry + want;
            let window: &[u8] = match self.locate(pos, want) {
                None => return false,
                Some(Some(_)) => {
                    // `content` is a prefix, so the carry before a held chunk is held too.
                    let start = (pos - carry as u64) as usize;
                    let held = &self.content.as_deref().unwrap_or_default()[start..start + len];
                    prev_held = Some(held);
                    held
                }
                Some(None) => {
                    if buf.is_empty() {
                        buf = vec![0u8; overlap + STREAM_CHUNK];
                    }
                    match prev_held.take() {
                        Some(prev) => buf[..carry].copy_from_slice(&prev[prev.len() - carry..]),
                        None => buf.copy_within(prev_len - carry..prev_len, 0),
                    }
                    if self.read_file_into(pos, &mut buf[carry..len]).is_none() {
                        return false;
                    }
                    &buf[..len]
                }
            };
            pos += want as u64;
            f(window, pos == range.end);
            prev_len = len;
            carry = overlap.min(len);
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

    /// Runs `spawn` at most once per scan and returns the cached signer check:
    /// `codesign`'s exit code (`None` if killed by a signal) and its stderr.
    /// `None` on the same terms as [`Self::codesign_dv`].
    pub fn signer_check(
        &self,
        spawn: impl FnOnce() -> Option<(Option<i32>, String)>,
    ) -> Option<(Option<i32>, String)> {
        self.signer_check_cache
            .get_or_init(|| self.spawn_if_object_stable(spawn))
            .clone()
    }

    /// Runs `spawn` at most once per scan and returns the cached strict
    /// Apple-anchor check exit code. `None` on the same terms as
    /// [`Self::codesign_dv`].
    pub fn strict_anchor_check(&self, spawn: impl FnOnce() -> Option<i32>) -> Option<i32> {
        *self
            .strict_anchor_cache
            .get_or_init(|| self.spawn_if_object_stable(spawn))
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
        if !self.tool_allowed() {
            return None;
        }
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

    /// Records that `rule_id` evaluated but could not cover everything it
    /// should have this scan.
    pub fn mark_incomplete(&self, rule_id: &'static str) {
        let mut marked = self
            .incomplete_rules
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !marked.contains(&rule_id) {
            marked.push(rule_id);
        }
    }

    /// Bytes this scan read from disk itself, for the target byte budget
    /// (§11.12): the prefix load and every read past it (counted when
    /// attempted, re-reads again). Reads served from `content` are free;
    /// external tools (`codesign`, `spctl`) are not counted.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    /// Bytes this scan's container readers decompressed (zip, xar entries
    /// and TOC, nested layers), for the target byte budget (§11.12). Stored
    /// members are not counted: their bytes were already read.
    pub fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes.load(Ordering::Relaxed)
    }

    /// Adds `n` to [`Self::decoded_bytes`] and takes it from the allowance,
    /// which saturates at zero (recorded as a hit) if `n` does not fit.
    pub(crate) fn add_decoded(&self, n: usize) {
        self.decoded_bytes.fetch_add(n as u64, Ordering::Relaxed);
        if !self.spend(n as u64) {
            self.allowance.store(0, Ordering::Relaxed);
        }
    }

    /// Whether a path-based tool (`codesign`, `spctl`) may run: false, and a
    /// hit recorded, when a real file's allowance left is below its length.
    /// The tool's own reads are not charged (#106).
    pub(crate) fn tool_allowed(&self) -> bool {
        let allowed = !self.is_file_backed() || self.allowance_left() >= self.file_len.unwrap_or(0);
        if !allowed {
            self.note_allowance_hit();
        }
        allowed
    }

    /// `cap` lowered to the allowance left: the most a container decode may
    /// spend, input re-reads included. Returns the cap and whether it was
    /// lowered.
    pub(crate) fn decode_cap(&self, cap: usize) -> (usize, bool) {
        let left = usize::try_from(self.allowance_left()).unwrap_or(usize::MAX);
        (cap.min(left), left < cap)
    }

    /// Bytes this scan may still read from disk or decode (§11.12):
    /// `u64::MAX` for an unbounded scan.
    pub fn allowance_left(&self) -> u64 {
        self.allowance.load(Ordering::Relaxed)
    }

    /// Whether a read, decode or tool run was refused, or a container read
    /// cut short, for want of allowance: the scan did not get the work it
    /// needed (§11.12).
    pub fn allowance_hit(&self) -> bool {
        self.allowance_hit.load(Ordering::Relaxed)
    }

    /// Records that a decode under a lowered [`Self::decode_cap`] stopped
    /// short.
    pub(crate) fn note_allowance_hit(&self) {
        self.allowance_hit.store(true, Ordering::Relaxed);
    }

    /// Takes `n` from the allowance, or refuses (and records it) without
    /// taking anything if fewer than `n` are left.
    fn spend(&self, n: u64) -> bool {
        // A CAS loop rather than `fetch_update`, deprecated on newer stable.
        let mut left = self.allowance.load(Ordering::Relaxed);
        loop {
            let Some(rest) = left.checked_sub(n) else {
                self.note_allowance_hit();
                return false;
            };
            match self.allowance.compare_exchange_weak(
                left,
                rest,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(now) => left = now,
            }
        }
    }

    /// Distinct rules marked incomplete this scan, in marking order.
    pub fn incomplete_rules(&self) -> Vec<&'static str> {
        self.incomplete_rules
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether `rule_id` was marked incomplete this scan.
    pub fn marked_incomplete(&self, rule_id: &'static str) -> bool {
        self.incomplete_rules
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&rule_id)
    }
}

/// Test base for struct literals: an unreadable real-file context with empty
/// caches. Literals set what they need and take the rest with `..Default::default()`.
#[cfg(test)]
impl Default for ScanContext {
    fn default() -> Self {
        Self::empty(PathBuf::new(), ContentSource::File)
    }
}

impl crate::source::ByteSource for ScanContext {
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

    fn read_range(&self, off: u64, len: usize) -> Option<Cow<'_, [u8]>> {
        self.read_range_cow(off, len)
    }

    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Option<()> {
        match self.locate(off, buf.len())? {
            Some(held) => {
                buf.copy_from_slice(held);
                Some(())
            }
            None => self.read_file_into(off, buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{sparse_temp_file, write_at, write_temp_file};

    /// A signing result is trusted only while the scanned object is unchanged:
    /// if the path is swapped/rewritten between the content read and the tool
    /// call, the tool inspected a different object, so its verdict is dropped
    /// rather than trusted (§11.7, NAV-003).
    #[test]
    fn signing_result_is_dropped_when_the_object_changes_underneath() {
        let path = write_temp_file("toctou", b"original bytes");
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

    /// Two rules ask for the strict anchor check; `codesign` runs once (#106).
    #[test]
    fn anchor_check_spawns_once() {
        let path = write_temp_file("anchor-once", b"bytes");
        let ctx = ScanContext::load(&path);
        let spawns = std::cell::Cell::new(0);
        let spawn = || {
            spawns.set(spawns.get() + 1);
            Some(0)
        };
        assert_eq!(ctx.strict_anchor_check(spawn), Some(0));
        assert_eq!(ctx.strict_anchor_check(spawn), Some(0));
        assert_eq!(spawns.get(), 1);
        let _ = std::fs::remove_file(&path);
    }

    /// The captured identity describes the object that was actually opened and
    /// read — its `size` matches both the reported length and the bytes read,
    /// because all three come from the one `fstat` on the handle the read went
    /// through, not a separate pre-open `stat` (§11.7).
    #[test]
    fn identity_is_derived_from_the_opened_and_read_object() {
        let path = write_temp_file("fd-identity", b"twelve bytes");
        let ctx = ScanContext::load(&path);
        let id = ctx.identity.expect("a readable file has an identity");
        assert_eq!(id.size, ctx.file_len.expect("length from the same fstat"));
        assert_eq!(id.size, ctx.content.as_ref().unwrap().len() as u64);
        assert!(!ctx.truncated);
        let _ = std::fs::remove_file(&path);
    }

    /// A poisoned failure list still records and reports failures.
    #[test]
    fn incomplete_marks_survive_a_poisoned_lock() {
        let ctx = ScanContext::from_embedded_bytes("x", vec![1], false);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = ctx.incomplete_rules.lock().unwrap();
            panic!("poison the lock");
        }));
        assert!(ctx.incomplete_rules.is_poisoned());
        assert!(!ctx.marked_incomplete("a"));
        ctx.mark_incomplete("a");
        assert!(ctx.marked_incomplete("a"));
    }

    /// A real, opened file supports ranged reads; embedded content (no file
    /// at all) never does (§5.2, #45).
    #[test]
    fn supports_ranged_reads_requires_an_actual_file_handle() {
        let path = write_temp_file("supports-ranged-reads", b"hello world");
        let ctx = ScanContext::load(&path);
        assert!(ctx.file.is_some());
        assert!(ctx.supports_ranged_reads());
        let _ = std::fs::remove_file(&path);

        let embedded = ScanContext::from_embedded_bytes("x.pkg!member", vec![1, 2, 3], false);
        assert!(!embedded.supports_ranged_reads());
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

    /// A `ByteSource::read_range` call fully inside `content` borrows from it
    /// rather than copying — the hot path for `macho::scan_ranged`'s many
    /// small header/signature reads (§5.2).
    #[test]
    fn read_range_inside_content_borrows_without_copying() {
        use crate::source::ByteSource;

        let path = write_temp_file("read-range-borrowed", b"hello world");
        let ctx = ScanContext::load(&path);
        let cow = ctx.read_range(0, 5).expect("in-range read");
        assert!(matches!(cow, std::borrow::Cow::Borrowed(_)));
        assert_eq!(&*cow, b"hello");
        let _ = std::fs::remove_file(&path);
    }

    /// A range past `content` has to be read for real, so it comes back owned.
    #[test]
    fn read_range_past_content_is_owned() {
        use crate::source::ByteSource;

        let total_len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("read-range-owned", total_len);
        let marker = b"MARKER-PAST-CONTENT";
        let marker_offset = MAX_CONTENT_BYTES as u64 + 100;
        write_at(&path, marker_offset, marker);

        let ctx = ScanContext::load(&path);
        let cow = ctx
            .read_range(marker_offset, marker.len())
            .expect("past-content read");
        assert!(matches!(cow, std::borrow::Cow::Owned(_)));
        assert_eq!(&*cow, marker);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_at_inside_content_returns_the_right_bytes() {
        let path = write_temp_file("read-at-inside", b"hello world");
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
        let path = write_temp_file("read-at-bounds", b"hello world");
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

    /// Windows crossing from the held prefix into file reads carry the right
    /// bytes, and only chunks not wholly held are read from disk.
    #[test]
    fn windows_match_file_bytes() {
        let len = MAX_CONTENT_BYTES + 3 * STREAM_CHUNK + 123;
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let path = write_temp_file("for-each-window-bytes", &data);
        let ctx = ScanContext::load(&path);
        let (start, overlap) = (5u64, 100usize);

        let mut pos = start;
        let mut carry = 0usize;
        let mut from_disk = 0u64;
        let ok = ctx.for_each_window(start..len as u64, overlap, |window, is_last| {
            let want = window.len() - carry;
            let from = pos as usize - carry;
            assert_eq!(window, &data[from..pos as usize + want]);
            if pos as usize + want > MAX_CONTENT_BYTES {
                from_disk += want as u64;
            }
            pos += want as u64;
            assert_eq!(is_last, pos == len as u64);
            carry = overlap.min(window.len());
        });
        assert!(ok);
        assert_eq!(pos, len as u64);
        assert_eq!(ctx.bytes_read(), MAX_CONTENT_BYTES as u64 + from_disk);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn for_each_window_rejects_a_range_past_eof() {
        let path = write_temp_file("for-each-window-eof", b"hello world");
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

    #[test]
    fn bytes_read_counts_disk_reads_but_not_reads_served_from_content() {
        let len = (MAX_CONTENT_BYTES + 4096) as u64;
        let path = sparse_temp_file("bytes-read", len);
        let ctx = ScanContext::load(&path);
        assert_eq!(ctx.bytes_read(), MAX_CONTENT_BYTES as u64);
        ctx.read_at(0, 100).unwrap();
        assert_eq!(ctx.bytes_read(), MAX_CONTENT_BYTES as u64);
        ctx.read_at(len - 100, 100).unwrap();
        ctx.read_at(len - 100, 100).unwrap();
        assert_eq!(ctx.bytes_read(), MAX_CONTENT_BYTES as u64 + 200);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_if_offers_the_opened_length_and_a_refusal_returns_none() {
        let path = write_temp_file("load-if", &[7u8; 1000]);
        let mut offered = None;
        let refused = ScanContext::load_if(&path, u64::MAX, |len| {
            offered = Some(len);
            false
        });
        assert!(refused.is_none());
        assert_eq!(offered, Some(1000));
        let _ = std::fs::remove_file(&path);
    }

    /// A FIFO (e.g. swapped in after the walker's check) loads as unreadable
    /// instead of blocking the scan (§11.7, §11.8).
    #[test]
    fn fifo_loads_unreadable() {
        let dir = std::env::temp_dir().join(format!("nav-fifo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("pipe");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        assert!(made.unwrap().success());
        let (tx, rx) = std::sync::mpsc::channel();
        let p = fifo.clone();
        std::thread::spawn(move || {
            let ctx = ScanContext::load(&p);
            let _ = tx.send((ctx.content.is_none(), ctx.file_len.is_none()));
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got, Ok((true, true)));
    }

    fn load_with(path: &Path, allowance: u64) -> ScanContext {
        ScanContext::load_if(path, allowance, |_| true).unwrap()
    }

    /// Past the prefix, a read the allowance can't cover is refused before
    /// it reads: nothing is charged and the hit is recorded (§11.12).
    #[test]
    fn a_read_past_the_allowance_is_refused_without_reading() {
        let len = (MAX_CONTENT_BYTES + 4096) as u64;
        let path = sparse_temp_file("allowance-read", len);
        let ctx = load_with(&path, MAX_CONTENT_BYTES as u64 + 150);
        assert!(!ctx.allowance_hit());
        assert!(ctx.read_at(len - 100, 100).is_some());
        assert_eq!(ctx.allowance_left(), 50);
        assert_eq!(ctx.read_at(len - 100, 100), None);
        assert_eq!(ctx.bytes_read(), MAX_CONTENT_BYTES as u64 + 100);
        assert_eq!(ctx.allowance_left(), 50);
        assert!(ctx.allowance_hit());
        // Reads served from `content` cost nothing and still succeed.
        assert!(ctx.read_at(0, 100).is_some());
        let _ = std::fs::remove_file(&path);
    }

    /// A stream stops at the chunk the allowance can't cover.
    #[test]
    fn a_stream_stops_where_the_allowance_runs_out() {
        let len = (MAX_CONTENT_BYTES + 3 * STREAM_CHUNK) as u64;
        let path = sparse_temp_file("allowance-stream", len);
        let ctx = load_with(&path, (MAX_CONTENT_BYTES + STREAM_CHUNK) as u64);
        let mut delivered = 0;
        let ok = ctx.for_each_window(MAX_CONTENT_BYTES as u64..len, 0, |w, _| {
            delivered += w.len();
        });
        assert!(!ok);
        assert_eq!(delivered, STREAM_CHUNK);
        assert_eq!(ctx.bytes_read(), (MAX_CONTENT_BYTES + STREAM_CHUNK) as u64);
        assert!(ctx.allowance_hit());
        let _ = std::fs::remove_file(&path);
    }

    /// An allowance below the prefix cuts the prefix there.
    #[test]
    fn the_prefix_load_is_cut_at_the_allowance() {
        let path = write_temp_file("allowance-prefix", &[7u8; 1000]);
        let ctx = load_with(&path, 100);
        assert_eq!(ctx.content.as_ref().map(Vec::len), Some(100));
        assert!(ctx.truncated);
        assert_eq!(ctx.bytes_read(), 100);
        assert_eq!(ctx.allowance_left(), 0);
        assert!(ctx.allowance_hit());
        assert_eq!(ctx.read_at(500, 10), None);
        let _ = std::fs::remove_file(&path);

        let path = write_temp_file("allowance-prefix-fits", &[7u8; 1000]);
        // Exactly the allowance long: read whole, so not a hit.
        let ctx = load_with(&path, 1000);
        assert!(!ctx.truncated);
        assert!(!ctx.allowance_hit());
        let ctx = load_with(&path, 1001);
        assert!(!ctx.truncated);
        assert!(!ctx.allowance_hit());
        let _ = std::fs::remove_file(&path);
    }

    /// The prefix is read to EOF whatever the stat'd length says: a procfs
    /// file is regular, reports 0, and has content.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_prefix_is_read_past_a_zero_stat_length() {
        let ctx = load_with(Path::new("/proc/self/status"), 1 << 20);
        assert_eq!(ctx.file_len, Some(0));
        let content = ctx.content.as_deref().unwrap();
        assert!(content.starts_with(b"Name:"));
        assert_eq!(ctx.bytes_read(), content.len() as u64);
        assert!(!ctx.allowance_hit());
    }

    /// Decoded bytes come out of the allowance, and a decode cap is lowered
    /// to what is left: none once it is spent.
    #[test]
    fn decoded_bytes_are_charged_and_capped_at_the_allowance() {
        let path = write_temp_file("allowance-decode", &[7u8; 100]);
        let ctx = load_with(&path, 1100);
        assert_eq!(ctx.decode_cap(4096), (1000, true));
        assert_eq!(ctx.decode_cap(500), (500, false));
        ctx.add_decoded(1000);
        assert_eq!(ctx.decoded_bytes(), 1000);
        assert_eq!(ctx.decode_cap(4096), (0, true));
        assert!(!ctx.allowance_hit());
        // More than is left saturates at zero and is recorded, never panics.
        ctx.add_decoded(1);
        assert_eq!(ctx.allowance_left(), 0);
        assert!(ctx.allowance_hit());
        let _ = std::fs::remove_file(&path);
    }

    /// An external tool reads the whole file, so it is not run on less
    /// allowance than the file's length (§11.12, #106).
    #[test]
    fn a_tool_is_not_run_without_allowance_for_the_file() {
        let path = write_temp_file("allowance-tool", &[7u8; 1000]);
        let ctx = load_with(&path, 1999);
        let mut ran = false;
        assert_eq!(
            ctx.run_object_bound(|| {
                ran = true;
                Some(())
            }),
            None
        );
        assert!(!ran);
        assert!(ctx.allowance_hit());

        let ctx = load_with(&path, 2000);
        assert_eq!(ctx.run_object_bound(|| Some(())), Some(()));
        assert!(!ctx.allowance_hit());
        let _ = std::fs::remove_file(&path);
    }
}
