//! Disk-image targets for `navctl scan` / `navctl rules test` (§6.2): mount
//! read-only in a private scratch directory, scan every volume as one
//! target, detach. Every failure falls back to the unmounted scan, which
//! nav-core reports `Partial` (§10, §11.8).

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use nav_core::process::{path_arg, run_capped, Captured};
use nav_core::{plist, scan_target_with_budget, PlistValue, ScanBudget, TargetScan};

const HDIUTIL: &str = "/usr/bin/hdiutil";

/// Largest image file navctl mounts.
pub const MAX_IMAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Largest logical size (`imageinfo`'s `Total Bytes`) navctl mounts.
pub const MAX_VOLUME_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Wall-clock limit on `hdiutil attach`.
pub const MOUNT_TIMEOUT: Duration = Duration::from_secs(60);
/// Wall-clock limit on every other `hdiutil` call.
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the main thread waits for the worker after a cancel signal.
const CANCEL_GRACE: Duration = Duration::from_secs(2);
const SCRATCH_DIR_NAME: &str = "navctl-scratch";
/// Under a run directory: where volumes are mounted.
const MOUNT_DIR: &str = "mnt";
/// Under a run directory: the lock its run holds while it lives.
const LOCK_FILE: &str = "lock";
/// Under a run directory: the lock file before it is locked and renamed.
const LOCK_PENDING: &str = "lock.new";
/// Under a run directory: the clone's file stem.
const CLONE_STEM: &str = "image";

/// Signal number received (SIGINT/SIGTERM/SIGHUP), or 0.
static CANCEL: AtomicI32 = AtomicI32::new(0);

/// A disk image mounted and scanned.
pub struct ImageReport {
    /// Root is the image path; member paths are labelled `image!path`.
    pub scan: TargetScan,
    pub volumes: usize,
    /// Why coverage is incomplete beyond `scan`'s own budget/unreadable.
    pub gaps: Vec<String>,
}

pub enum ImageScan {
    /// Not a regular file holding a disk image: scan it the usual way.
    NotImage,
    /// A disk image that was not mounted, and why.
    Unmounted(String),
    Scanned(ImageReport),
    /// Cancelled by `signal`. `released`: cleanup verified that nothing of
    /// this run is still attached.
    Interrupted {
        signal: i32,
        released: bool,
    },
}

/// Mounts and scans `path` if it is a disk image. Must be called from the
/// main thread: it installs signal handlers and waits on a worker.
pub fn scan_image(path: &Path, budget: &ScanBudget) -> ImageScan {
    let Some(file) = open_image(path) else {
        return ImageScan::NotImage;
    };
    if !cfg!(target_os = "macos") {
        return ImageScan::Unmounted("disk images are only mounted on macOS".into());
    }
    if !Path::new(HDIUTIL).is_file() {
        return ImageScan::Unmounted(format!("{HDIUTIL} not found"));
    }

    let (outcome, released) = mount_on_worker(file, path, budget);
    set_signal_handlers(libc::SIG_DFL);
    match (CANCEL.load(Ordering::SeqCst), outcome) {
        (0, Ok(report)) => ImageScan::Scanned(report),
        (0, Err(reason)) => ImageScan::Unmounted(reason),
        (signal, _) => ImageScan::Interrupted { signal, released },
    }
}

/// `path` opened, if it is a regular file holding a disk image.
fn open_image(path: &Path) -> Option<File> {
    // Stat first so a FIFO or device is never opened.
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    matches!(nav_core::disk_image_format_of_file(&file), Ok(Some(_))).then_some(file)
}

/// Runs [`mount_and_scan`] on a worker thread while this thread watches for
/// a cancel signal, then cleans up either way. Also returns
/// [`cleanup_run`]'s verdict (true when nothing was ever attached).
fn mount_on_worker(
    file: File,
    path: &Path,
    budget: &ScanBudget,
) -> (Result<ImageReport, String>, bool) {
    set_signal_handlers(on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
    let unusable = |e: io::Error| (Err(format!("scratch directory unusable: {e}")), true);
    let root = match scratch_root() {
        Ok(root) => root,
        Err(e) => return unusable(e),
    };
    sweep_stale(&root);
    if cancelled() {
        return (Err("interrupted".into()), true);
    }
    let (run, _lock) = match create_run_dir(&root) {
        Ok(run) => run,
        Err(e) => return unusable(e),
    };

    let (tx, rx) = mpsc::channel();
    let (label, worker_run, budget) = (path.to_path_buf(), run.clone(), *budget);
    let attaching = Arc::new(AtomicBool::new(false));
    let worker_attaching = Arc::clone(&attaching);
    let worker = thread::spawn(move || {
        let r = mount_and_scan(&file, &label, &worker_run, &budget, &worker_attaching);
        let _ = tx.send(r);
    });

    let outcome = loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(r) => {
                let _ = worker.join();
                break r;
            }
            Err(mpsc::RecvTimeoutError::Timeout) if CANCEL.load(Ordering::SeqCst) != 0 => {
                // Give the worker time to kill its hdiutil child and stop; a
                // scan still walking the volume is cut off by the detach.
                if rx.recv_timeout(CANCEL_GRACE).is_ok() {
                    let _ = worker.join();
                }
                break Err("interrupted".into());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err("internal error while scanning the image".into())
            }
        }
    };
    let released = cleanup_run(&run, attaching.load(Ordering::SeqCst));
    (outcome, released)
}

/// Clones `file` into `run`, checks the clone, attaches it under
/// `run/mnt` and scans the volumes, labelling results and reasons with
/// `label`. Every step after the clone reads only the clone. Mounts are
/// left for [`cleanup_run`]. `attaching` stays set if an attach was killed
/// before it returned.
fn mount_and_scan(
    file: &File,
    label: &Path,
    run: &Path,
    budget: &ScanBudget,
    attaching: &AtomicBool,
) -> Result<ImageReport, String> {
    let image = clone_into(file, label, run)?;
    scan_clone(&image, label, run, budget, attaching).map_err(|why| {
        why.replace(
            image.to_string_lossy().as_ref(),
            label.to_string_lossy().as_ref(),
        )
    })
}

fn scan_clone(
    image: &Path,
    label: &Path,
    run: &Path,
    budget: &ScanBudget,
    attaching: &AtomicBool,
) -> Result<ImageReport, String> {
    let clone = File::open(image).map_err(|e| format!("cannot open the clone: {e}"))?;
    // `uchg`/`uappnd` come across with the clone and would stop its removal.
    clear_flags(&clone).map_err(|e| format!("cannot clear the clone's file flags: {e}"))?;
    if !matches!(nav_core::disk_image_format_of_file(&clone), Ok(Some(_))) {
        return Err("image changed before it was cloned and is no longer a disk image".into());
    }
    let len = clone
        .metadata()
        .map_err(|e| format!("cannot stat image: {e}"))?
        .len();
    drop(clone);
    if len > MAX_IMAGE_BYTES {
        return Err(limit_reason(format!(
            "image file is larger than {} GiB",
            MAX_IMAGE_BYTES >> 30
        )));
    }
    let image_arg = path_arg(image);
    // Before anything else reads the image: `imageinfo` on an encrypted
    // image without `-stdinpass` raises a GUI passphrase prompt.
    let enc = query_plist(&[os("isencrypted"), os("-plist"), image_arg.as_os_str()])?;
    match enc.get("encrypted").and_then(PlistValue::as_bool) {
        Some(false) => {}
        Some(true) => return Err("image is encrypted".into()),
        None => return Err("could not tell whether the image is encrypted".into()),
    }
    let info = query_plist(&[
        os("imageinfo"),
        os("-plist"),
        os("-stdinpass"),
        image_arg.as_os_str(),
    ])?;
    let logical = info
        .get("Size Information")
        .and_then(|s| s.get("Total Bytes"))
        .and_then(PlistValue::as_i64)
        .ok_or("logical size of the image unknown")?;
    if logical < 0 || logical as u64 > MAX_VOLUME_BYTES {
        return Err(limit_reason(format!(
            "logical size is larger than {} GiB",
            MAX_VOLUME_BYTES >> 30
        )));
    }

    let mounts = run.join(MOUNT_DIR);
    attaching.store(true, Ordering::SeqCst);
    let out = run_hdiutil(
        &[
            os("attach"),
            os("-readonly"),
            os("-nobrowse"),
            os("-noautoopen"),
            os("-noautofsck"),
            os("-owners"),
            os("off"),
            os("-verify"),
            os("-stdinpass"),
            os("-plist"),
            os("-mountrandom"),
            mounts.as_os_str(),
            image_arg.as_os_str(),
        ],
        MOUNT_TIMEOUT,
    );
    // Only a started child that was killed may still land; run_capped
    // errs only when nothing was spawned.
    if !matches!(&out, Ok(o) if o.timed_out) {
        attaching.store(false, Ordering::SeqCst);
    }
    let out = out.map_err(|e| format!("hdiutil attach: {e}"))?;
    if out.timed_out {
        return Err(limit_reason(format!(
            "mount did not finish within {} s",
            MOUNT_TIMEOUT.as_secs()
        )));
    }
    if !out.success() {
        return Err(format!("mount failed: {}", error_line(&out)));
    }
    let attached = captured_plist(&out).ok_or("mount failed: unreadable hdiutil output")?;
    let entities = parse_attach(&attached, &mounts);
    if entities.volumes.is_empty() {
        return Err("no volume on the image mounted".into());
    }
    if let Some((n, _)) = entities.volumes.iter().find(|(_, v)| !locked_down(v)) {
        return Err(format!(
            "volume {n} was not mounted read-only, nosuid and nodev, so it was not scanned"
        ));
    }

    // Volumes sit one level below `mounts`, so their contents keep the
    // caller's depth limit.
    let walk_budget = ScanBudget {
        max_depth: budget.max_depth.saturating_add(1),
        ..*budget
    };
    let mut scan = scan_target_with_budget(&mounts, true, &walk_budget)
        .map_err(|e| format!("cannot read the mounted volume: {e}"))?;
    relabel(&mut scan, label, &entities.volumes, entities.candidates > 1);
    let mut gaps = entities.gaps;
    gaps.extend(vanished(&entities.volumes, is_mount_point));
    Ok(ImageReport {
        scan,
        volumes: entities.volumes.len(),
        gaps,
    })
}

/// A gap for each of `volumes` no longer mounted where the attach put it.
fn vanished(volumes: &[(usize, PathBuf)], mounted: impl Fn(&Path) -> bool) -> Vec<String> {
    volumes
        .iter()
        .filter(|(_, v)| !mounted(v))
        .map(|(n, _)| format!("volume {n} was unmounted during the scan"))
        .collect()
}

/// Whether a volume is mounted at `path` exactly (`statfs`'s mount point).
#[cfg(target_os = "macos")]
fn is_mount_point(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: a zeroed statfs is a valid out-buffer and `c` is NUL-terminated.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut fs) } != 0 {
        return false;
    }
    let name = fs.f_mntonname.map(|c| c as u8);
    std::ffi::CStr::from_bytes_until_nul(&name)
        .is_ok_and(|on| on.to_bytes() == path.as_os_str().as_bytes())
}

#[cfg(not(target_os = "macos"))]
fn is_mount_point(_: &Path) -> bool {
    true
}

/// Whether the volume at `path` is mounted read-only, nosuid and nodev, as
/// the system defaults for disk images; asserted since root scans mount too.
#[cfg(target_os = "macos")]
fn locked_down(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: a zeroed statfs is a valid out-buffer and `c` is NUL-terminated.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut fs) } != 0 {
        return false;
    }
    let want = (libc::MNT_RDONLY | libc::MNT_NOSUID | libc::MNT_NODEV) as u32;
    fs.f_flags & want == want
}

#[cfg(not(target_os = "macos"))]
fn locked_down(_: &Path) -> bool {
    true
}

/// Clones `file` into `run` as `image[.ext]`, keeping `label`'s extension
/// for hdiutil. Never copies: an image on another volume is not mounted.
fn clone_into(file: &File, label: &Path, run: &Path) -> Result<PathBuf, String> {
    let name = match label.extension().and_then(OsStr::to_str) {
        Some(ext) if ext.len() <= 32 && !ext.contains('/') => format!("{CLONE_STEM}.{ext}"),
        _ => CLONE_STEM.to_string(),
    };
    match clone_file(file, run, &name) {
        Ok(()) => Ok(run.join(name)),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => Err(
            "image is on a different volume from the scratch directory and is not copied".into(),
        ),
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => {
            Err("the image's filesystem does not support cloning; image not copied".into())
        }
        Err(e) => Err(format!("could not clone the image: {e}")),
    }
}

#[cfg(target_os = "macos")]
fn clone_file(file: &File, dir: &Path, name: &str) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // <sys/clonefile.h>; not in the libc crate.
    const CLONE_NOFOLLOW: u32 = 0x0001;
    const CLONE_NOOWNERCOPY: u32 = 0x0002;
    let dir = File::open(dir)?;
    let name = std::ffi::CString::new(name).map_err(io::Error::other)?;
    // SAFETY: both descriptors are open for the call and `name` is a valid
    // NUL-terminated string.
    let r = unsafe {
        libc::fclonefileat(
            file.as_raw_fd(),
            dir.as_raw_fd(),
            name.as_ptr(),
            CLONE_NOFOLLOW | CLONE_NOOWNERCOPY,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Clears the user immutable and append-only flags on `file`, which we
/// own, keeping every other flag (`UF_COMPRESSED` must stay).
#[cfg(target_os = "macos")]
fn clear_flags(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::macos::fs::MetadataExt;
    let blocking = libc::UF_IMMUTABLE | libc::UF_APPEND;
    let flags = file.metadata()?.st_flags();
    if flags & blocking == 0 {
        return Ok(());
    }
    // SAFETY: fchflags on a descriptor we own.
    if unsafe { libc::fchflags(file.as_raw_fd(), flags & !blocking) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
fn clear_flags(_: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn clone_file(_: &File, _: &Path, _: &str) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

fn limit_reason(what: String) -> String {
    format!("extraction limit exceeded: {what}")
}

fn os(s: &str) -> &OsStr {
    OsStr::new(s)
}

/// Volumes and gaps from an `attach -plist` result.
#[derive(Debug, Default, PartialEq)]
struct Attached {
    /// Mount points under the run directory with their volume numbers, in
    /// number order.
    volumes: Vec<(usize, PathBuf)>,
    /// Entities that are or should have been volumes, mounted or not.
    candidates: usize,
    gaps: Vec<String>,
}

/// Sort key for a `dev-entry`: `(disk, slice)` for `/dev/diskN` (slice 0)
/// and `/dev/diskNsM`, compared numerically. `None` for anything else.
fn dev_key(dev: &str) -> Option<(u64, u64)> {
    let rest = dev.strip_prefix("/dev/disk")?;
    let n = rest.bytes().take_while(u8::is_ascii_digit).count();
    let (disk, tail) = rest.split_at(n);
    let slice = match tail.strip_prefix('s') {
        None if tail.is_empty() => 0,
        Some(m) if !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()) => m.parse().ok()?,
        _ => return None,
    };
    Some((disk.parse().ok()?, slice))
}

/// `entities` by `dev-entry` (disk, then slice, numerically), so volume
/// numbers do not depend on the order `hdiutil` lists them (§6.2, §11.1).
/// An entity with a missing or unparseable `dev-entry` goes after the
/// rest, in listing order.
fn in_slice_order(entities: &[PlistValue]) -> Vec<&PlistValue> {
    let mut v: Vec<_> = entities.iter().collect();
    v.sort_by_key(|e| {
        let key = e
            .get("dev-entry")
            .and_then(PlistValue::as_str)
            .and_then(dev_key);
        (key.is_none(), key)
    });
    v
}

fn parse_attach(plist: &PlistValue, run: &Path) -> Attached {
    let mut out = Attached::default();
    let entities = plist
        .get("system-entities")
        .and_then(PlistValue::as_array)
        .unwrap_or_default();
    for e in in_slice_order(entities) {
        let mountable = e.get("potentially-mountable").and_then(PlistValue::as_bool);
        // Every candidate takes a number, mounted or not, so a failed
        // mount does not renumber the others.
        match e.get("mount-point").and_then(PlistValue::as_str) {
            Some(mp) => {
                out.candidates += 1;
                if Path::new(mp).starts_with(run) {
                    out.volumes.push((out.candidates, PathBuf::from(mp)));
                } else {
                    out.gaps.push(format!(
                        "volume {} was mounted outside the scratch directory and not scanned",
                        out.candidates
                    ));
                }
            }
            None if mountable == Some(true) => {
                out.candidates += 1;
                out.gaps.push(format!(
                    "volume {} on the image did not mount",
                    out.candidates
                ))
            }
            None => {}
        }
    }
    out
}

/// Rewrites every path in `scan` from the mount to `image!path` (`image!N/path`
/// with the volume's number when `numbered`), and sets the root.
fn relabel(scan: &mut TargetScan, image: &Path, volumes: &[(usize, PathBuf)], numbered: bool) {
    let image_str = image.display().to_string();
    let label = |p: &Path| -> PathBuf {
        for (n, v) in volumes {
            if let Ok(rel) = p.strip_prefix(v) {
                let rel = rel.display();
                return if numbered {
                    PathBuf::from(format!("{image_str}!{n}/{rel}"))
                } else {
                    PathBuf::from(format!("{image_str}!{rel}"))
                };
            }
        }
        PathBuf::from(format!("{image_str}!"))
    };
    // `<mount>/x` -> `image!x`, and a bare `<mount>`; longest first, so one
    // mount name that prefixes another can't rewrite the other's paths.
    let mut prefixes: Vec<(String, String)> = Vec::new();
    for (_, v) in volumes {
        let to = label(v).display().to_string();
        prefixes.push((format!("{}/", v.display()), to.clone()));
        prefixes.push((v.display().to_string(), to.trim_end_matches('/').into()));
    }
    prefixes.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
    for r in &mut scan.results {
        r.path = label(&r.path);
        for s in &mut r.signals {
            for (from, to) in &prefixes {
                if s.description.contains(from.as_str()) {
                    s.description = s.description.replace(from.as_str(), to);
                }
            }
        }
    }
    for p in scan.skipped.iter_mut().chain(scan.unreadable.iter_mut()) {
        *p = label(p);
    }
    scan.primary = None;
    scan.root = image.to_path_buf();
}

/// `<user temp dir>/navctl-scratch`, created 0700; must be a real directory
/// owned by us and closed to others. Returned canonical, as hdiutil
/// reports mount points.
fn scratch_root() -> io::Result<PathBuf> {
    let root = user_temp_dir().join(SCRATCH_DIR_NAME);
    match std::fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(&root)?;
    // SAFETY: getuid takes no arguments and never fails.
    let uid = unsafe { libc::getuid() };
    if !meta.file_type().is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(io::Error::other(format!(
            "{} is not a private directory owned by this user",
            root.display()
        )));
    }
    std::fs::canonicalize(&root)
}

/// `temp_dir()`, except as root: then the per-uid Darwin temp dir, ignoring
/// `TMPDIR`, which under `sudo -E` names a dir the invoking user controls
/// (#241). Falls back to `temp_dir()` off macOS or if `confstr` fails.
fn user_temp_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    // SAFETY: getuid takes no arguments and never fails.
    if unsafe { libc::getuid() } == 0 {
        use std::os::unix::ffi::OsStrExt;
        let mut buf = [0u8; libc::PATH_MAX as usize];
        // SAFETY: confstr writes at most buf.len() bytes, NUL-terminated.
        let n = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        // n counts the NUL; n > buf.len() means truncated.
        if n > 1 && n <= buf.len() {
            return PathBuf::from(OsStr::from_bytes(&buf[..n - 1]));
        }
    }
    std::env::temp_dir()
}

/// A fresh 0700 `<pid>-<random>` directory under `root`, with its 0700
/// mount directory, and the lock that marks it live. The run owns the
/// directory while it holds the returned lock file.
fn create_run_dir(root: &Path) -> io::Result<(PathBuf, File)> {
    let mut rand = [0u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut rand)?;
    let name = format!("{}-{:016x}", std::process::id(), u64::from_ne_bytes(rand));
    let dir = root.join(name);
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    match lock_run_dir(&dir) {
        Ok(lock) => Ok((dir, lock)),
        Err(e) => {
            let _ = remove_run_dir(&dir);
            Err(e)
        }
    }
}

/// Creates `dir`'s lock file, locked, and its mount directory. The lock is
/// taken under a temporary name and renamed into place, so a sweep never
/// finds `lock` unlocked.
fn lock_run_dir(dir: &Path) -> io::Result<File> {
    let pending = dir.join(LOCK_PENDING);
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&pending)?;
    if try_lock(&lock) != Lock::Free {
        return Err(io::Error::other("cannot lock the run directory"));
    }
    std::fs::rename(&pending, dir.join(LOCK_FILE))?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.join(MOUNT_DIR))?;
    Ok(lock)
}

/// A run directory's lock file, as a sweep finds it.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Lock {
    /// Taken by us now: its run has exited.
    Free,
    /// Held by a live run.
    Held,
    /// No lock file: a run still creating it, or one from navctl 0.7.
    Missing,
    /// Could not be checked.
    Unknown,
}

/// `flock(LOCK_EX | LOCK_NB)` on `file`.
fn try_lock(file: &File) -> Lock {
    use std::os::fd::AsRawFd;
    // SAFETY: flock on a descriptor we own.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Lock::Free;
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::EWOULDBLOCK) => Lock::Held,
        _ => Lock::Unknown,
    }
}

/// The state of `dir`'s lock file; when `Free`, also the file holding it.
fn probe_lock(dir: &Path) -> (Lock, Option<File>) {
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join(LOCK_FILE));
    match opened {
        Ok(f) => match try_lock(&f) {
            Lock::Free => (Lock::Free, Some(f)),
            other => (other, None),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => (Lock::Missing, None),
        Err(_) => (Lock::Unknown, None),
    }
}

/// Whether a run directory is dead, given its lock and whether the pid in
/// its name is alive (consulted only when there is no lock file; §6.2).
fn run_is_dead(lock: Lock, pid_alive: impl FnOnce() -> bool) -> bool {
    match lock {
        Lock::Free => true,
        Lock::Held | Lock::Unknown => false,
        Lock::Missing => !pid_alive(),
    }
}

/// The pid a run directory name under the scratch root starts with.
fn owner_pid(name: &OsStr) -> Option<i32> {
    let name = name.to_str()?;
    let (pid, rest) = name.split_once('-')?;
    if rest.is_empty() {
        return None;
    }
    pid.parse().ok().filter(|p| *p > 0)
}

fn pid_alive(pid: i32) -> bool {
    // SAFETY: kill with signal 0 only checks the pid; no signal is sent.
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Detaches the attachments of, and removes, run directories under `root`
/// whose navctl has exited (see [`run_is_dead`]). A directory is removed
/// only once nothing refers into it. Nothing outside `root` is touched.
fn sweep_stale(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        if cancelled() {
            return;
        }
        let dir = e.path();
        let Some(pid) = owner_pid(&e.file_name()) else {
            continue;
        };
        if !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        // Held until the directory is gone, so no other sweep takes it.
        let (lock, _held) = probe_lock(&dir);
        if !run_is_dead(lock, || pid_alive(pid)) {
            continue;
        }
        let swept = release(&dir, true).and_then(|()| remove_run_dir(&dir));
        match swept {
            Ok(()) => {}
            Err(_) if cancelled() => return,
            Err(why) => nav_core::safe_eprintln!(
                "navctl: warning: {why}; keeping stale scratch directory {}",
                dir.display()
            ),
        }
    }
}

fn cancelled() -> bool {
    CANCEL.load(Ordering::SeqCst) != 0
}

/// Detaches every attachment of ours (its image or a mount point under
/// `run`), then removes `run` if nothing of ours is left attached. With
/// `attach_cut` (an attach killed before it returned), first waits up to
/// [`SETTLE`] for it to land; if it does not, keeps `run`.
/// Returns whether nothing of ours is attached and `run` is gone; otherwise
/// warns and keeps `run` for a later run's sweep.
fn cleanup_run(run: &Path, attach_cut: bool) -> bool {
    let landed = attach_cut && settle(run);
    let result = release(run, false).and_then(|()| {
        if attach_cut && !landed {
            Err("an hdiutil attach was cut short and may still finish".into())
        } else {
            remove_run_dir(run)
        }
    });
    match result {
        Ok(()) => true,
        Err(why) => {
            nav_core::safe_eprintln!(
                "navctl: warning: {why}; keeping scratch directory {} for a later run to clean up",
                run.display()
            );
            false
        }
    }
}

/// How long cleanup watches for a killed attach to land.
const SETTLE: Duration = Duration::from_secs(5);

/// Waits up to [`SETTLE`] for an attachment of `run` to appear, and
/// detaches it. Returns whether one appeared.
fn settle(run: &Path) -> bool {
    let end = std::time::Instant::now() + SETTLE;
    while std::time::Instant::now() < end {
        let ours: Vec<Attachment> = attachments(false)
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.refers_into(run))
            .collect();
        if !ours.is_empty() {
            ours.iter().for_each(detach);
            return true;
        }
        thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Detaches every attachment referring into `dir` and checks that none is
/// left. A listing that fails is an error, never "nothing attached".
/// `stale`: a sweep, so listings stop on a cancel and each detach is noted
/// as left by an earlier run.
fn release(dir: &Path, stale: bool) -> Result<(), String> {
    let ours = || -> Result<Vec<Attachment>, String> {
        Ok(attachments(stale)?
            .into_iter()
            .filter(|a| a.refers_into(dir))
            .collect())
    };
    let found = ours()?;
    if found.is_empty() {
        return Ok(());
    }
    for a in &found {
        if stale {
            nav_core::safe_eprintln!(
                "navctl: detaching a stale scratch mount from an earlier run: {}",
                a.describe()
            );
        }
        detach(a);
    }
    let left: Vec<String> = ours()?.iter().map(Attachment::describe).collect();
    if left.is_empty() {
        Ok(())
    } else {
        Err(format!("could not detach {}", left.join(", ")))
    }
}

/// Removes `dir`: the empty mount-point directories, the mount directory
/// and the files directly in `dir`. Never recursive, so it cannot delete
/// into a volume that is still mounted. Errors if `dir` is still there.
fn remove_run_dir(dir: &Path) -> Result<(), String> {
    for d in [dir.join(MOUNT_DIR), dir.to_path_buf()] {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let _ = if e.file_type().is_ok_and(|t| t.is_dir()) {
                std::fs::remove_dir(e.path())
            } else {
                std::fs::remove_file(e.path())
            };
        }
    }
    match std::fs::remove_dir(dir) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            Err(format!("could not remove the scratch directory: {e}"))
        }
        _ => Ok(()),
    }
}

/// One image `hdiutil info` lists.
#[derive(Debug, Clone, PartialEq)]
struct Attachment {
    /// Whole-disk device; detaching it detaches every entity.
    device: Option<String>,
    image_path: Option<PathBuf>,
    mount_points: Vec<PathBuf>,
}

impl Attachment {
    /// The image path and every mount point.
    fn paths(&self) -> impl Iterator<Item = &Path> {
        self.image_path
            .iter()
            .chain(&self.mount_points)
            .map(PathBuf::as_path)
    }

    /// Whether the image or a mount point is under `dir` (canonical, as
    /// hdiutil reports paths).
    fn refers_into(&self, dir: &Path) -> bool {
        self.paths().any(|p| p.starts_with(dir))
    }

    /// What `hdiutil detach` is given: the device, else a mount point.
    fn target(&self) -> Option<&OsStr> {
        self.device
            .as_deref()
            .map(OsStr::new)
            .or_else(|| self.mount_points.first().map(|m| m.as_os_str()))
    }

    fn describe(&self) -> String {
        let device = self.device.as_deref().unwrap_or("unknown device");
        match self.mount_points.first() {
            Some(m) => format!("{} ({device})", m.display()),
            None => device.to_string(),
        }
    }
}

/// Everything `hdiutil info` lists. `cancellable`: stop once a cancel
/// signal arrives; otherwise it runs even after one.
fn attachments(cancellable: bool) -> Result<Vec<Attachment>, String> {
    let args = [os("info"), os("-plist")];
    let out = if cancellable {
        run_hdiutil(&args, QUERY_TIMEOUT)
    } else {
        run_hdiutil_uncancellable(&args, QUERY_TIMEOUT)
    };
    let info =
        plist_result(&args, out).map_err(|e| format!("could not list attached images: {e}"))?;
    parse_info(&info).ok_or_else(|| "could not list attached images: no image list".into())
}

/// The attachments in an `info -plist` result, or `None` if it has no
/// `images` list.
fn parse_info(info: &PlistValue) -> Option<Vec<Attachment>> {
    let images = info.get("images").and_then(PlistValue::as_array)?;
    let all = images
        .iter()
        .map(|img| {
            let entities = img
                .get("system-entities")
                .and_then(PlistValue::as_array)
                .unwrap_or_default();
            Attachment {
                device: whole_disk(entities),
                image_path: img
                    .get("image-path")
                    .and_then(PlistValue::as_str)
                    .map(PathBuf::from),
                mount_points: entities
                    .iter()
                    .filter_map(|e| e.get("mount-point").and_then(PlistValue::as_str))
                    .map(PathBuf::from)
                    .collect(),
            }
        })
        .collect();
    Some(all)
}

/// The image's whole disk (`/dev/diskN`): an entity that is one, else the
/// disk of the first slice. Detaching it detaches every entity.
fn whole_disk(entities: &[PlistValue]) -> Option<String> {
    let devs = || {
        entities
            .iter()
            .filter_map(|e| e.get("dev-entry").and_then(PlistValue::as_str))
    };
    devs()
        .find(|d| disk_of(d).as_deref() == Some(*d))
        .map(str::to_string)
        .or_else(|| devs().find_map(disk_of))
}

/// `/dev/diskN` for `/dev/diskN` or a slice `/dev/diskNsM`.
fn disk_of(dev: &str) -> Option<String> {
    let rest = dev.strip_prefix("/dev/disk")?;
    let n = rest.bytes().take_while(u8::is_ascii_digit).count();
    let (digits, tail) = rest.split_at(n);
    let slice = tail
        .strip_prefix('s')
        .is_some_and(|m| !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()));
    (n > 0 && (tail.is_empty() || slice)).then(|| format!("/dev/disk{digits}"))
}

/// `hdiutil detach`, retried with `-force`. Runs even after a cancel.
fn detach(a: &Attachment) {
    let Some(target) = a.target() else {
        return;
    };
    for force in [false, true] {
        let mut args = vec![os("detach"), target, os("-quiet")];
        if force {
            args.push(os("-force"));
        }
        if run_hdiutil_uncancellable(&args, QUERY_TIMEOUT).is_ok_and(|o| o.success()) {
            return;
        }
    }
}

/// `out`'s stdout as a plist, or `None` if it was cut or unparseable.
fn captured_plist(out: &Captured) -> Option<PlistValue> {
    if out.stdout_cut {
        return None;
    }
    plist::parse(&out.stdout)
}

/// The last stderr line that is not a deprecation warning.
fn error_line(out: &Captured) -> String {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty() && !l.contains("deprecated"))
        .map(|l| l.trim().trim_start_matches("hdiutil: ").to_string())
        .unwrap_or_else(|| "hdiutil reported no reason".into())
}

fn query_plist(args: &[&OsStr]) -> Result<PlistValue, String> {
    plist_result(args, run_hdiutil(args, QUERY_TIMEOUT))
}

/// The plist an `hdiutil args` run printed, or why there is none.
fn plist_result(args: &[&OsStr], out: io::Result<Captured>) -> Result<PlistValue, String> {
    let verb = args[0].to_string_lossy().into_owned();
    let out = out.map_err(|e| format!("hdiutil {verb}: {e}"))?;
    if out.timed_out {
        return Err(format!("hdiutil {verb} timed out"));
    }
    if !out.success() {
        return Err(format!("hdiutil {verb} failed: {}", error_line(&out)));
    }
    captured_plist(&out).ok_or_else(|| format!("hdiutil {verb}: unreadable output"))
}

fn run_hdiutil(args: &[&OsStr], timeout: Duration) -> io::Result<Captured> {
    retry_busy(|| {
        if CANCEL.load(Ordering::SeqCst) != 0 {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        }
        run_capped(HDIUTIL, args, timeout, Some(&CANCEL))
    })
}

fn run_hdiutil_uncancellable(args: &[&OsStr], timeout: Duration) -> io::Result<Captured> {
    retry_busy(|| run_capped(HDIUTIL, args, timeout, None))
}

/// Extra attempts for an hdiutil call failing with EAGAIN (about 14 s).
const BUSY_RETRIES: u32 = 10;

/// Retries `call` while hdiutil fails with "Resource temporarily
/// unavailable", as it does while the image is still attached or detaching.
fn retry_busy(mut call: impl FnMut() -> io::Result<Captured>) -> io::Result<Captured> {
    let mut attempt = 0;
    loop {
        let out = call()?;
        let busy = !out.success()
            && !out.timed_out
            && String::from_utf8_lossy(&out.stderr).contains("Resource temporarily unavailable");
        attempt += 1;
        if !busy || attempt > BUSY_RETRIES {
            return Ok(out);
        }
        thread::sleep(Duration::from_millis(250 * u64::from(attempt)));
    }
}

extern "C" fn on_signal(sig: libc::c_int) {
    CANCEL.store(sig, Ordering::SeqCst);
}

/// Sets SIGINT/SIGTERM/SIGHUP to `handler`: [`on_signal`], which only sets
/// [`CANCEL`] for the main thread to act on, or `SIG_DFL`.
fn set_signal_handlers(handler: libc::sighandler_t) {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: a zeroed sigaction is valid; `on_signal` only does an
        // atomic store, which is async-signal-safe.
        let rc = unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handler;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut())
        };
        if rc != 0 {
            nav_core::safe_eprintln!(
                "navctl: could not set a handler for signal {sig}: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(entries: Vec<(&str, PlistValue)>) -> PlistValue {
        PlistValue::Dict(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    fn entity(dev: &str, mount: Option<&str>, mountable: bool) -> PlistValue {
        let mut e = vec![
            ("dev-entry", PlistValue::String(dev.into())),
            ("potentially-mountable", PlistValue::Bool(mountable)),
        ];
        if let Some(m) = mount {
            e.push(("mount-point", PlistValue::String(m.into())));
        }
        dict(e)
    }

    #[test]
    fn attach_collects_every_volume_and_each_missing_one() {
        let run = Path::new("/s/1-ab");
        let plist = dict(vec![(
            "system-entities",
            PlistValue::Array(vec![
                entity("/dev/disk5", None, false),
                entity("/dev/disk5s1", Some("/s/1-ab/dmg.A"), true),
                entity("/dev/disk5s2", Some("/s/1-ab/dmg.B"), true),
                entity("/dev/disk5s3", None, true),
                entity("/dev/disk5s4", Some("/Volumes/X"), true),
            ]),
        )]);
        let got = parse_attach(&plist, run);
        assert_eq!(
            got.volumes,
            vec![
                (1, PathBuf::from("/s/1-ab/dmg.A")),
                (2, PathBuf::from("/s/1-ab/dmg.B"))
            ]
        );
        assert_eq!(got.gaps.len(), 2, "{:?}", got.gaps);
    }

    fn numbers(listing: &[PlistValue]) -> Attached {
        let plist = dict(vec![(
            "system-entities",
            PlistValue::Array(listing.to_vec()),
        )]);
        parse_attach(&plist, Path::new("/s/1-ab"))
    }

    #[test]
    fn volume_numbers_follow_slice_order() {
        let listing = [
            entity("/dev/disk5", None, false),
            entity("/dev/disk5s1", Some("/s/1-ab/a"), true),
            entity("/dev/disk5s2", Some("/s/1-ab/b"), true),
            entity("/dev/disk5s10", Some("/s/1-ab/j"), true),
        ];
        let want = numbers(&listing);
        assert_eq!(
            want.volumes,
            vec![
                (1, PathBuf::from("/s/1-ab/a")),
                (2, PathBuf::from("/s/1-ab/b")),
                (3, PathBuf::from("/s/1-ab/j")),
            ]
        );
        for order in [[3, 1, 0, 2], [2, 3, 1, 0], [1, 0, 3, 2], [0, 2, 1, 3]] {
            let shuffled: Vec<_> = order.iter().map(|&i| listing[i].clone()).collect();
            assert_eq!(numbers(&shuffled), want, "{order:?}");
        }
    }

    #[test]
    fn unmounted_slice_keeps_its_number() {
        let listing = [
            entity("/dev/disk5s3", Some("/s/1-ab/c"), true),
            entity("/dev/disk5s2", None, true),
            entity("/dev/disk5s1", Some("/s/1-ab/a"), true),
            entity("/dev/disk5", None, false),
        ];
        let got = numbers(&listing);
        assert_eq!(
            got.volumes,
            vec![
                (1, PathBuf::from("/s/1-ab/a")),
                (3, PathBuf::from("/s/1-ab/c"))
            ]
        );
        assert_eq!(got.candidates, 3);
        assert_eq!(got.gaps.len(), 1);
    }

    #[test]
    fn odd_dev_entries_sort_last_in_listing_order() {
        let no_dev = dict(vec![
            ("potentially-mountable", PlistValue::Bool(true)),
            ("mount-point", PlistValue::String("/s/1-ab/x".into())),
        ]);
        let listing = [
            no_dev,
            entity("/dev/disk5sX", Some("/s/1-ab/y"), true),
            entity("/dev/disk99999999999999999999s1", Some("/s/1-ab/z"), true),
            entity("/dev/disk5s2", Some("/s/1-ab/b"), true),
            entity("/dev/disk5s1", Some("/s/1-ab/a"), true),
        ];
        let names: Vec<_> = numbers(&listing)
            .volumes
            .iter()
            .map(|(n, p)| (*n, p.file_name().unwrap().to_str().unwrap().to_string()))
            .collect();
        let want: Vec<_> = [(1, "a"), (2, "b"), (3, "x"), (4, "y"), (5, "z")]
            .iter()
            .map(|(n, s)| (*n, s.to_string()))
            .collect();
        assert_eq!(names, want);
    }

    #[test]
    fn info_gives_each_image_its_whole_disk_and_mounts() {
        let image = |whole: &str, mount: &str| {
            dict(vec![
                ("image-path", PlistValue::String(format!("/i{whole}.dmg"))),
                (
                    "system-entities",
                    PlistValue::Array(vec![
                        entity(whole, None, false),
                        entity(&format!("{whole}s1"), Some(mount), true),
                    ]),
                ),
            ])
        };
        let info = dict(vec![(
            "images",
            PlistValue::Array(vec![
                image("/dev/disk5", "/s/1-ab/dmg.A"),
                image("/dev/disk7", "/Volumes/Mine"),
            ]),
        )]);
        let all = parse_info(&info).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].device.as_deref(), Some("/dev/disk5"));
        assert_eq!(all[0].image_path, Some(PathBuf::from("/i/dev/disk5.dmg")));
        assert!(all[0].refers_into(Path::new("/s/1-ab")));
        assert!(!all[1].refers_into(Path::new("/s/1-ab")));
        assert!(!all[0].refers_into(Path::new("/s/1-a")));
    }

    /// An attachment is ours by its image path alone (a volume unmounted
    /// under it), or by a mount point; never by being the same image
    /// attached from elsewhere.
    #[test]
    fn ownership_is_by_image_path_or_mount_point_under_the_run_dir() {
        let run = Path::new("/s/1-ab");
        let att = |image: &str, mounts: &[&str]| Attachment {
            device: Some("/dev/disk9".into()),
            image_path: Some(PathBuf::from(image)),
            mount_points: mounts.iter().map(PathBuf::from).collect(),
        };
        assert!(att("/s/1-ab/image.dmg", &[]).refers_into(run));
        assert!(att("/u/x.dmg", &["/s/1-ab/mnt/dmg.A"]).refers_into(run));
        assert!(!att("/u/x.dmg", &[]).refers_into(run));
        assert!(!att("/u/x.dmg", &["/Volumes/X"]).refers_into(run));
        assert!(!att("/s/1-abc/image.dmg", &[]).refers_into(run));
    }

    #[test]
    fn an_info_result_without_an_image_list_is_not_empty() {
        assert_eq!(parse_info(&dict(vec![])), None);
        let empty = dict(vec![("images", PlistValue::Array(vec![]))]);
        assert_eq!(parse_info(&empty), Some(vec![]));
    }

    #[test]
    fn each_volume_gone_from_its_mount_point_is_a_gap() {
        let vols = [(1, PathBuf::from("/s/a")), (2, PathBuf::from("/s/b"))];
        assert_eq!(vanished(&vols, |_| true), Vec::<String>::new());
        assert_eq!(
            vanished(&vols, |v| v.ends_with("a")),
            vec!["volume 2 was unmounted during the scan".to_string()]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn only_a_mount_point_itself_is_one() {
        assert!(is_mount_point(Path::new("/")));
        assert!(!is_mount_point(Path::new("/usr/bin")));
        assert!(!is_mount_point(Path::new("/no/such/dir")));
    }

    #[test]
    fn a_run_is_dead_when_its_lock_can_be_taken() {
        let unreachable = || -> bool { panic!("pid consulted") };
        assert!(run_is_dead(Lock::Free, unreachable));
        assert!(!run_is_dead(Lock::Held, unreachable));
        assert!(!run_is_dead(Lock::Unknown, unreachable));
        assert!(run_is_dead(Lock::Missing, || false));
        assert!(!run_is_dead(Lock::Missing, || true));
    }

    #[test]
    fn a_held_run_lock_is_seen_as_held_and_a_released_one_as_free() {
        let root = std::env::temp_dir().join(format!("navctl-lock-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let (dir, lock) = create_run_dir(&root).unwrap();
        assert_eq!(probe_lock(&dir).0, Lock::Held);
        drop(lock);
        let (state, held) = probe_lock(&dir);
        assert_eq!(state, Lock::Free);
        assert!(held.is_some());
        drop(held);
        remove_run_dir(&dir).unwrap();
        assert!(!dir.exists());
        assert_eq!(probe_lock(&dir).0, Lock::Missing);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn run_dir_names_give_their_pid() {
        assert_eq!(owner_pid(OsStr::new("123-00ff")), Some(123));
        for bad in ["123", "123-", "abc-1", "-5-x", "0-x"] {
            assert_eq!(owner_pid(OsStr::new(bad)), None, "{bad}");
        }
        assert_eq!(disk_of("/dev/disk12").as_deref(), Some("/dev/disk12"));
        assert_eq!(disk_of("/dev/disk12s1").as_deref(), Some("/dev/disk12"));
        for bad in [
            "/dev/disk",
            "/dev/disks1",
            "/dev/disk1x",
            "/dev/disk1s",
            "/dev/rdisk1",
        ] {
            assert_eq!(disk_of(bad), None, "{bad}");
        }
        let entities = [entity("/dev/disk5s1", Some("/s/1-ab/mnt/dmg.A"), true)];
        assert_eq!(whole_disk(&entities).as_deref(), Some("/dev/disk5"));
        // An APFS image: the synthesized container's slice before the disk.
        let entities = [
            entity("/dev/disk6s1", Some("/s/1-ab/mnt/dmg.A"), true),
            entity("/dev/disk5s1", None, false),
            entity("/dev/disk5", None, false),
        ];
        assert_eq!(whole_disk(&entities).as_deref(), Some("/dev/disk5"));
    }
}
