//! Disk-image targets for `navctl scan` / `navctl rules test` (§6.2): mount
//! read-only in a private scratch directory, scan every volume as one
//! target, detach. Every failure falls back to the unmounted scan, which
//! nav-core reports `Partial` (§10, §11.8).

use std::ffi::OsStr;
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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
/// Bytes kept from each of an `hdiutil` call's stdout and stderr.
const MAX_CAPTURE: usize = 1024 * 1024;
/// How long the main thread waits for the worker after a cancel signal.
const CANCEL_GRACE: Duration = Duration::from_secs(2);
/// How long output is collected once hdiutil exits; a helper holding the
/// pipe open must not hang navctl.
const PIPE_GRACE: Duration = Duration::from_secs(2);
const SCRATCH_DIR_NAME: &str = "navctl-scratch";

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
    /// Cancelled by this signal; mounts have been cleaned up.
    Interrupted(i32),
}

/// Mounts and scans `path` if it is a disk image. Must be called from the
/// main thread: it installs signal handlers and waits on a worker.
pub fn scan_image(path: &Path, budget: &ScanBudget) -> ImageScan {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {}
        _ => return ImageScan::NotImage,
    }
    if !matches!(nav_core::disk_image_format_of_path(path), Ok(Some(_))) {
        return ImageScan::NotImage;
    }
    if !cfg!(target_os = "macos") {
        return ImageScan::Unmounted("disk images are only mounted on macOS".into());
    }
    if !Path::new(HDIUTIL).is_file() {
        return ImageScan::Unmounted(format!("{HDIUTIL} not found"));
    }

    let outcome = mount_on_worker(path, budget);
    set_signal_handlers(libc::SIG_DFL);
    match (CANCEL.load(Ordering::SeqCst), outcome) {
        (0, Ok(report)) => ImageScan::Scanned(report),
        (0, Err(reason)) => ImageScan::Unmounted(reason),
        (signal, _) => ImageScan::Interrupted(signal),
    }
}

/// Runs [`mount_and_scan`] on a worker thread while this thread watches for
/// a cancel signal, then detaches and removes the run directory either way.
fn mount_on_worker(path: &Path, budget: &ScanBudget) -> Result<ImageReport, String> {
    set_signal_handlers(on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
    let root = scratch_root().map_err(|e| format!("scratch directory unusable: {e}"))?;
    sweep_stale(&root);
    let run = create_run_dir(&root).map_err(|e| format!("scratch directory unusable: {e}"))?;

    let (tx, rx) = mpsc::channel();
    let before = Arc::new(Mutex::new(None));
    let (image, worker_run, budget) = (path.to_path_buf(), run.clone(), *budget);
    let worker_before = Arc::clone(&before);
    let worker = thread::spawn(move || {
        let _ = tx.send(mount_and_scan(&image, &worker_run, &budget, &worker_before));
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
    let before = before.lock().map(|b| b.clone()).unwrap_or(None);
    cleanup_run(&run, before.as_ref().map(|b: &Before| (path, b)));
    outcome
}

/// Devices attached from the image before our attach.
type Before = Vec<String>;

/// Size checks, encryption check, attach, scan. Mounts are left for
/// [`cleanup_run`]; `before` is set just before the attach starts.
fn mount_and_scan(
    image: &Path,
    run: &Path,
    budget: &ScanBudget,
    before: &Mutex<Option<Before>>,
) -> Result<ImageReport, String> {
    let len = std::fs::metadata(image)
        .map_err(|e| format!("cannot stat image: {e}"))?
        .len();
    if len > MAX_IMAGE_BYTES {
        return Err(limit_reason(format!(
            "image file is larger than {} GiB",
            MAX_IMAGE_BYTES >> 30
        )));
    }
    // Before anything else reads the image: `imageinfo` on an encrypted
    // image without `-stdinpass` raises a GUI passphrase prompt.
    let enc = query_plist(&[os("isencrypted"), os("-plist"), image.as_os_str()])?;
    match enc.get("encrypted").and_then(PlistValue::as_bool) {
        Some(false) => {}
        Some(true) => return Err("image is encrypted".into()),
        None => return Err("could not tell whether the image is encrypted".into()),
    }
    let info = query_plist(&[
        os("imageinfo"),
        os("-plist"),
        os("-stdinpass"),
        image.as_os_str(),
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

    // Without a real snapshot, cleanup could take an existing attachment for ours.
    let info = query_plist(&[os("info"), os("-plist")])?;
    let attached_before = devices_of_image(&parse_info(&info), image);
    if let Ok(mut b) = before.lock() {
        *b = Some(attached_before);
    }
    let out = run_hdiutil(
        &[
            os("attach"),
            os("-readonly"),
            os("-nobrowse"),
            os("-noautoopen"),
            os("-noautofsck"),
            os("-verify"),
            os("-stdinpass"),
            os("-plist"),
            os("-mountrandom"),
            run.as_os_str(),
            image.as_os_str(),
        ],
        MOUNT_TIMEOUT,
    )
    .map_err(|e| format!("hdiutil attach: {e}"))?;
    if out.timed_out {
        return Err(limit_reason(format!(
            "mount did not finish within {} s",
            MOUNT_TIMEOUT.as_secs()
        )));
    }
    if !out.success() {
        return Err(format!("mount failed: {}", out.error_line()));
    }
    let attached = out
        .plist()
        .ok_or("mount failed: unreadable hdiutil output")?;
    let entities = parse_attach(&attached, run);
    if entities.volumes.is_empty() {
        return Err("no volume on the image mounted".into());
    }

    // Volumes sit one level below `run`, so their contents keep the
    // caller's depth limit.
    let walk_budget = ScanBudget {
        max_depth: budget.max_depth.saturating_add(1),
        ..*budget
    };
    let mut scan = scan_target_with_budget(run, true, &walk_budget)
        .map_err(|e| format!("cannot read the mounted volume: {e}"))?;
    relabel(&mut scan, image, &entities.volumes);
    Ok(ImageReport {
        scan,
        volumes: entities.volumes.len(),
        gaps: entities.gaps,
    })
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
    /// Mount points under the run directory, in entity order.
    volumes: Vec<PathBuf>,
    gaps: Vec<String>,
}

fn parse_attach(plist: &PlistValue, run: &Path) -> Attached {
    let mut out = Attached::default();
    let entities = plist
        .get("system-entities")
        .and_then(PlistValue::as_array)
        .unwrap_or_default();
    for e in entities {
        let mountable = e.get("potentially-mountable").and_then(PlistValue::as_bool);
        match e.get("mount-point").and_then(PlistValue::as_str) {
            Some(mp) if Path::new(mp).starts_with(run) => out.volumes.push(PathBuf::from(mp)),
            Some(_) => out
                .gaps
                .push("a volume mounted outside the scratch directory was not scanned".into()),
            None if mountable == Some(true) => {
                out.gaps.push("a volume on the image did not mount".into())
            }
            None => {}
        }
    }
    out
}

/// Rewrites every path in `scan` from the mount to `image!path` (with a
/// 1-based volume number when there are several), and sets the root.
fn relabel(scan: &mut TargetScan, image: &Path, volumes: &[PathBuf]) {
    let image_str = image.display().to_string();
    let label = |p: &Path| -> PathBuf {
        for (i, v) in volumes.iter().enumerate() {
            if let Ok(rel) = p.strip_prefix(v) {
                let rel = rel.display();
                return if volumes.len() == 1 {
                    PathBuf::from(format!("{image_str}!{rel}"))
                } else {
                    PathBuf::from(format!("{image_str}!{}/{rel}", i + 1))
                };
            }
        }
        PathBuf::from(format!("{image_str}!"))
    };
    // `<mount>/x` -> `image!x`, and a bare `<mount>`; longest first, so one
    // mount name that prefixes another can't rewrite the other's paths.
    let mut prefixes: Vec<(String, String)> = Vec::new();
    for v in volumes {
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

/// `<temp_dir>/navctl-scratch`, created 0700; must be a real directory
/// owned by us and closed to others. Returned canonical, as hdiutil
/// reports mount points.
fn scratch_root() -> io::Result<PathBuf> {
    let root = std::env::temp_dir().join(SCRATCH_DIR_NAME);
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

/// A fresh 0700 `<pid>-<random>` directory under `root`.
fn create_run_dir(root: &Path) -> io::Result<PathBuf> {
    let mut rand = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut rand)?;
    let name = format!("{}-{:016x}", std::process::id(), u64::from_ne_bytes(rand));
    let dir = root.join(name);
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
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

/// Detaches mounts and removes run directories left under `root` by a
/// navctl that is no longer running. Nothing outside `root` is touched.
fn sweep_stale(root: &Path) {
    let me = std::process::id() as i32;
    let dead = |dir: &Path| -> bool {
        dir.strip_prefix(root)
            .ok()
            .and_then(|rel| rel.components().next())
            .and_then(|c| owner_pid(c.as_os_str()))
            .is_some_and(|pid| pid != me && !pid_alive(pid))
    };
    for a in attachments() {
        let stale = a
            .mount_points
            .iter()
            .find(|m| m.starts_with(root) && dead(m));
        if let Some(m) = stale {
            eprintln!(
                "navctl: detaching a stale scratch mount from an earlier run: {}",
                m.display()
            );
            detach(&a);
        }
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) && dead(&path) {
            remove_run_dir(&path);
        }
    }
}

/// Detaches everything mounted under `run` and, given `(image, before)`,
/// every attachment of `image` not in `before` with no mount point (a
/// killed or failed attach); then removes `run`, warning about anything
/// that would not go.
fn cleanup_run(run: &Path, ours: Option<(&Path, &Before)>) {
    let leftovers = |all: Vec<Attachment>| -> Vec<Attachment> {
        all.into_iter()
            .filter(|a| {
                a.mounted_under(run)
                    || ours.is_some_and(|(image, before)| {
                        a.is_image(image)
                            && a.mount_points.is_empty()
                            && a.device.as_ref().is_some_and(|d| !before.contains(d))
                    })
            })
            .collect()
    };
    for a in leftovers(attachments()) {
        detach(&a);
    }
    for a in leftovers(attachments()) {
        eprintln!("navctl: warning: could not detach {}", a.describe());
    }
    remove_run_dir(run);
}

/// Removes `dir` and its empty mount-point directories. Never recursive, so
/// it cannot delete into a volume that is still mounted.
fn remove_run_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let _ = std::fs::remove_dir(e.path());
        }
    }
    let _ = std::fs::remove_dir(dir);
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
    fn mounted_under(&self, dir: &Path) -> bool {
        self.mount_points.iter().any(|m| m.starts_with(dir))
    }

    /// Same file as `image`, compared canonically as hdiutil reports it.
    fn is_image(&self, image: &Path) -> bool {
        let canon = std::fs::canonicalize(image).ok();
        self.image_path.is_some() && self.image_path == canon
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

/// Everything `hdiutil info` lists (empty if it fails).
fn attachments() -> Vec<Attachment> {
    match query_plist(&[os("info"), os("-plist")]) {
        Ok(info) => parse_info(&info),
        Err(_) => Vec::new(),
    }
}

fn devices_of_image(all: &[Attachment], image: &Path) -> Before {
    all.iter()
        .filter(|a| a.is_image(image))
        .filter_map(|a| a.device.clone())
        .collect()
}

fn parse_info(info: &PlistValue) -> Vec<Attachment> {
    let images = info
        .get("images")
        .and_then(PlistValue::as_array)
        .unwrap_or_default();
    images
        .iter()
        .map(|img| {
            let entities = img
                .get("system-entities")
                .and_then(PlistValue::as_array)
                .unwrap_or_default();
            Attachment {
                device: whole_disk(entities).map(str::to_string),
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
        .collect()
}

/// The first entity's device, when it is a whole disk (`/dev/diskN`):
/// detaching it detaches every entity of the image.
fn whole_disk(entities: &[PlistValue]) -> Option<&str> {
    entities
        .first()
        .and_then(|e| e.get("dev-entry"))
        .and_then(PlistValue::as_str)
        .filter(|d| is_whole_disk(d))
}

fn is_whole_disk(dev: &str) -> bool {
    dev.strip_prefix("/dev/disk")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
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

/// Captured result of one `hdiutil` call.
struct Captured {
    status: Option<ExitStatus>,
    stdout: Vec<u8>,
    stdout_cut: bool,
    stderr: Vec<u8>,
    timed_out: bool,
}

impl Captured {
    fn success(&self) -> bool {
        !self.timed_out && self.status.is_some_and(|s| s.success())
    }

    fn plist(&self) -> Option<PlistValue> {
        if self.stdout_cut {
            return None;
        }
        plist::parse(&self.stdout)
    }

    /// The last stderr line that is not a deprecation warning.
    fn error_line(&self) -> String {
        String::from_utf8_lossy(&self.stderr)
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty() && !l.contains("deprecated"))
            .map(|l| l.trim().trim_start_matches("hdiutil: ").to_string())
            .unwrap_or_else(|| "hdiutil reported no reason".into())
    }
}

fn query_plist(args: &[&OsStr]) -> Result<PlistValue, String> {
    let verb = args[0].to_string_lossy().into_owned();
    let out = run_hdiutil(args, QUERY_TIMEOUT).map_err(|e| format!("hdiutil {verb}: {e}"))?;
    if out.timed_out {
        return Err(format!("hdiutil {verb} timed out"));
    }
    if !out.success() {
        return Err(format!("hdiutil {verb} failed: {}", out.error_line()));
    }
    out.plist()
        .ok_or_else(|| format!("hdiutil {verb}: unreadable output"))
}

fn run_hdiutil(args: &[&OsStr], timeout: Duration) -> io::Result<Captured> {
    retry_busy(|| {
        if CANCEL.load(Ordering::SeqCst) != 0 {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        }
        run_capped(HDIUTIL, args, timeout, true)
    })
}

fn run_hdiutil_uncancellable(args: &[&OsStr], timeout: Duration) -> io::Result<Captured> {
    retry_busy(|| run_capped(HDIUTIL, args, timeout, false))
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

/// Runs `program` with empty stdin, keeping up to [`MAX_CAPTURE`] of each
/// output stream (drained concurrently so the child never blocks), killed
/// at `timeout` or, when `cancellable`, on a cancel signal.
fn run_capped(
    program: &str,
    args: &[&OsStr],
    timeout: Duration,
    cancellable: bool,
) -> io::Result<Captured> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = wait_until(&mut child, deadline, cancellable)?;
    // Not received in time counts as cut, so the output is not trusted.
    let (stdout, stdout_cut) = stdout
        .recv_timeout(PIPE_GRACE)
        .unwrap_or((Vec::new(), true));
    let (stderr, _) = stderr.recv_timeout(PIPE_GRACE).unwrap_or_default();
    Ok(Captured {
        status,
        stdout,
        stdout_cut,
        stderr,
        timed_out,
    })
}

fn wait_until(
    child: &mut Child,
    deadline: Instant,
    cancellable: bool,
) -> io::Result<(Option<ExitStatus>, bool)> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((Some(status), false));
        }
        let cancelled = cancellable && CANCEL.load(Ordering::SeqCst) != 0;
        if cancelled || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok((None, true));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Reads `pipe` to EOF on a thread, keeping the first [`MAX_CAPTURE`] bytes;
/// the flag is true if more was discarded.
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut cut = false;
        let Some(mut pipe) = pipe else {
            let _ = tx.send((kept, cut));
            return;
        };
        let mut buf = [0u8; 8192];
        loop {
            match pipe.read(&mut buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = MAX_CAPTURE - kept.len();
                    kept.extend_from_slice(&buf[..n.min(room)]);
                    cut |= n > room;
                }
            }
        }
        let _ = tx.send((kept, cut));
    });
    rx
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
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handler;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
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
                PathBuf::from("/s/1-ab/dmg.A"),
                PathBuf::from("/s/1-ab/dmg.B")
            ]
        );
        assert_eq!(got.gaps.len(), 2, "{:?}", got.gaps);
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
        let all = parse_info(&info);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].device.as_deref(), Some("/dev/disk5"));
        assert_eq!(all[0].image_path, Some(PathBuf::from("/i/dev/disk5.dmg")));
        assert!(all[0].mounted_under(Path::new("/s/1-ab")));
        assert!(!all[1].mounted_under(Path::new("/s/1-ab")));
        assert!(!all[0].mounted_under(Path::new("/s/1-a")));
    }

    #[test]
    fn run_dir_names_give_their_pid() {
        assert_eq!(owner_pid(OsStr::new("123-00ff")), Some(123));
        for bad in ["123", "123-", "abc-1", "-5-x", "0-x"] {
            assert_eq!(owner_pid(OsStr::new(bad)), None, "{bad}");
        }
        assert!(is_whole_disk("/dev/disk12"));
        assert!(!is_whole_disk("/dev/disk12s1"));
        assert!(!is_whole_disk("/dev/disk"));
    }

    #[test]
    fn capture_is_capped_and_drained() {
        let out = run_capped(
            "/bin/sh",
            &[os("-c"), os("head -c 3000000 /dev/zero; echo err >&2")],
            Duration::from_secs(30),
            false,
        )
        .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.len(), MAX_CAPTURE);
        assert!(out.stdout_cut);
        assert_eq!(out.stderr, b"err\n");
    }

    #[test]
    fn a_slow_child_is_killed_at_the_timeout() {
        let start = Instant::now();
        let out = run_capped("/bin/sleep", &[os("30")], Duration::from_millis(200), false).unwrap();
        assert!(out.timed_out);
        assert!(!out.success());
        assert!(start.elapsed() < Duration::from_secs(10));
    }
}
