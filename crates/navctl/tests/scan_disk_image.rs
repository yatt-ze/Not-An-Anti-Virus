//! End-to-end coverage for `navctl scan` / `rules test` on disk images
//! (§6.2, #86): images are built with `hdiutil create`, and every test
//! checks that nothing stays mounted under its private scratch root. They
//! run one at a time: under concurrent load hdiutil fails with EAGAIN and
//! `create` can leave its own temporary attach behind.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use nav_core::PlistValue;

const DROPPER_SH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../nav-core/fixtures/suspicious/dropper.sh"
);

/// A private temp tree; navctl runs with `TMPDIR` inside it, so its scratch
/// root is per test. Drop detaches anything left mounted there, then
/// removes the tree.
struct Sandbox {
    root: PathBuf,
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        static N: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "navctl-dmg-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        Sandbox {
            root,
            _serial: serial,
        }
    }

    fn src(&self) -> PathBuf {
        self.root.join("src")
    }

    fn scratch(&self) -> PathBuf {
        self.root.join("tmp/navctl-scratch")
    }

    /// `hdiutil create -srcfolder src` in `format`.
    fn image(&self, name: &str, format: &str) -> PathBuf {
        let out = self.root.join(name);
        let src = self.src();
        let created = hdiutil(&[
            os("create"),
            os("-quiet"),
            os("-volname"),
            os("NavTest"),
            os("-format"),
            os(format),
            os("-srcfolder"),
            os(&src),
            os(&out),
        ]);
        assert!(created, "hdiutil create {format}");
        self.wait_released();
        out
    }

    /// Waits until nothing under the sandbox is attached: `hdiutil create`
    /// attaches internally and may detach after it returns, or not at all.
    fn wait_released(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.mounts().is_empty() {
            if Instant::now() >= deadline {
                self.detach_all();
                assert_eq!(self.mounts(), Vec::new(), "could not release");
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn detach_all(&self) {
        for (device, _) in self.mounts() {
            hdiutil(&[os("detach"), os(&device), os("-force"), os("-quiet")]);
        }
    }

    fn navctl(&self, args: &[&str], target: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_navctl"))
            .args(args)
            .arg(target)
            .env("TMPDIR", self.root.join("tmp"))
            .stdin(Stdio::null())
            .output()
            .expect("navctl spawns")
    }

    fn mounts(&self) -> Vec<(String, String)> {
        mounts_under(&self.root)
    }

    /// Nothing mounted under the sandbox, and no run directory left.
    fn assert_clean(&self) {
        assert_eq!(self.mounts(), Vec::new(), "mount left behind");
        if let Ok(entries) = std::fs::read_dir(self.scratch()) {
            let left: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            assert!(left.is_empty(), "scratch entries left: {left:?}");
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.detach_all();
        let _ = Command::new("/usr/bin/chflags")
            .args(["-R", "nouchg,nouappnd"])
            .arg(&self.root)
            .status();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Runs `/usr/bin/hdiutil args`, retrying while concurrent runs make it
/// fail with EAGAIN.
fn hdiutil(args: &[&std::ffi::OsStr]) -> bool {
    for attempt in 1..=10 {
        let out = Command::new("/usr/bin/hdiutil")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        if out.status.success() {
            return true;
        }
        if !String::from_utf8_lossy(&out.stderr).contains("temporarily unavailable") {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200 * attempt));
    }
    false
}

fn os<S: AsRef<std::ffi::OsStr> + ?Sized>(s: &S) -> &std::ffi::OsStr {
    s.as_ref()
}

/// (whole-disk device, mount point) of each image mounted under `dir`, or
/// whose image file is under it (mount point then empty).
fn mounts_under(dir: &Path) -> Vec<(String, String)> {
    let out = Command::new("/usr/bin/hdiutil")
        .args(["info", "-plist"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let info = nav_core::plist::parse(&out.stdout).expect("hdiutil info plist");
    let mut found = Vec::new();
    for img in info
        .get("images")
        .and_then(PlistValue::as_array)
        .unwrap_or_default()
    {
        let entities = img
            .get("system-entities")
            .and_then(PlistValue::as_array)
            .unwrap_or_default();
        let device = entities
            .first()
            .and_then(|e| e.get("dev-entry"))
            .and_then(PlistValue::as_str)
            .unwrap_or_default();
        let mounted = entities.iter().find_map(|e| {
            e.get("mount-point")
                .and_then(PlistValue::as_str)
                .filter(|mp| Path::new(mp).starts_with(dir))
        });
        let image = img.get("image-path").and_then(PlistValue::as_str);
        if let Some(mp) = mounted {
            found.push((device.to_string(), mp.to_string()));
        } else if image.is_some_and(|p| Path::new(p).starts_with(dir)) {
            found.push((device.to_string(), String::new()));
        }
    }
    found
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Neither stream mentions the scratch mount.
fn assert_no_scratch_path(o: &Output) {
    for text in [stdout(o), stderr(o)] {
        assert!(!text.contains("navctl-scratch"), "{text}");
    }
}

#[test]
fn a_clean_image_is_complete_in_both_formats() {
    let sb = Sandbox::new("clean");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    for format in ["UDZO", "UDRW"] {
        let image = sb.image(&format!("clean-{format}.dmg"), format);
        let out = sb.navctl(&["scan"], &image);
        assert_eq!(out.status.code(), Some(0), "{format}: {}", stderr(&out));
        let lines: Vec<_> = stdout(&out).lines().map(str::to_owned).collect();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with(image.to_str().unwrap()), "{lines:?}");
        assert!(lines[0].contains("completeness=Complete"), "{lines:?}");
        assert!(lines[0].ends_with("(disk image: 1 files)"), "{lines:?}");
        assert!(!stderr(&out).contains("not inspected"), "{}", stderr(&out));
        assert_no_scratch_path(&out);

        let verbose = sb.navctl(&["scan", "--verbose"], &image);
        let member = format!("{}!readme.txt", image.display());
        assert!(
            stdout(&verbose).starts_with(&member),
            "{}",
            stdout(&verbose)
        );

        let rules = sb.navctl(&["rules", "test"], &image);
        assert_eq!(rules.status.code(), Some(0), "{}", stdout(&rules));
        assert!(
            stdout(&rules).contains("Disk image: "),
            "{}",
            stdout(&rules)
        );
        assert!(!stdout(&rules).contains(UNINSPECTED), "{}", stdout(&rules));
        assert_no_scratch_path(&rules);

        let json = sb.navctl(&["rules", "test", "--json"], &image);
        let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(v["kind"], "disk-image");
        assert_eq!(v["coverage_complete"], true);
        assert_eq!(v["volumes"], 1);
        assert_eq!(v["results"][0]["path"], member.as_str());
        sb.assert_clean();
    }
}

const UNINSPECTED: &str = "uninspected-container";

#[test]
fn a_dropper_inside_an_image_is_found() {
    let sb = Sandbox::new("dropper");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    std::fs::copy(DROPPER_SH, sb.src().join("install.sh")).unwrap();
    let image = sb.image("dropper.dmg", "UDZO");

    let out = sb.navctl(&["scan"], &image);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let line = stdout(&out);
    assert!(line.contains("-> notify"), "{line}");
    assert!(line.contains("worst: dropper.dmg!install.sh)"), "{line}");
    assert_no_scratch_path(&out);

    let json = sb.navctl(&["scan", "--json"], &image);
    let objects: Vec<serde_json::Value> = stdout(&json)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    // Members first, then the target summary (#51).
    let (summary, members) = objects.split_last().unwrap();
    assert_eq!(summary["kind"], "disk-image");
    assert_eq!(summary["files"], 2);
    assert!(summary["volumes"].is_number() && summary["mount_gaps"].is_array());
    let paths: Vec<String> = members
        .iter()
        .map(|v| v["path"].as_str().unwrap().to_owned())
        .collect();
    let label = |n: &str| format!("{}!{n}", image.display());
    assert_eq!(paths, vec![label("install.sh"), label("readme.txt")]);

    let rules = sb.navctl(&["rules", "test"], &image);
    assert_eq!(rules.status.code(), Some(1));
    assert!(
        stdout(&rules).contains("Worst finding — dropper.dmg!install.sh"),
        "{}",
        stdout(&rules)
    );
    sb.assert_clean();
}

#[test]
fn no_mount_keeps_the_image_unread() {
    let sb = Sandbox::new("no-mount");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    let image = sb.image("plain.dmg", "UDZO");
    for cmd in [
        &["scan", "--no-mount"][..],
        &["rules", "test", "--no-mount"][..],
    ] {
        let out = sb.navctl(cmd, &image);
        assert_eq!(out.status.code(), Some(3), "{cmd:?}");
        let text = stdout(&out) + &stderr(&out);
        assert!(text.contains("not inspected"), "{cmd:?}: {text}");
        assert!(!text.contains("not mounted"), "{cmd:?}: {text}");
    }
    assert!(!sb.scratch().exists(), "--no-mount must not create scratch");
}

#[test]
fn a_corrupted_image_is_partial_with_a_reason() {
    let sb = Sandbox::new("corrupt");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    let image = sb.image("corrupt.dmg", "UDZO");
    let mut bytes = std::fs::read(&image).unwrap();
    for b in &mut bytes[2000..2200] {
        *b = 0xff;
    }
    std::fs::write(&image, bytes).unwrap();

    let out = sb.navctl(&["scan"], &image);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("disk image not mounted"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("not inspected"), "{}", stderr(&out));
    assert!(stdout(&out).contains("completeness=Partial"));

    assert_no_scratch_path(&out);

    let rules = sb.navctl(&["rules", "test"], &image);
    assert_eq!(rules.status.code(), Some(3));
    assert!(stdout(&rules).starts_with("Disk image not mounted: "));
    assert_no_scratch_path(&rules);
    sb.assert_clean();
}

/// An encrypted image stops at `hdiutil isencrypted`, never reaching
/// `imageinfo` or `attach`, so no passphrase prompt can appear; it scans
/// `Partial` through `uninspected-container`.
#[test]
fn an_encrypted_image_is_never_attached() {
    let sb = Sandbox::new("encrypted");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    let image = sb.root.join("enc.dmg");
    let mut child = Command::new("/usr/bin/hdiutil")
        .args(["create", "-quiet", "-encryption", "AES-128", "-stdinpass"])
        .args(["-format", "UDZO", "-srcfolder"])
        .arg(sb.src())
        .arg(&image)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"pw").unwrap();
    assert!(child.wait().unwrap().success());
    sb.wait_released();

    let start = Instant::now();
    let out = sb.navctl(&["scan"], &image);
    assert!(start.elapsed() < Duration::from_secs(20));
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("not mounted: image is encrypted"), "{err}");
    assert!(
        err.contains("disk image (encrypted) not inspected"),
        "{err}"
    );
    sb.assert_clean();
}

/// `Applications -> /Applications` (in every app DMG) and a link to a host
/// file are not followed, and do not make the image `Partial`.
#[test]
fn symlinks_do_not_leave_the_volume() {
    let sb = Sandbox::new("symlinks");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    std::os::unix::fs::symlink("/Applications", sb.src().join("Applications")).unwrap();
    std::os::unix::fs::symlink(DROPPER_SH, sb.src().join("host.sh")).unwrap();
    let image = sb.image("links.dmg", "UDZO");

    let out = sb.navctl(&["scan", "--json"], &image);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let lines: Vec<_> = stdout(&out).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("links.dmg!readme.txt"), "{lines:?}");
    assert!(lines[1].contains("\"kind\":\"disk-image\""), "{lines:?}");
    sb.assert_clean();
}

/// One `ScanBudget` covers the image: a file limit below its file count
/// makes it `Partial`.
#[test]
fn the_scan_budget_applies_to_the_image() {
    let sb = Sandbox::new("budget");
    std::fs::write(sb.src().join("a.txt"), "a\n").unwrap();
    std::fs::write(sb.src().join("b.txt"), "b\n").unwrap();
    let image = sb.image("budget.dmg", "UDZO");
    let out = sb.navctl(&["scan", "--max-files", "1"], &image);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("completeness=Partial"),
        "{}",
        stdout(&out)
    );
    assert!(stderr(&out).contains("max-files"), "{}", stderr(&out));
    assert_no_scratch_path(&out);
    sb.assert_clean();
}

#[test]
fn an_image_over_the_size_caps_is_not_mounted() {
    let sb = Sandbox::new("caps");
    // Past the 16 GiB file cap: sparse, with a UDIF trailer magic.
    let huge = sb.root.join("huge.dmg");
    let f = std::fs::File::create(&huge).unwrap();
    let len = (16u64 << 30) + 4096;
    f.set_len(len).unwrap();
    use std::os::unix::fs::FileExt;
    f.write_all_at(b"koly", len - 512).unwrap();
    drop(f);
    // Past the 64 GiB logical cap: a sparse image with no filesystem.
    let wide = sb.root.join("wide");
    assert!(hdiutil(&[
        os("create"),
        os("-quiet"),
        os("-size"),
        os("65g"),
        os("-type"),
        os("SPARSE"),
        os("-layout"),
        os("NONE"),
        os(&wide),
    ]));
    sb.wait_released();

    for image in [huge, sb.root.join("wide.sparseimage")] {
        let out = sb.navctl(&["scan"], &image);
        assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
        assert!(
            stderr(&out).contains("extraction limit exceeded"),
            "{}",
            stderr(&out)
        );
    }
    sb.assert_clean();
}

/// Opens a run directory's lock file, creating it.
fn lock_file(dir: &Path) -> std::fs::File {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("lock"))
        .unwrap()
}

/// The sweep detaches and removes run directories whose lock is free, and
/// keeps locked ones; lockless ones go by pid (§6.2, #174).
#[test]
fn stale_mounts_from_a_dead_run_are_swept() {
    let sb = Sandbox::new("stale");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    let image = sb.image("stale.dmg", "UDZO");
    std::fs::create_dir(sb.scratch()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(sb.scratch(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let mut gone = Command::new("/usr/bin/true").spawn().unwrap();
    let dead_pid = gone.id();
    gone.wait().unwrap();
    let live_pid = std::process::id();
    let run = |pid: u32, tag: &str| {
        let dir = sb.scratch().join(format!("{pid}-{tag}"));
        std::fs::create_dir(&dir).unwrap();
        dir
    };
    // Its pid is alive (ours), but nothing holds its lock.
    let mounted = run(live_pid, "0001");
    drop(lock_file(&mounted));
    let unmounted = run(live_pid, "0002");
    drop(lock_file(&unmounted));
    // Its pid is gone, but the lock is held.
    let locked = run(dead_pid, "0003");
    let held = lock_file(&locked);
    // SAFETY: flock on a descriptor we own.
    assert_eq!(
        unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&held), libc::LOCK_EX) },
        0
    );
    let legacy_dead = run(dead_pid, "0004");
    let legacy_live = run(live_pid, "0005");

    // One image can only be attached once at a time.
    for (dir, mount) in [(&mounted, true), (&unmounted, false), (&locked, false)] {
        let copy = dir.join("image.dmg");
        std::fs::copy(&image, &copy).unwrap();
        let mut args = vec![os("attach"), os("-readonly"), os("-nobrowse"), os("-quiet")];
        if mount {
            args.extend([os("-mountrandom"), os(dir)]);
        } else {
            args.push(os("-nomount"));
        }
        args.push(os(&copy));
        assert!(hdiutil(&args), "attach in {}", dir.display());
    }
    assert_eq!(sb.mounts().len(), 3, "{:?}", sb.mounts());

    let out = sb.navctl(&["scan"], &image);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("stale scratch mount"),
        "{}",
        stderr(&out)
    );
    let left = sb.mounts();
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(mounts_under(&locked), left);
    for (dir, kept) in [
        (&mounted, false),
        (&unmounted, false),
        (&locked, true),
        (&legacy_dead, false),
        (&legacy_live, true),
    ] {
        assert_eq!(dir.exists(), kept, "{}", dir.display());
    }
    drop(held);
}

/// SIGINT while the image is attaching: navctl exits 130. If the attach
/// was killed, the run directory is kept and the next run sweeps it.
#[test]
fn an_interrupted_scan_detaches_and_exits_130() {
    let sb = Sandbox::new("sigint");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    let image = sb.image("sigint.dmg", "UDZO");
    let child = Command::new(env!("CARGO_BIN_EXE_navctl"))
        .arg("scan")
        .arg(&image)
        .env("TMPDIR", sb.root.join("tmp"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Wait for the run directory, which exists for the whole attach.
    let deadline = Instant::now() + Duration::from_secs(30);
    while std::fs::read_dir(sb.scratch()).map_or(true, |mut d| d.next().is_none()) {
        assert!(Instant::now() < deadline, "no run directory appeared");
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(300));
    // SAFETY: plain kill(2) on our own child.
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let out = child.wait_with_output().unwrap();
    // The attach may already have finished and the scan with it.
    if out.status.code() != Some(0) {
        assert_eq!(out.status.code(), Some(130), "{}", stderr(&out));
        assert!(stderr(&out).contains("interrupted"), "{}", stderr(&out));
    }
    if stderr(&out).contains("may still be attached") {
        let next = sb.navctl(&["scan"], &image);
        assert_eq!(next.status.code(), Some(0), "{}", stderr(&next));
    }
    sb.assert_clean();
}

/// An image another process attached with `-nomount` is scanned through
/// navctl's own clone, and the other attachment is left alone (#175).
#[test]
fn an_image_attached_elsewhere_stays_attached() {
    let sb = Sandbox::new("held");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    let image = sb.image("held.dmg", "UDZO");
    assert!(hdiutil(&[
        os("attach"),
        os("-nomount"),
        os("-readonly"),
        os("-quiet"),
        os(&image)
    ]));
    let held = sb.mounts();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].1, "", "{held:?}");

    let out = sb.navctl(&["scan"], &image);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout(&out).ends_with("(disk image: 1 files)\n"),
        "{}",
        stdout(&out)
    );
    assert_no_scratch_path(&out);
    assert_eq!(sb.mounts(), held);
    assert_eq!(mounts_under(&sb.scratch()), Vec::new());
    sb.detach_all();
    sb.assert_clean();
}

/// An image on another volume than the scratch directory cannot be cloned
/// and is never copied: it is `Partial` with the reason (#176).
#[test]
fn an_image_on_another_volume_is_not_copied() {
    let sb = Sandbox::new("off-volume");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    let inner = sb.image("inner.dmg", "UDZO");
    let outer_src = sb.root.join("outer-src");
    std::fs::create_dir(&outer_src).unwrap();
    std::fs::rename(&inner, outer_src.join("inner.dmg")).unwrap();
    let outer = sb.root.join("outer.dmg");
    assert!(hdiutil(&[
        os("create"),
        os("-quiet"),
        os("-format"),
        os("UDZO"),
        os("-srcfolder"),
        os(&outer_src),
        os(&outer),
    ]));
    sb.wait_released();
    let vol = sb.root.join("vol");
    std::fs::create_dir(&vol).unwrap();
    assert!(hdiutil(&[
        os("attach"),
        os("-readonly"),
        os("-nobrowse"),
        os("-quiet"),
        os("-mountpoint"),
        os(&vol),
        os(&outer),
    ]));

    let out = sb.navctl(&["scan"], &vol.join("inner.dmg"));
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("different volume from the scratch directory and is not copied"),
        "{}",
        stderr(&out)
    );
    assert!(stdout(&out).contains("completeness=Partial"));
    assert_eq!(mounts_under(&sb.scratch()), Vec::new());
    sb.detach_all();
    sb.assert_clean();
}

/// `uchg`/`uappnd` on the image do not keep its clone from being removed.
#[test]
fn an_immutable_image_leaves_no_clone_behind() {
    let sb = Sandbox::new("uchg");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    let image = sb.image("locked.dmg", "UDZO");
    assert!(Command::new("/usr/bin/chflags")
        .arg("uchg,uappnd")
        .arg(&image)
        .status()
        .unwrap()
        .success());
    let out = sb.navctl(&["scan"], &image);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    sb.assert_clean();
}

/// A volume mounted at a mount point under a run directory.
fn scratch_volume(scratch: &Path) -> Option<PathBuf> {
    std::fs::read_dir(scratch).ok()?.flatten().find_map(|run| {
        std::fs::read_dir(run.path().join("mnt"))
            .ok()?
            .flatten()
            .map(|mp| mp.path())
            .find(|mp| is_mount_point(mp))
    })
}

/// Whether process `pid` has a child (navctl's `hdiutil`).
fn has_child(pid: i32) -> bool {
    Command::new("/usr/bin/pgrep")
        .args(["-P", &pid.to_string()])
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

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

/// An image of 5,000 small files, so its walk outlasts stopping navctl.
fn big_image(sb: &Sandbox) -> PathBuf {
    for d in 0..50 {
        let dir = sb.src().join(format!("d{d:02}"));
        std::fs::create_dir(&dir).unwrap();
        for f in 0..100 {
            std::fs::write(dir.join(format!("f{f:03}.txt")), "plain text\n").unwrap();
        }
    }
    sb.image("big.dmg", "UDZO")
}

/// Starts navctl `args image` and SIGSTOPs it once a volume is mounted
/// under the scratch root. Also returns the mount point if the volume was
/// still mounted once navctl stopped.
fn stop_when_mounted(sb: &Sandbox, args: &[&str], image: &Path) -> (Child, Option<PathBuf>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_navctl"))
        .args(args)
        .arg(image)
        .env("TMPDIR", sb.root.join("tmp"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    // The volume appears before `hdiutil attach` exits; wait for both.
    let pid = child.id() as i32;
    while scratch_volume(&sb.scratch()).is_none() || has_child(pid) {
        assert!(Instant::now() < deadline, "no volume was mounted");
        if child.try_wait().unwrap().is_some() {
            return (child, None);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    // SAFETY: plain kill(2) on our own child.
    unsafe { libc::kill(pid, libc::SIGSTOP) };
    let mounted = scratch_volume(&sb.scratch());
    (child, mounted)
}

/// SIGINT while a volume is mounted under the scratch root: navctl
/// detaches it, removes the run directory, says so and exits 130 (#173).
#[test]
fn a_signal_after_the_mount_detaches_and_exits_130() {
    let sb = Sandbox::new("sigint-mounted");
    let image = big_image(&sb);
    for attempt in 1..=3 {
        let (child, mounted) = stop_when_mounted(&sb, &["scan"], &image);
        // The SIGINT is delivered on SIGCONT.
        // SAFETY: plain kill(2) on our own child.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGINT);
            libc::kill(child.id() as i32, libc::SIGCONT);
        }
        let out = child.wait_with_output().unwrap();
        if mounted.is_none() || out.status.code() == Some(0) {
            // The walk finished first; nothing was interrupted.
            sb.assert_clean();
            assert!(attempt < 3, "never interrupted during the walk");
            continue;
        }
        assert_eq!(out.status.code(), Some(130), "{}", stderr(&out));
        assert!(
            stderr(&out).contains("scan interrupted; scratch mounts detached"),
            "{}",
            stderr(&out)
        );
        sb.assert_clean();
        return;
    }
}

/// A volume detached by someone else while navctl walks it is a mount gap,
/// so `coverage_complete` is false (#177).
#[test]
fn a_volume_unmounted_during_the_scan_is_a_gap() {
    let sb = Sandbox::new("vanished");
    let image = big_image(&sb);
    for attempt in 1..=3 {
        let (child, mounted) = stop_when_mounted(&sb, &["rules", "test", "--json"], &image);
        if let Some(mp) = &mounted {
            assert!(hdiutil(&[os("detach"), os(mp), os("-force"), os("-quiet")]));
        }
        // SAFETY: plain kill(2) on our own child.
        unsafe { libc::kill(child.id() as i32, libc::SIGCONT) };
        let out = child.wait_with_output().unwrap();
        sb.assert_clean();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let gaps = v["mount_gaps"].to_string();
        if mounted.is_none() || !gaps.contains("unmounted during the scan") {
            // navctl was past the check when it stopped.
            assert!(attempt < 3, "never detached during the walk: {gaps}");
            continue;
        }
        assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
        assert_eq!(v["coverage_complete"], false);
        assert_eq!(gaps, r#"["volume 1 was unmounted during the scan"]"#);
        return;
    }
}
