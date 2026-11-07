//! End-to-end coverage for `navctl scan` / `rules test` on disk images
//! (§6.2, #86): images are built with `hdiutil create`, and every test
//! checks that nothing stays mounted under its private scratch root. They
//! run one at a time: under concurrent load hdiutil fails with EAGAIN and
//! `create` can leave its own temporary attach behind.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
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
    let paths: Vec<String> = stdout(&json)
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["path"].as_str().unwrap().to_owned()
        })
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

    let rules = sb.navctl(&["rules", "test"], &image);
    assert_eq!(rules.status.code(), Some(3));
    assert!(stdout(&rules).starts_with("Disk image not mounted: "));
    sb.assert_clean();
}

/// An encrypted image never reaches `hdiutil imageinfo` or `attach`, so no
/// passphrase prompt can appear. nav-core does not recognise one as a disk
/// image (its `encrcdsa` header hides the UDIF trailer), so navctl scans
/// it as a file without creating a scratch directory.
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
    assert!(out.status.code().is_some(), "{}", stderr(&out));
    assert!(!stderr(&out).contains("not mounted"), "{}", stderr(&out));
    assert!(!sb.scratch().exists(), "hdiutil path was entered");
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
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("links.dmg!readme.txt"), "{lines:?}");
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

/// A mount left by a killed navctl (its pid gone) is detached by the next
/// run; one owned by a live pid is left alone.
#[test]
fn stale_mounts_from_a_dead_run_are_swept() {
    let sb = Sandbox::new("stale");
    std::fs::write(sb.src().join("readme.txt"), "hello\n").unwrap();
    let image = sb.image("stale.dmg", "UDZO");
    // One image can only be attached once at a time.
    let dead_image = sb.root.join("dead.dmg");
    let live_image = sb.root.join("live.dmg");
    std::fs::copy(&image, &dead_image).unwrap();
    std::fs::copy(&image, &live_image).unwrap();
    std::fs::create_dir(sb.scratch()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(sb.scratch(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let mut gone = Command::new("/usr/bin/true").spawn().unwrap();
    let dead = gone.id();
    gone.wait().unwrap();
    let dead_dir = sb.scratch().join(format!("{dead}-feedface"));
    let live_dir = sb
        .scratch()
        .join(format!("{}-feedface", std::process::id()));
    for (dir, img) in [(&dead_dir, &dead_image), (&live_dir, &live_image)] {
        std::fs::create_dir(dir).unwrap();
        let attached = hdiutil(&[
            os("attach"),
            os("-readonly"),
            os("-nobrowse"),
            os("-quiet"),
            os("-mountrandom"),
            os(dir),
            os(img),
        ]);
        assert!(attached);
    }

    let out = sb.navctl(&["scan"], &image);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("stale scratch mount"),
        "{}",
        stderr(&out)
    );
    let left: Vec<_> = sb
        .mounts()
        .into_iter()
        .filter(|m| !m.1.is_empty())
        .collect();
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(Path::new(&left[0].1).starts_with(&live_dir), "{left:?}");
    assert!(!dead_dir.exists());
}

/// SIGINT while the image is attaching: navctl detaches and exits 130.
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
    sb.assert_clean();
}
