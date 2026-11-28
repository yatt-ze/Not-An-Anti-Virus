//! `navctl uninstall` against a throwaway HOME, a fake service layout and
//! no launchd (§8, §13, #250). Needs the debug-only `NAV_TEST_*` overrides.

#![cfg(all(unix, debug_assertions))]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MARKER: &str = "# Added by the NAV installer; navctl uninstall removes it";
const EXPORT: &str = "export PATH=\"$HOME/.local/bin:$PATH\"";
const SERVICE_DIRS: [&str; 4] = [
    "Library/LaunchDaemons",
    "Library/PrivilegedHelperTools",
    "etc/navd",
    "private/var/db/navd",
];

/// One test's sandbox: `home` has a space on purpose, `bin` is `~/.local/bin`.
struct Fx {
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    svc: PathBuf,
    uid: u32,
}

impl Drop for Fx {
    fn drop(&mut self) {
        // Undo any read-only dirs a test left behind.
        fn open_up(p: &Path) {
            if let Ok(m) = fs::symlink_metadata(p) {
                if m.is_dir() {
                    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
                    if let Ok(rd) = fs::read_dir(p) {
                        for e in rd.flatten() {
                            open_up(&e.path());
                        }
                    }
                }
            }
        }
        open_up(&self.root);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn sha256(p: &Path) -> String {
    Sha256::digest(fs::read(p).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// True when permission tricks can't work (running as root).
fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments and never fails.
    unsafe { libc::geteuid() == 0 }
}

fn lock(p: &Path) {
    fs::set_permissions(p, fs::Permissions::from_mode(0o555)).unwrap();
}

fn unlock(p: &Path) {
    fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
}

/// `bin uninstall` with only the test overrides that fake the service.
fn run_at(fx: &Fx, bin: &Path) -> Output {
    Command::new(bin)
        .arg("uninstall")
        .env_clear()
        .env("HOME", &fx.home)
        .env("NAV_TEST_SERVICE_ROOT", &fx.svc)
        .output()
        .unwrap()
}

impl Fx {
    /// A managed install: `navctl` in `~/.local/bin`, a receipt, and a
    /// `~/.zshrc` holding the installer's PATH block.
    fn new(name: &str) -> Fx {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("nav-uninstall-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("h ome");
        let fx = Fx {
            bin: home.join(".local/bin"),
            svc: root.join("svc"),
            home,
            root,
            // SAFETY: getuid takes no arguments and never fails.
            uid: unsafe { libc::getuid() },
        };
        fs::create_dir_all(&fx.bin).unwrap();
        fs::create_dir_all(&fx.svc).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_navctl"), fx.navctl()).unwrap();
        fx.write_receipt(&sha256(&fx.navctl()), Some(&fx.zshrc()));
        fs::write(
            fx.zshrc(),
            format!("alias ll='ls -l'\n{MARKER}\n{EXPORT}\nexport EDITOR=vi\n"),
        )
        .unwrap();
        fx
    }

    fn navctl(&self) -> PathBuf {
        self.bin.join("navctl")
    }

    fn zshrc(&self) -> PathBuf {
        self.home.join(".zshrc")
    }

    fn data_dir(&self) -> PathBuf {
        self.home.join(".local/share/nav")
    }

    fn receipt(&self) -> PathBuf {
        self.data_dir().join("install-receipt.json")
    }

    /// Writes the receipt in install.sh's exact layout.
    fn write_receipt(&self, sha: &str, edit: Option<&Path>) {
        let edit = edit.map_or("null".to_string(), |p| format!("\"{}\"", p.display()));
        fs::create_dir_all(self.data_dir()).unwrap();
        fs::write(
            self.receipt(),
            format!(
                "{{\n  \"schema\": 1,\n  \"version\": \"{VERSION}\",\n  \"target\": \"aarch64-apple-darwin\",\n  \"binary_path\": \"{}\",\n  \"binary_sha256\": \"{sha}\",\n  \"path_edit\": {edit}\n}}\n",
                self.navctl().display()
            ),
        )
        .unwrap();
    }

    /// Lays down a full fake service install.
    fn service(&self) {
        let p = |rel: &str| self.svc.join(rel);
        for d in SERVICE_DIRS {
            fs::create_dir_all(p(d)).unwrap();
        }
        fs::write(p("Library/LaunchDaemons/com.nav.navd.plist"), "plist").unwrap();
        fs::write(p("Library/PrivilegedHelperTools/navd"), "navd").unwrap();
        fs::write(p("private/var/db/navd/navd.out.log"), "log").unwrap();
    }

    fn service_left(&self) -> bool {
        self.svc
            .join("Library/LaunchDaemons/com.nav.navd.plist")
            .exists()
            || self.svc.join("Library/PrivilegedHelperTools/navd").exists()
            || self.svc.join("private/var/db/navd").exists()
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(self.navctl());
        c.arg("uninstall")
            .env_clear()
            .env("HOME", &self.home)
            .env("NAV_TEST_SERVICE_ROOT", &self.svc);
        c
    }

    /// As `sudo` would run it: root, with `SUDO_UID` naming this user.
    fn sudo(&self) -> Command {
        let mut c = self.cmd();
        c.env("NAV_TEST_ROOT", "1")
            .env("SUDO_UID", self.uid.to_string())
            .env("NAV_TEST_SUDO_HOME", &self.home);
        c
    }

    fn run(&self) -> Output {
        self.cmd().output().unwrap()
    }

    fn zshrc_text(&self) -> String {
        fs::read_to_string(self.zshrc()).unwrap()
    }

    /// Binary, receipt and PATH block all still there.
    fn untouched(&self) -> bool {
        self.navctl().exists() && self.receipt().exists() && self.zshrc_text().contains(MARKER)
    }
}

#[test]
fn managed_clean() {
    let fx = Fx::new("clean");
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(
        out(&o),
        format!(
            "Uninstalling navctl {VERSION}\n\
             \x20 - Removed ~/.local/bin/navctl\n\
             \x20 - Removed the PATH line from ~/.zshrc\n\
             \x20 - Removed the install receipt and ~/.local/share/nav\n\
             \n\
             Uninstalled navctl\n"
        )
    );
    assert_eq!(err(&o), "");
    assert!(!fx.navctl().exists() && !fx.data_dir().exists());
    assert!(fx.bin.is_dir(), "the install dir stays");
    assert_eq!(fx.zshrc_text(), "alias ll='ls -l'\nexport EDITOR=vi\n");
}

#[test]
fn managed_with_service() {
    let fx = Fx::new("svc");
    fx.service();
    let o = fx.sudo().output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(
        out(&o),
        format!(
            "Uninstalling navctl {VERSION}\n\
             \x20 - Removed the navd service\n\
             \x20   Full Disk Access grant reset is best-effort; check System Settings.\n\
             \x20 - Removed ~/.local/bin/navctl\n\
             \x20 - Removed the PATH line from ~/.zshrc\n\
             \x20 - Removed the install receipt and ~/.local/share/nav\n\
             \n\
             Uninstalled navctl\n"
        )
    );
    assert!(!fx.service_left() && !fx.navctl().exists());
}

#[test]
fn partial_service() {
    let fx = Fx::new("partial");
    fs::create_dir_all(fx.svc.join("etc/navd")).unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(4));
    assert!(err(&o).contains("needs root"), "{}", err(&o));
    assert!(fx.svc.join("etc/navd").exists() && fx.untouched());

    let o = fx.sudo().output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(!fx.svc.join("etc/navd").exists() && !fx.navctl().exists());
}

#[test]
fn stray_service_file() {
    let fx = Fx::new("stray");
    fs::create_dir_all(fx.svc.join("private/var/db")).unwrap();
    fs::write(fx.svc.join("private/var/db/navd.err.log"), "x").unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(4));
    assert!(err(&o).contains("needs root"), "{}", err(&o));
    assert!(fx.untouched());
}

#[test]
fn service_needs_root() {
    let fx = Fx::new("noroot");
    fx.service();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(4));
    assert_eq!(out(&o), "");
    assert_eq!(
        err(&o),
        "error: the navd service is installed, and removing it needs root\n\
         Nothing was removed. Run: sudo ~/.local/bin/navctl uninstall\n"
    );
    assert!(fx.service_left() && fx.untouched());
}

#[test]
fn sudo_without_uid() {
    let fx = Fx::new("nouid");
    let mut c = fx.cmd();
    c.env("NAV_TEST_ROOT", "1")
        .env("NAV_TEST_SUDO_HOME", &fx.home);
    let o = c.output().unwrap();
    assert_eq!(o.status.code(), Some(4));
    assert_eq!(out(&o), "");
    let e = err(&o);
    assert!(
        e.starts_with("error: SUDO_UID is missing or invalid, so NAV can't tell whose files to remove\nRun it through sudo from your own account: sudo "),
        "{e}"
    );
    assert!(e.ends_with(" uninstall\n"), "{e}");
    assert!(fx.untouched());
}

#[test]
fn sudo_bad_uid() {
    for bad in ["", "abc", "0", "-1", "99999999999"] {
        let fx = Fx::new("baduid");
        let mut c = fx.cmd();
        c.env("NAV_TEST_ROOT", "1")
            .env("NAV_TEST_SUDO_HOME", &fx.home)
            .env("SUDO_UID", bad);
        let o = c.output().unwrap();
        assert_eq!(o.status.code(), Some(4), "{bad:?}");
        assert!(
            err(&o).contains("SUDO_UID is missing or invalid"),
            "{bad:?}"
        );
        assert!(fx.untouched(), "{bad:?}");
    }
}

#[test]
fn no_receipt() {
    let fx = Fx::new("norcpt");
    fs::remove_file(fx.receipt()).unwrap();
    fx.service();
    let o = fx.sudo().output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(
        out(&o),
        "Uninstalling the navd service\n\
         \x20 - Removed the navd service\n\
         \x20   Full Disk Access grant reset is best-effort; check System Settings.\n\
         \n\
         navctl wasn't installed by the NAV installer, so it was left in place.\n\
         Remove ~/.local/bin/navctl yourself.\n"
    );
    assert!(!fx.service_left());
    assert!(fx.navctl().exists() && fx.zshrc_text().contains(MARKER));
}

#[test]
fn no_receipt_no_service() {
    let fx = Fx::new("nothing");
    fs::remove_file(fx.receipt()).unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        out(&o),
        "navctl wasn't installed by the NAV installer, so it was left in place.\n\
         Remove ~/.local/bin/navctl yourself.\n"
    );
    assert!(fx.navctl().exists());
}

#[test]
fn package_manager_hint() {
    let fx = Fx::new("pkg");
    fs::remove_file(fx.receipt()).unwrap();
    let cargo = fx.home.join(".cargo/bin");
    fs::create_dir_all(&cargo).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_navctl"), cargo.join("navctl")).unwrap();
    let o = run_at(&fx, &cargo.join("navctl"));
    assert_eq!(o.status.code(), Some(0));
    assert!(
        out(&o).ends_with("Remove it with: cargo uninstall navctl\n"),
        "{}",
        out(&o)
    );

    let cellar = fx.root.join("opt/Cellar/nav/1.0/bin");
    fs::create_dir_all(&cellar).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_navctl"), cellar.join("navctl")).unwrap();
    let o = run_at(&fx, &cellar.join("navctl"));
    assert!(
        out(&o).ends_with("Remove it with: brew uninstall nav\n"),
        "{}",
        out(&o)
    );
}

#[test]
fn other_binary_receipt() {
    let fx = Fx::new("other");
    let other = fx.root.join("elsewhere");
    fs::create_dir_all(&other).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_navctl"), other.join("navctl")).unwrap();
    let o = run_at(&fx, &other.join("navctl"));
    assert_eq!(o.status.code(), Some(0));
    assert!(
        out(&o).starts_with(
            "The install receipt is for ~/.local/bin/navctl, not this navctl, so it was left alone.\n"
        ),
        "{}",
        out(&o)
    );
    assert!(fx.untouched() && other.join("navctl").exists());
}

#[test]
fn bad_receipt() {
    let fx = Fx::new("badrcpt");
    fs::write(fx.receipt(), "{ not json").unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0));
    assert!(
        out(&o).starts_with(
            "Left ~/.local/share/nav/install-receipt.json alone: it couldn't be read ("
        ),
        "{}",
        out(&o)
    );
    assert!(fx.navctl().exists());
}

#[test]
fn receipt_symlink() {
    let fx = Fx::new("linkrcpt");
    let real = fx.root.join("real.json");
    fs::rename(fx.receipt(), &real).unwrap();
    symlink(&real, fx.receipt()).unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0));
    assert!(out(&o).contains("not a regular file"), "{}", out(&o));
    assert!(fx.navctl().exists() && real.exists());
}

#[test]
fn hash_mismatch() {
    let fx = Fx::new("hash");
    fx.write_receipt(&"0".repeat(64), Some(&fx.zshrc()));
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(
        out(&o),
        format!(
            "Uninstalling navctl {VERSION}\n\
             \x20 - ~/.local/bin/navctl was modified since it was installed; removing it anyway\n\
             \x20 - Removed ~/.local/bin/navctl\n\
             \x20 - Removed the PATH line from ~/.zshrc\n\
             \x20 - Removed the install receipt and ~/.local/share/nav\n\
             \n\
             Uninstalled navctl\n"
        )
    );
    assert!(!fx.navctl().exists());
}

#[test]
fn path_dir_shared() {
    let fx = Fx::new("shared");
    fs::write(fx.bin.join("uv"), "").unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(
        out(&o),
        format!(
            "Uninstalling navctl {VERSION}\n\
             \x20 - Removed ~/.local/bin/navctl\n\
             \x20 - Kept the PATH line in ~/.zshrc: ~/.local/bin also holds other programs\n\
             \x20   Remove it yourself when nothing else needs that directory.\n\
             \x20 - Removed the install receipt and ~/.local/share/nav\n\
             \n\
             Uninstalled navctl\n"
        )
    );
    assert!(fx.zshrc_text().contains(MARKER));
}

#[test]
fn ds_store_ignored() {
    let fx = Fx::new("dsstore");
    fs::write(fx.bin.join(".DS_Store"), "").unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0));
    assert!(out(&o).contains("Removed the PATH line from ~/.zshrc"));
    assert!(!fx.zshrc_text().contains(MARKER));
}

#[test]
fn path_block_modified() {
    let fx = Fx::new("modified");
    let edited = format!("alias a=b\n{MARKER}\nexport PATH=\"$HOME/.local/bin:$PATH:/x\"\n");
    fs::write(fx.zshrc(), &edited).unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(
        out(&o),
        format!(
            "Uninstalling navctl {VERSION}\n\
             \x20 - Removed ~/.local/bin/navctl\n\
             \x20 - Kept the PATH line in ~/.zshrc: it no longer matches what the installer wrote\n\
             \x20   Delete the \"{MARKER}\" line and the line after it yourself.\n\
             \x20 - Removed the install receipt and ~/.local/share/nav\n\
             \n\
             Uninstalled navctl\n"
        )
    );
    assert_eq!(fx.zshrc_text(), edited);
}

#[test]
fn path_line_gone() {
    let fx = Fx::new("gone");
    fs::write(fx.zshrc(), "alias a=b\n").unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0));
    assert!(
        out(&o).contains("- The PATH line was already gone from ~/.zshrc\n"),
        "{}",
        out(&o)
    );
    assert_eq!(fx.zshrc_text(), "alias a=b\n");
}

#[test]
fn no_path_edit() {
    let fx = Fx::new("noedit");
    fx.write_receipt(&sha256(&fx.navctl()), None);
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0));
    assert!(!out(&o).contains("PATH"), "{}", out(&o));
    assert!(fx.zshrc_text().contains(MARKER));
}

#[test]
fn custom_dir_block() {
    let fx = Fx::new("custom");
    let dir = fx.root.join("my $bin");
    fs::create_dir_all(&dir).unwrap();
    let bin = dir.join("navctl");
    fs::rename(fx.navctl(), &bin).unwrap();
    let receipt = fs::read_to_string(fx.receipt()).unwrap().replace(
        &fx.navctl().display().to_string(),
        &bin.display().to_string(),
    );
    fs::write(fx.receipt(), receipt).unwrap();
    let escaped = dir.display().to_string().replace('$', "\\$");
    fs::write(
        fx.zshrc(),
        format!("{MARKER}\nexport PATH=\"{escaped}:$PATH\"\n"),
    )
    .unwrap();
    let o = run_at(&fx, &bin);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(
        out(&o).contains("Removed the PATH line from ~/.zshrc"),
        "{}",
        out(&o)
    );
    assert_eq!(fx.zshrc_text(), "");
    assert!(dir.is_dir());
}

#[test]
fn rc_outside_home() {
    let fx = Fx::new("outside");
    let rc = fx.root.join(".zshrc");
    fs::write(&rc, format!("{MARKER}\n{EXPORT}\n")).unwrap();
    fx.write_receipt(&sha256(&fx.navctl()), Some(&rc));
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0));
    assert!(
        out(&o).contains("it isn't a startup file NAV edits"),
        "{}",
        out(&o)
    );
    assert!(fs::read_to_string(&rc).unwrap().contains(MARKER));
}

#[test]
fn rc_symlink() {
    let fx = Fx::new("rclink");
    let real = fx.root.join("dotfiles-zshrc");
    fs::rename(fx.zshrc(), &real).unwrap();
    symlink(&real, fx.zshrc()).unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0));
    assert!(
        out(&o).contains("it isn't a plain file you own"),
        "{}",
        out(&o)
    );
    assert!(fs::read_to_string(&real).unwrap().contains(MARKER));
    assert!(fs::symlink_metadata(fx.zshrc()).unwrap().is_symlink());
}

#[test]
fn rc_mode_kept() {
    let fx = Fx::new("rcmode");
    fs::set_permissions(fx.zshrc(), fs::Permissions::from_mode(0o640)).unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0));
    let mode = fs::metadata(fx.zshrc()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640);
}

#[test]
fn binary_failure() {
    if is_root() {
        return;
    }
    let fx = Fx::new("binfail");
    lock(&fx.bin);
    let o = fx.run();
    assert_eq!(o.status.code(), Some(4));
    assert_eq!(out(&o), format!("Uninstalling navctl {VERSION}\n"));
    assert_eq!(
        err(&o),
        "error: could not remove ~/.local/bin/navctl: Permission denied (os error 13)\n\
         The install receipt was kept, so you can finish with: ~/.local/bin/navctl uninstall\n"
    );
    assert!(fx.untouched(), "nothing after the binary runs");

    unlock(&fx.bin);
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(!fx.navctl().exists() && !fx.data_dir().exists());
    assert!(!fx.zshrc_text().contains(MARKER));
}

#[test]
fn path_failure() {
    if is_root() {
        return;
    }
    let fx = Fx::new("pathfail");
    lock(&fx.home);
    let o = fx.run();
    unlock(&fx.home);
    assert_eq!(o.status.code(), Some(4));
    assert_eq!(
        out(&o),
        format!("Uninstalling navctl {VERSION}\n  - Removed ~/.local/bin/navctl\n")
    );
    assert!(
        err(&o).starts_with("error: could not update ~/.zshrc: Permission denied (os error 13)\n"),
        "{}",
        err(&o)
    );
    assert!(err(&o).contains("The install receipt was kept."));
    assert!(!fx.navctl().exists() && fx.receipt().exists());
    assert!(fx.zshrc_text().contains(MARKER));
}

#[test]
fn receipt_failure() {
    if is_root() {
        return;
    }
    let fx = Fx::new("rcptfail");
    lock(&fx.data_dir());
    let o = fx.run();
    unlock(&fx.data_dir());
    assert_eq!(o.status.code(), Some(4));
    assert_eq!(
        err(&o),
        "error: could not remove ~/.local/share/nav/install-receipt.json: Permission denied (os error 13)\n\
         Remove it yourself: rm ~/.local/share/nav/install-receipt.json\n"
    );
    assert!(!fx.navctl().exists() && fx.receipt().exists());
    assert!(!fx.zshrc_text().contains(MARKER));
}

#[test]
fn data_dir_failure() {
    if is_root() {
        return;
    }
    let fx = Fx::new("dirfail");
    let share = fx.home.join(".local/share");
    lock(&share);
    let o = fx.run();
    unlock(&share);
    assert_eq!(o.status.code(), Some(4));
    assert!(
        out(&o).ends_with("  - Removed the install receipt\n"),
        "{}",
        out(&o)
    );
    assert_eq!(
        err(&o),
        "error: could not remove ~/.local/share/nav: Permission denied (os error 13)\n\
         Remove it yourself: rmdir ~/.local/share/nav\n"
    );
    assert!(fx.data_dir().is_dir() && !fx.receipt().exists());
}

#[test]
fn data_dir_not_empty() {
    let fx = Fx::new("dirfull");
    fs::write(fx.data_dir().join("other"), "x").unwrap();
    let o = fx.run();
    assert_eq!(o.status.code(), Some(0));
    assert!(
        out(&o).contains("  - Removed the install receipt\n"),
        "{}",
        out(&o)
    );
    assert!(fx.data_dir().join("other").exists());
}

#[test]
fn service_failure() {
    if is_root() {
        return;
    }
    let fx = Fx::new("svcfail");
    fx.service();
    let db = fx.svc.join("private/var/db");
    lock(&db);
    let o = fx.sudo().output().unwrap();
    unlock(&db);
    assert_eq!(o.status.code(), Some(4));
    assert_eq!(out(&o), format!("Uninstalling navctl {VERSION}\n"));
    let e = err(&o);
    assert!(
        e.starts_with("error: could not fully remove the navd service\n  "),
        "{e}"
    );
    assert!(e.contains("Permission denied"), "{e}");
    assert!(
        e.ends_with(
            "Nothing else was removed. Fix that, then rerun: sudo ~/.local/bin/navctl uninstall\n"
        ),
        "{e}"
    );
    assert!(fx.untouched());
}

#[test]
fn rerun_finishes() {
    if is_root() {
        return;
    }
    let fx = Fx::new("rerun");
    fx.service();
    let db = fx.svc.join("private/var/db");
    lock(&db);
    let o = fx.sudo().output().unwrap();
    assert_eq!(o.status.code(), Some(4));
    unlock(&db);
    let o = fx.sudo().output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(!fx.service_left() && !fx.navctl().exists() && !fx.data_dir().exists());
}
