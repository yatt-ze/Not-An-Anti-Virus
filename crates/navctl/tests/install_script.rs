//! `install.sh` against a fake release on disk (`file://`), with shimmed
//! `uname`, `id`, `sysctl` and `gh` (§13, #250). No network, no real `gh`.

#![cfg(unix)]
#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const ARM: &str = "aarch64-apple-darwin";
const X86: &str = "x86_64-apple-darwin";
const MARKER: &str = "# Added by the NAV installer; navctl uninstall removes it";

/// One test's sandbox. `home`, `bin` and `tmp` contain spaces on purpose.
struct Fx {
    root: PathBuf,
    home: PathBuf,
    bin: PathBuf,
    tmp: PathBuf,
    rel: PathBuf,
    shims: PathBuf,
}

/// Runs `cmd` on a pseudo-terminal (stdout is a TTY, `/dev/tty` opens), sends
/// `answer` once the `[Y/n] ` prompt appears, and returns the exit status
/// and the terminal output with CRLF folded to LF.
fn run_pty(cmd: &mut Command, answer: &str) -> (bool, String) {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;

    let (mut m, mut sl) = (0, 0);
    // SAFETY: valid out-pointers; the name, termios and winsize may be null.
    let rc = unsafe {
        libc::openpty(
            &mut m,
            &mut sl,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    // SAFETY: openpty returned two fresh descriptors that nothing else owns.
    let (mut master, slave) = unsafe { (fs::File::from_raw_fd(m), fs::File::from_raw_fd(sl)) };
    cmd.stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    // SAFETY: setsid and ioctl are async-signal-safe; this makes the pty the
    // child's controlling terminal so `/dev/tty` opens.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    // Drop the parent's slave copies so the master sees EOF at exit.
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let (mut buf, mut text, mut sent) = ([0u8; 4096], String::new(), false);
    while let Ok(n) = master.read(&mut buf) {
        if n == 0 {
            break;
        }
        text.push_str(&String::from_utf8_lossy(&buf[..n]));
        if !sent && text.contains("[Y/n] ") {
            master.write_all(answer.as_bytes()).unwrap();
            sent = true;
        }
    }
    let ok = child.wait().unwrap().success();
    (ok, text.replace("\r\n", "\n"))
}

fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn sha256(p: &Path) -> String {
    let o = run(Command::new("shasum").args(["-a", "256"]).arg(p));
    out(&o).split_whitespace().next().unwrap().to_string()
}

impl Fx {
    fn new(name: &str) -> Fx {
        let root = std::env::temp_dir().join(format!("nav-install-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let fx = Fx {
            home: root.join("h ome"),
            bin: root.join("in stall"),
            tmp: root.join("t mp"),
            rel: root.join("rel"),
            shims: root.join("shims"),
            root,
        };
        for d in [&fx.home, &fx.tmp, &fx.rel, &fx.shims] {
            fs::create_dir_all(d).unwrap();
        }
        script(
            &fx.shims.join("uname"),
            r#"case "$1" in -s) echo "${FAKE_S:-Darwin}";; -m) echo "${FAKE_M:-arm64}";; *) exec /usr/bin/uname "$@";; esac"#,
        );
        script(
            &fx.shims.join("id"),
            r#"if [ "$1" = -u ]; then echo "${FAKE_UID:-501}"; else exec /usr/bin/id "$@"; fi"#,
        );
        script(&fx.shims.join("sysctl"), r#"echo "${FAKE_TRANSLATED:-0}""#);
        fx
    }

    fn receipt(&self) -> PathBuf {
        self.home.join(".local/share/nav/install-receipt.json")
    }

    fn installed(&self) -> PathBuf {
        self.bin.join("navctl")
    }

    /// A fake `gh` that logs `attestation` calls to `gh.log`.
    fn fake_gh(&self) {
        script(
            &self.shims.join("gh"),
            r#"case "$1" in
--version) echo "gh version $FAKE_GH_VERSION (2026-01-01)";;
auth) exit "${FAKE_GH_AUTH:-0}";;
attestation) echo "$@" >> "$FAKE_GH_LOG"; exit "${FAKE_GH_VERIFY:-0}";;
esac"#,
        );
    }

    /// Builds the release for `target`: `stage` populates the archive's
    /// source dir, `members` is what goes into the tarball.
    fn release_with(&self, target: &str, stage: impl FnOnce(&Path), members: &[&str]) {
        let dir = self.root.join("stage");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        stage(&dir);
        let asset = format!("navctl-{VERSION}-{target}.tar.gz");
        let st = Command::new("/usr/bin/tar")
            .arg("-czf")
            .arg(self.rel.join(&asset))
            .arg("-C")
            .arg(&dir)
            .args(members)
            .status()
            .unwrap();
        assert!(st.success());
        self.write_sums(&asset);
    }

    fn write_sums(&self, asset: &str) {
        let o = run(Command::new("shasum")
            .args(["-a", "256", asset])
            .current_dir(&self.rel));
        fs::write(self.rel.join("SHA256SUMS"), o.stdout).unwrap();
    }

    fn release(&self, target: &str) {
        self.release_with(
            target,
            |d| {
                fs::copy(env!("CARGO_BIN_EXE_navctl"), d.join("navctl")).unwrap();
            },
            &["navctl"],
        );
    }

    fn cmd(&self) -> Command {
        let sh = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh");
        let mut c = Command::new("sh");
        c.arg(sh)
            .env_clear()
            .env("HOME", &self.home)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", self.shims.display()),
            )
            .env("TMPDIR", &self.tmp)
            .env("NAV_VERSION", VERSION)
            .env("NAV_INSTALL_DIR", &self.bin)
            .env(
                "NAV_DOWNLOAD_BASE",
                format!("file://{}", self.rel.display()),
            )
            .env("FAKE_GH_LOG", self.root.join("gh.log"));
        c
    }

    fn install(&self) -> Output {
        run(&mut self.cmd())
    }

    /// No temp files in the install or receipt dirs, and no work dir left.
    fn assert_clean(&self) {
        for d in [self.bin.clone(), self.receipt().parent().unwrap().into()] {
            let Ok(rd) = fs::read_dir(&d) else { continue };
            for e in rd {
                let n = e.unwrap().file_name().to_string_lossy().into_owned();
                assert!(!n.starts_with('.'), "leftover {n} in {}", d.display());
            }
        }
        assert_eq!(fs::read_dir(&self.tmp).unwrap().count(), 0, "work dir left");
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn expect_ok(o: &Output) {
    assert!(o.status.success(), "stdout: {}\nstderr: {}", out(o), err(o));
}

fn expect_fail(o: &Output, needle: &str) {
    assert!(!o.status.success(), "unexpected success: {}", out(o));
    assert!(err(o).contains(needle), "stderr: {}", err(o));
}

/// Installs once, applies `break_it`, reruns, and checks the refusal left
/// the first install untouched.
fn refuses(name: &str, needle: &str, break_it: impl FnOnce(&Fx)) {
    let fx = Fx::new(name);
    fx.release(ARM);
    expect_ok(&fx.install());
    let bin = fs::read(fx.installed()).unwrap();
    let receipt = fs::read(fx.receipt()).unwrap();

    break_it(&fx);
    expect_fail(&fx.install(), needle);

    assert_eq!(fs::read(fx.installed()).unwrap(), bin);
    assert_eq!(fs::read(fx.receipt()).unwrap(), receipt);
    fx.assert_clean();
}

/// Without a prior install, nothing may appear.
fn refuses_fresh(name: &str, needle: &str, break_it: impl FnOnce(&Fx)) {
    let fx = Fx::new(name);
    fx.release(ARM);
    break_it(&fx);
    expect_fail(&fx.install(), needle);
    assert!(!fx.installed().exists());
    assert!(!fx.receipt().exists());
    fx.assert_clean();
}

#[test]
fn non_darwin_refused() {
    let fx = Fx::new("linux");
    fx.release(ARM);
    let o = run(fx.cmd().env("FAKE_S", "Linux"));
    expect_fail(&o, "macOS-only");
    assert!(!fx.installed().exists());
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    /// The receipt is byte-exact serde_json pretty output with the canonical
    /// path, modes are 0600/0700, and the installed binary runs.
    #[test]
    fn clean_install() {
        let fx = Fx::new("clean");
        fx.release(ARM);
        let o = fx.install();
        expect_ok(&o);
        assert!(out(&o).contains("export PATH="), "{}", out(&o));

        let v = run(Command::new(fx.installed()).arg("--version"));
        assert_eq!(out(&v), format!("navctl {VERSION}\n"));
        assert_eq!(mode(&fx.installed()), 0o755);

        let canon = fs::canonicalize(&fx.bin).unwrap().join("navctl");
        let want = format!(
            "{{\n  \"schema\": 1,\n  \"version\": \"{VERSION}\",\n  \"target\": \"{ARM}\",\n  \"binary_path\": \"{}\",\n  \"binary_sha256\": \"{}\",\n  \"path_edit\": null\n}}\n",
            canon.display(),
            sha256(&fx.installed())
        );
        assert_eq!(fs::read_to_string(fx.receipt()).unwrap(), want);
        assert_eq!(mode(&fx.receipt()), 0o600);
        assert_eq!(mode(fx.receipt().parent().unwrap()), 0o700);
        fx.assert_clean();
    }

    /// The exact plain-text output of a fresh install off PATH, checksum only.
    #[test]
    fn fresh_output() {
        let fx = Fx::new("fresh-out");
        fx.release(ARM);
        let o = run(fx.cmd().env("SHELL", "/bin/zsh"));
        expect_ok(&o);
        let canon = fs::canonicalize(&fx.bin).unwrap();
        let archive = fx.rel.join(format!("navctl-{VERSION}-{ARM}.tar.gz"));
        let mb = fs::metadata(archive).unwrap().len() as f64 / 1e6;
        let want = format!(
            "Installing navctl {VERSION} for Apple silicon ({ARM})
  - Downloaded ({mb:.1} MB)
  - Verified SHA-256 checksum
  - Skipped build attestation check (install gh 2.102.0+ to enable it)
Installed navctl {VERSION} in {canon}

{dir} isn't on your PATH yet. Add this line to ~/.zshrc:
  export PATH=\"{dir}:$PATH\"
Then open a new terminal.

Get started: navctl scan <file or .app>  (navctl --help for more)
",
            canon = canon.display(),
            dir = fx.bin.display()
        );
        assert_eq!(out(&o), want);
        assert_eq!(err(&o), "");
    }

    /// Reinstall and version-change wording, from the receipt's version.
    #[test]
    fn reinstall_wording() {
        let fx = Fx::new("wording");
        fx.release(ARM);
        expect_ok(&fx.install());
        let o = fx.install();
        let canon = fs::canonicalize(&fx.bin).unwrap();
        assert!(
            out(&o).contains(&format!(
                "Reinstalled navctl {VERSION} in {}\n",
                canon.display()
            )),
            "{}",
            out(&o)
        );

        let r = fs::read_to_string(fx.receipt()).unwrap();
        let old = r.replace(
            &format!("\"version\": \"{VERSION}\""),
            "\"version\": \"0.0.1\"",
        );
        fs::write(fx.receipt(), old).unwrap();
        let o = fx.install();
        assert!(
            out(&o).contains(&format!(
                "Updated navctl 0.0.1 -> {VERSION} in {}\n",
                canon.display()
            )),
            "{}",
            out(&o)
        );
    }

    /// The exact refusal for an unmanaged navctl: nothing on stdout.
    #[test]
    fn refusal_output() {
        let fx = Fx::new("refuse-out");
        fx.release(ARM);
        fs::create_dir_all(&fx.bin).unwrap();
        fs::write(fx.installed(), "old").unwrap();
        let o = fx.install();
        let canon = fs::canonicalize(&fx.bin).unwrap().join("navctl");
        assert!(!o.status.success());
        assert_eq!(out(&o), "");
        assert_eq!(
            err(&o),
            format!(
                "error: {} already exists and wasn't installed by this script\nRemove it, or replace it with:\n  curl -fsSL https://raw.githubusercontent.com/yatt-ze/Not-An-Anti-Virus/main/install.sh | NAV_FORCE=1 sh\n",
                canon.display()
            )
        );
    }

    /// A different navctl earlier on PATH is pointed out; ours first is not.
    #[test]
    fn shadowed_navctl() {
        let fx = Fx::new("shadow");
        fx.release(ARM);
        let other = fx.root.join("other");
        fs::create_dir_all(&other).unwrap();
        script(&other.join("navctl"), "exit 0");
        let path = |first: &Path, second: &Path| {
            format!(
                "{}:{}:{}:/usr/bin:/bin",
                first.display(),
                second.display(),
                fx.shims.display()
            )
        };
        let o = run(fx.cmd().env("PATH", path(&other, &fx.bin)));
        expect_ok(&o);
        assert!(out(&o).contains("comes first on your PATH"), "{}", out(&o));
        assert!(!out(&o).contains("isn't on your PATH"), "{}", out(&o));
        assert!(!out(&o).contains("cargo uninstall"), "{}", out(&o));
        let o = run(fx.cmd().env("PATH", path(&fx.bin, &other)));
        expect_ok(&o);
        assert!(!out(&o).contains("comes first"), "{}", out(&o));

        let cargo = fx.root.join(".cargo/bin");
        fs::create_dir_all(&cargo).unwrap();
        script(&cargo.join("navctl"), "exit 0");
        let o = run(fx.cmd().env("PATH", path(&cargo, &fx.bin)));
        expect_ok(&o);
        assert!(out(&o).contains("cargo uninstall navctl"), "{}", out(&o));
    }

    /// A symlinked install dir is recorded by its canonical path.
    #[test]
    fn symlinked_dir() {
        let fx = Fx::new("symdir");
        fx.release(ARM);
        let real = fx.root.join("re al");
        fs::create_dir_all(&real).unwrap();
        let link = fx.root.join("li nk");
        symlink(&real, &link).unwrap();
        expect_ok(&run(fx.cmd().env("NAV_INSTALL_DIR", &link)));
        let r = fs::read_to_string(fx.receipt()).unwrap();
        let canon = fs::canonicalize(&real).unwrap().join("navctl");
        assert!(r.contains(&format!("\"binary_path\": \"{}\",", canon.display())));
        assert!(real.join("navctl").is_file());
    }

    /// A managed binary is replaced silently, or with a note after drift.
    #[test]
    fn managed_reinstall() {
        let fx = Fx::new("reinstall");
        fx.release(ARM);
        expect_ok(&fx.install());
        let o = fx.install();
        expect_ok(&o);
        assert!(!out(&o).contains("was modified since"), "{}", out(&o));

        let mut b = fs::read(fx.installed()).unwrap();
        b.extend_from_slice(b"drift");
        fs::write(fx.installed(), b).unwrap();
        let o = fx.install();
        expect_ok(&o);
        assert!(out(&o).contains("was modified since"), "{}", out(&o));
        assert!(fs::read_to_string(fx.receipt())
            .unwrap()
            .contains(&sha256(&fx.installed())));
        fx.assert_clean();
    }

    /// An unmanaged navctl is refused untouched; NAV_FORCE=1 replaces it.
    #[test]
    fn unmanaged_file() {
        let fx = Fx::new("unmanaged");
        fx.release(ARM);
        fs::create_dir_all(&fx.bin).unwrap();
        fs::write(fx.installed(), "old").unwrap();
        expect_fail(&fx.install(), "NAV_FORCE");
        assert_eq!(fs::read_to_string(fx.installed()).unwrap(), "old");
        assert!(!fx.receipt().exists());
        fx.assert_clean();

        expect_ok(&run(fx.cmd().env("NAV_FORCE", "1")));
        assert_ne!(
            fs::read_to_string(fx.installed()).unwrap_or_default(),
            "old"
        );
        assert!(fx.receipt().exists());
    }

    /// An unmanaged symlink is refused, and forced replacement swaps the
    /// link without touching its target.
    #[test]
    fn unmanaged_symlink() {
        let fx = Fx::new("unmlink");
        fx.release(ARM);
        fs::create_dir_all(&fx.bin).unwrap();
        let target = fx.root.join("target");
        fs::write(&target, "precious").unwrap();
        symlink(&target, fx.installed()).unwrap();
        expect_fail(&fx.install(), "NAV_FORCE");
        assert!(fs::symlink_metadata(fx.installed())
            .unwrap()
            .file_type()
            .is_symlink());

        expect_ok(&run(fx.cmd().env("NAV_FORCE", "1")));
        let md = fs::symlink_metadata(fx.installed()).unwrap();
        assert!(md.file_type().is_file());
        assert_eq!(fs::read_to_string(&target).unwrap(), "precious");
    }

    #[test]
    fn bad_checksum() {
        refuses("badsum", "checksum mismatch", |fx| {
            let asset = format!("navctl-{VERSION}-{ARM}.tar.gz");
            fs::write(
                fx.rel.join("SHA256SUMS"),
                format!("{}  {asset}\n", "0".repeat(64)),
            )
            .unwrap();
        });
    }

    #[test]
    fn missing_sums_line() {
        refuses("nosum", "exactly once", |fx| {
            fs::write(
                fx.rel.join("SHA256SUMS"),
                format!("{}  other.tar.gz\n", "0".repeat(64)),
            )
            .unwrap();
        });
    }

    #[test]
    fn duplicate_sums_line() {
        refuses("dupsum", "exactly once", |fx| {
            let s = fs::read_to_string(fx.rel.join("SHA256SUMS")).unwrap();
            fs::write(fx.rel.join("SHA256SUMS"), format!("{s}{s}")).unwrap();
        });
    }

    /// A truncated archive (interrupted download) fails the checksum.
    #[test]
    fn truncated_archive() {
        refuses("trunc", "checksum mismatch", |fx| {
            let p = fx.rel.join(format!("navctl-{VERSION}-{ARM}.tar.gz"));
            let b = fs::read(&p).unwrap();
            fs::write(&p, &b[..b.len() / 2]).unwrap();
        });
    }

    #[test]
    fn missing_archive() {
        refuses("noarch", "could not download", |fx| {
            fs::remove_file(fx.rel.join(format!("navctl-{VERSION}-{ARM}.tar.gz"))).unwrap();
        });
    }

    #[test]
    fn extra_member() {
        refuses_fresh("extra", "unexpected contents", |fx| {
            fx.release_with(
                ARM,
                |d| {
                    fs::copy(env!("CARGO_BIN_EXE_navctl"), d.join("navctl")).unwrap();
                    fs::write(d.join("extra"), "x").unwrap();
                },
                &["navctl", "extra"],
            );
        });
    }

    #[test]
    fn symlinked_member() {
        refuses_fresh("symmem", "not a regular file", |fx| {
            fx.release_with(
                ARM,
                |d| symlink(env!("CARGO_BIN_EXE_navctl"), d.join("navctl")).unwrap(),
                &["navctl"],
            );
        });
    }

    #[test]
    fn wrong_version() {
        refuses("wrongver", "reports", |fx| {
            fx.release_with(
                ARM,
                |d| script(&d.join("navctl"), "echo navctl 9.9.9"),
                &["navctl"],
            );
        });
    }

    #[test]
    fn unsupported_arch() {
        let fx = Fx::new("arch");
        fx.release(ARM);
        expect_fail(
            &run(fx.cmd().env("FAKE_M", "riscv64")),
            "unsupported architecture",
        );
        assert!(!fx.installed().exists());
    }

    #[test]
    fn intel_target() {
        let fx = Fx::new("intel");
        fx.release(X86);
        expect_ok(&run(fx.cmd().env("FAKE_M", "x86_64")));
        assert!(fs::read_to_string(fx.receipt()).unwrap().contains(X86));
    }

    /// An x86_64 shell under Rosetta installs the arm64 build.
    #[test]
    fn rosetta_arm() {
        let fx = Fx::new("rosetta");
        fx.release(ARM);
        expect_ok(&run(fx
            .cmd()
            .env("FAKE_M", "x86_64")
            .env("FAKE_TRANSLATED", "1")));
        assert!(fs::read_to_string(fx.receipt()).unwrap().contains(ARM));
    }

    #[test]
    fn root_refused() {
        let fx = Fx::new("root");
        fx.release(ARM);
        expect_fail(&run(fx.cmd().env("FAKE_UID", "0")), "root");
        assert!(!fx.installed().exists());
    }

    #[test]
    fn invalid_version() {
        let fx = Fx::new("badver");
        for v in [
            "v1.2.3",
            "1.2",
            "1.2.3.4",
            "1.2.3-rc1",
            "1..3",
            "a.b.c",
            "1.2.3\n",
        ] {
            expect_fail(&run(fx.cmd().env("NAV_VERSION", v)), "NAV_VERSION");
        }
    }

    #[test]
    fn base_needs_version() {
        let fx = Fx::new("nobase");
        expect_fail(
            &run(fx.cmd().env_remove("NAV_VERSION")),
            "requires NAV_VERSION",
        );
    }

    #[test]
    fn quote_in_dir() {
        let fx = Fx::new("quote");
        fx.release(ARM);
        let bad = fx.root.join("a\"b");
        expect_fail(&run(fx.cmd().env("NAV_INSTALL_DIR", bad)), "quote");
        assert!(!fx.receipt().exists());
    }

    fn with_gh(name: &str, version: &str, f: impl FnOnce(&Fx, &mut Command)) -> (Fx, Output) {
        let fx = Fx::new(name);
        fx.release(ARM);
        fx.fake_gh();
        let mut c = fx.cmd();
        c.env("FAKE_GH_VERSION", version);
        f(&fx, &mut c);
        let o = run(&mut c);
        (fx, o)
    }

    #[test]
    fn gh_too_old() {
        let (fx, o) = with_gh("gh101", "2.101.0", |_, _| {});
        expect_ok(&o);
        assert!(
            out(&o).contains("Skipped build attestation") && out(&o).contains("older than 2.102.0"),
            "{}",
            out(&o)
        );
        assert!(!fx.root.join("gh.log").exists());
    }

    #[test]
    fn gh_prerelease() {
        let (_fx, o) = with_gh("ghrc", "2.102.0-rc.1", |_, _| {});
        expect_ok(&o);
        assert!(out(&o).contains("needs a stable gh"), "{}", out(&o));
    }

    #[test]
    fn gh_logged_out() {
        let (fx, o) = with_gh("ghout", "2.102.0", |_, c| {
            c.env("FAKE_GH_AUTH", "1");
        });
        expect_ok(&o);
        assert!(out(&o).contains("gh auth login"), "{}", out(&o));
        assert!(!fx.root.join("gh.log").exists());
    }

    #[test]
    fn attestation_fails() {
        let (fx, o) = with_gh("ghbad", "2.102.0", |_, c| {
            c.env("FAKE_GH_VERIFY", "1");
        });
        expect_fail(&o, "attestation");
        assert!(!fx.installed().exists());
        assert!(!fx.receipt().exists());
        fx.assert_clean();
    }

    /// Verification runs with the exact repo and signer identity.
    #[test]
    fn attestation_passes() {
        let (fx, o) = with_gh("ghok", "2.102.0", |_, _| {});
        expect_ok(&o);
        assert!(
            out(&o).contains("Verified build attestation"),
            "{}",
            out(&o)
        );
        let log = fs::read_to_string(fx.root.join("gh.log")).unwrap();
        assert!(log.contains("--repo yatt-ze/Not-An-Anti-Virus"), "{log}");
        assert!(
            log.contains("--cert-identity https://github.com/yatt-ze/Not-An-Anti-Virus/.github/workflows/release.yml@refs/heads/main"),
            "{log}"
        );
        assert!(fx.installed().exists());
    }

    fn zsh(fx: &Fx) -> Command {
        let mut c = fx.cmd();
        c.env("SHELL", "/bin/zsh");
        c
    }

    fn block(fx: &Fx) -> String {
        format!("{MARKER}\nexport PATH=\"{}:$PATH\"\n", fx.bin.display())
    }

    fn rc(fx: &Fx) -> PathBuf {
        fx.home.join(".zshrc")
    }

    fn path_edit(fx: &Fx) -> String {
        let r = fs::read_to_string(fx.receipt()).unwrap();
        r.lines()
            .find(|l| l.starts_with("  \"path_edit\": "))
            .unwrap()
            .trim_start_matches("  \"path_edit\": ")
            .to_string()
    }

    fn rc_quoted(p: &Path) -> String {
        format!("\"{}\"", p.display())
    }

    /// `NAV_MODIFY_PATH=1` appends the exact block and records the file; a
    /// rerun neither duplicates it nor loses the receipt field.
    #[test]
    fn path_added() {
        let fx = Fx::new("pathadd");
        fx.release(ARM);
        let o = run(zsh(&fx).env("NAV_MODIFY_PATH", "1"));
        expect_ok(&o);
        assert!(out(&o).contains("  - Added "), "{}", out(&o));
        assert!(out(&o).contains("Open a new terminal to start using navctl.\n"));
        assert_eq!(fs::read_to_string(rc(&fx)).unwrap(), block(&fx));
        assert_eq!(path_edit(&fx), rc_quoted(&rc(&fx)));

        let o = run(zsh(&fx).env("NAV_MODIFY_PATH", "1"));
        expect_ok(&o);
        assert!(
            out(&o).contains("is already added to PATH in "),
            "{}",
            out(&o)
        );
        assert_eq!(fs::read_to_string(rc(&fx)).unwrap(), block(&fx));
        assert_eq!(path_edit(&fx), rc_quoted(&rc(&fx)));

        // Dir now on PATH, or edits switched off: the field is carried over.
        let on_path = format!("{}:/usr/bin:/bin", fx.bin.display());
        expect_ok(&run(zsh(&fx).env("PATH", on_path)));
        assert_eq!(path_edit(&fx), rc_quoted(&rc(&fx)));
        expect_ok(&run(zsh(&fx).env("NAV_MODIFY_PATH", "0")));
        assert_eq!(path_edit(&fx), rc_quoted(&rc(&fx)));
        assert_eq!(fs::read_to_string(rc(&fx)).unwrap(), block(&fx));
    }

    /// A deleted navctl doesn't lose `path_edit`: that line keeps the dir on PATH.
    #[test]
    fn path_edit_kept() {
        let fx = Fx::new("pathkeep");
        fx.release(ARM);
        expect_ok(&run(zsh(&fx).env("NAV_MODIFY_PATH", "1")));
        fs::remove_file(fx.installed()).unwrap();
        let on_path = format!("{}:/usr/bin:/bin", fx.bin.display());
        expect_ok(&run(zsh(&fx).env("PATH", on_path)));
        assert_eq!(path_edit(&fx), rc_quoted(&rc(&fx)));
    }

    /// A relative install dir is refused before anything is written.
    #[test]
    fn relative_dir() {
        let fx = Fx::new("reldir");
        fx.release(ARM);
        expect_fail(&run(fx.cmd().env("NAV_INSTALL_DIR", "bin")), "absolute");
        assert!(!fx.receipt().exists());
    }

    /// `NAV_MODIFY_PATH=0` touches no file and prints the hint.
    #[test]
    fn path_declined() {
        let fx = Fx::new("pathoff");
        fx.release(ARM);
        let o = run(zsh(&fx).env("NAV_MODIFY_PATH", "0"));
        expect_ok(&o);
        assert!(
            out(&o).contains("Add this line to ~/.zshrc:"),
            "{}",
            out(&o)
        );
        assert!(!rc(&fx).exists());
        assert_eq!(path_edit(&fx), "null");
    }

    #[test]
    fn zdotdir_used() {
        let fx = Fx::new("zdot");
        fx.release(ARM);
        let z = fx.root.join("z dot");
        fs::create_dir_all(&z).unwrap();
        expect_ok(&run(zsh(&fx)
            .env("NAV_MODIFY_PATH", "1")
            .env("ZDOTDIR", &z)));
        assert_eq!(fs::read_to_string(z.join(".zshrc")).unwrap(), block(&fx));
        assert!(!rc(&fx).exists());
        assert_eq!(path_edit(&fx), rc_quoted(&z.join(".zshrc")));
    }

    #[test]
    fn bash_profile() {
        let fx = Fx::new("bashrc");
        fx.release(ARM);
        expect_ok(&run(fx
            .cmd()
            .env("SHELL", "/bin/bash")
            .env("NAV_MODIFY_PATH", "1")));
        assert_eq!(
            fs::read_to_string(fx.home.join(".bash_profile")).unwrap(),
            block(&fx)
        );
    }

    /// Fish keeps the printed hint even with `NAV_MODIFY_PATH=1`.
    #[test]
    fn fish_hint() {
        let fx = Fx::new("fish");
        fx.release(ARM);
        let o = run(fx
            .cmd()
            .env("SHELL", "/usr/bin/fish")
            .env("NAV_MODIFY_PATH", "1"));
        expect_ok(&o);
        assert!(out(&o).contains("fish_add_path"), "{}", out(&o));
        assert_eq!(path_edit(&fx), "null");
        assert_eq!(fs::read_dir(&fx.home).unwrap().count(), 1, "only .local");
    }

    /// An rc file that can't be written falls back to the hint, exit 0.
    #[test]
    fn rc_unwritable() {
        let fx = Fx::new("rcfail");
        fx.release(ARM);
        fs::create_dir(rc(&fx)).unwrap();
        let o = run(zsh(&fx).env("NAV_MODIFY_PATH", "1"));
        expect_ok(&o);
        assert!(out(&o).contains("Couldn't change ~/.zshrc"), "{}", out(&o));
        assert!(
            out(&o).contains("isn't on your PATH yet. Add this line"),
            "{}",
            out(&o)
        );
        assert_eq!(path_edit(&fx), "null");

        fs::remove_dir(rc(&fx)).unwrap();
        fs::write(rc(&fx), "keep\n").unwrap();
        fs::set_permissions(rc(&fx), fs::Permissions::from_mode(0o444)).unwrap();
        let o = run(zsh(&fx).env("NAV_MODIFY_PATH", "1"));
        expect_ok(&o);
        assert!(out(&o).contains("Couldn't change"), "{}", out(&o));
        assert_eq!(fs::read_to_string(rc(&fx)).unwrap(), "keep\n");
    }

    #[test]
    fn newline_added() {
        let fx = Fx::new("nonl");
        fx.release(ARM);
        fs::write(rc(&fx), "export A=1").unwrap();
        expect_ok(&run(zsh(&fx).env("NAV_MODIFY_PATH", "1")));
        assert_eq!(
            fs::read_to_string(rc(&fx)).unwrap(),
            format!("export A=1\n{}", block(&fx))
        );
    }

    #[test]
    fn invalid_modify() {
        let fx = Fx::new("badmod");
        // No release on disk: the refusal must come before any download.
        let o = run(zsh(&fx).env("NAV_MODIFY_PATH", "yes"));
        expect_fail(&o, "NAV_MODIFY_PATH");
        assert_eq!(out(&o), "");
    }

    /// Answering the prompt on a terminal: n leaves the file alone, Enter edits.
    #[test]
    fn prompt_answers() {
        let fx = Fx::new("prompt");
        fx.release(ARM);
        let (ok, text) = run_pty(zsh(&fx).env("NO_COLOR", "1"), "n\n");
        assert!(ok, "{text}");
        assert!(text.contains("Add it to ~/.zshrc? [Y/n] n\n"), "{text}");
        assert!(text.contains("Add this line to ~/.zshrc:"), "{text}");
        assert!(!rc(&fx).exists());
        assert_eq!(path_edit(&fx), "null");

        let (ok, text) = run_pty(zsh(&fx).env("NO_COLOR", "1"), "\n");
        assert!(ok, "{text}");
        assert!(text.contains("Added "), "{text}");
        assert_eq!(fs::read_to_string(rc(&fx)).unwrap(), block(&fx));
        assert_eq!(path_edit(&fx), rc_quoted(&rc(&fx)));
    }
}
