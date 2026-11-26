//! Install / uninstall / residue-check, driven off one [`Layout`] and one
//! [`SystemOps`] (§11.10). The three share the [`Layout::manifest`] enumeration
//! so teardown can't drift behind install and orphan root-owned files.
//!
//! Filesystem work uses plain `std::fs` against prefixed paths (fakes faithfully
//! under a temp dir); only the privileged operations go through the seam.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::ops::SystemOps;
use crate::{FsKind, Layout, CODESIGN_ID, LABEL, TCC_SERVICE};

const DIR_MODE: u32 = 0o755;
const PLIST_MODE: u32 = 0o644;
const BIN_MODE: u32 = 0o755;

/// What [`install`] copied.
#[derive(Debug, Clone)]
pub struct InstallReport {
    /// The source after following symlinks.
    pub source: PathBuf,
    /// Lowercase-hex SHA-256 of the source bytes, taken while copying, before
    /// the ad-hoc codesign step changes the installed file.
    pub sha256: String,
}

/// Copy `navd` to its root-owned home, lay down state dirs and the plist, and
/// bootstrap the daemon. Idempotent: safe to re-run over an existing install.
///
/// `navd_src` is resolved (symlinks followed), then opened with `O_NOFOLLOW`
/// and checked on the open handle: it must be a regular file, not group- or
/// world-writable, and owned by a uid in `allowed_owners`. The copy reads from
/// that same handle. Hardening only: it cannot stop code running as an allowed
/// owner from swapping the file (§11.10).
/// Requires the privileges `ops` implies — real installs run as root.
pub fn install(
    layout: &Layout,
    ops: &dyn SystemOps,
    navd_src: &Path,
    allowed_owners: &[u32],
) -> Result<InstallReport> {
    let source = fs::canonicalize(navd_src)
        .with_context(|| format!("navd binary not found at {}", navd_src.display()))?;
    let mut src_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&source)
        .with_context(|| format!("opening {}", source.display()))?;
    let meta = src_file.metadata()?;
    anyhow::ensure!(
        meta.is_file(),
        "refusing {}: not a regular file",
        source.display()
    );
    anyhow::ensure!(
        meta.mode() & 0o022 == 0,
        "refusing {}: group- or world-writable (fix: chmod go-w)",
        source.display()
    );
    anyhow::ensure!(
        allowed_owners.contains(&meta.uid()),
        "refusing {}: owned by uid {}, allowed uids are {:?} (fix: chown to one of them)",
        source.display(),
        meta.uid(),
        allowed_owners
    );

    // Tear out a still-loaded prior job so the new plist bootstraps cleanly.
    // `bootout` returns before the process actually exits, so it does *not*
    // by itself avoid ETXTBSY on the copy below — the unlink right before
    // `fs::copy` is what does that (a still-running process keeps its old
    // inode open; the copy just creates a fresh one).
    if ops.is_loaded(LABEL)? {
        ops.bootout(LABEL)?;
    }

    // Root-owned config and state dirs; state holds the helper-dir marker.
    for dir in [layout.config_dir(), layout.state_dir()] {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE))?;
        ops.chown_root(&dir)?;
    }

    // Root-owned copy of the daemon (never the Cellar path, §11.10). The helper
    // dir is Apple-shared: create it only if absent and set explicit root:wheel
    // 0755 perms only when we created it — never re-permission a dir another
    // installer already owns, and don't leave the perms to root's umask.
    // Marker first, so a failure after creating the dir can't leave it unmarked.
    let helper_dir = layout.helper_dir();
    if !helper_dir.exists() {
        let marker = layout.helper_dir_marker();
        fs::write(&marker, b"").with_context(|| format!("writing marker {}", marker.display()))?;
        fs::set_permissions(&marker, fs::Permissions::from_mode(PLIST_MODE))?;
        ops.chown_root(&marker)?;
        fs::create_dir_all(&helper_dir)
            .with_context(|| format!("creating {}", helper_dir.display()))?;
        fs::set_permissions(&helper_dir, fs::Permissions::from_mode(DIR_MODE))?;
        ops.chown_root(&helper_dir)?;
    }
    let bin = layout.helper_binary();
    // Unlink any existing binary first: a still-running prior daemon keeps its
    // old inode open, so `fs::copy` creates a fresh one instead of truncating
    // the one in use — this, not the `bootout` above, is what avoids ETXTBSY.
    remove_file_if_present(&bin).with_context(|| format!("removing old {}", bin.display()))?;
    let sha256 = copy_hashed(&mut src_file, &bin)
        .with_context(|| format!("copying navd to {}", bin.display()))?;
    fs::set_permissions(&bin, fs::Permissions::from_mode(BIN_MODE))?;
    ops.chown_root(&bin)?;
    ops.codesign_adhoc(&bin, CODESIGN_ID)?;

    // LaunchDaemon plist, pointing at the copied binary.
    let plist = layout.plist_path();
    if let Some(parent) = plist.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&plist, layout.render_plist())
        .with_context(|| format!("writing {}", plist.display()))?;
    fs::set_permissions(&plist, fs::Permissions::from_mode(PLIST_MODE))?;
    ops.chown_root(&plist)?;

    // Clear a sticky disable override before loading — but only when one is
    // actually set: an unconditional `enable` writes a persistent enabled
    // record into launchd's disabled DB, itself residue (§11.10).
    if ops.is_disabled(LABEL)? {
        ops.enable(LABEL)?;
    }
    ops.bootstrap(&plist)?;
    Ok(InstallReport { source, sha256 })
}

/// Copy `src` to a new file at `dst`, returning the lowercase-hex SHA-256 of
/// the bytes copied.
fn copy_hashed(src: &mut fs::File, dst: &Path) -> Result<String> {
    let mut out = fs::File::create(dst)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])?;
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// What an uninstall managed to do. Best-effort: every artifact is attempted
/// regardless of earlier failures, so a partial install still tears down.
#[derive(Debug, Default)]
pub struct UninstallReport {
    pub removed: Vec<PathBuf>,
    pub errors: Vec<String>,
}

impl UninstallReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Reverse [`install`], tolerant of a partial or failed install. Never fails
/// because a piece is already gone; collects errors rather than aborting.
///
/// Does not touch the Homebrew-managed `navctl` (§11.10). The TCC grant is
/// reset best-effort and scoped to [`CODESIGN_ID`] — the one artifact with no
/// guaranteed removal (§11.8).
pub fn uninstall(layout: &Layout, ops: &dyn SystemOps) -> UninstallReport {
    let mut report = UninstallReport::default();

    // Clear a sticky disable override *before* bootout (it survives bootout),
    // but only if one is set — an unconditional `enable` would leave a
    // persistent enabled record, defeating zero residue (§11.10). On a failed
    // check, clear defensively so a stuck override can't block a re-install.
    let disabled = match ops.is_disabled(LABEL) {
        Ok(d) => d,
        Err(e) => {
            report.errors.push(format!("is_disabled {LABEL}: {e:#}"));
            true
        }
    };
    if disabled {
        if let Err(e) = ops.enable(LABEL) {
            report.errors.push(format!("enable {LABEL}: {e:#}"));
        }
    }
    if let Err(e) = ops.bootout(LABEL) {
        report.errors.push(format!("bootout {LABEL}: {e:#}"));
    }

    let helper_dir_ours = layout.helper_dir_marker().is_file();
    let mut helper_dir_failed = false;
    for artifact in layout.manifest().fs {
        let path = artifact.path;
        let result = match artifact.kind {
            FsKind::File => remove_file_if_present(&path),
            // Keep the marker so a re-run can still reclaim the helper dir.
            FsKind::Dir if helper_dir_failed && path == layout.state_dir() => {
                report.errors.push(format!(
                    "{}: kept, holds the helper-dir marker",
                    path.display()
                ));
                continue;
            }
            FsKind::Dir => remove_dir_all_if_present(&path),
            // A non-empty shared dir holds another installer's helper (§11.10).
            FsKind::SharedDir => {
                let r = remove_shared_dir_if_empty(&path, helper_dir_ours);
                helper_dir_failed = r.is_err();
                r
            }
        };
        match result {
            Ok(true) => report.removed.push(path),
            Ok(false) => {}
            Err(e) => report.errors.push(format!("{}: {e:#}", path.display())),
        }
    }

    // Honest residual: attempt the scoped reset; can't be guaranteed (§11.8).
    if let Err(e) = ops.tccutil_reset(TCC_SERVICE, CODESIGN_ID) {
        report
            .errors
            .push(format!("tccutil reset {CODESIGN_ID}: {e:#}"));
    }

    report
}

/// Observable leftover state after an uninstall. Excludes TCC: its grant can't
/// be queried here, so it's reported by [`uninstall`]'s action, not asserted.
#[derive(Debug, Default)]
pub struct ResidueReport {
    /// Manifest paths still present (a `SharedDir` only if we created it, and it
    /// is present and empty).
    pub fs_residue: Vec<PathBuf>,
    pub launchd_loaded: bool,
    pub launchd_disabled: bool,
    /// A benign `=> enabled` record lingering in launchd's disabled DB.
    /// Reported for visibility but not counted as unclean: there's no CLI to
    /// unset it, and uninstall only ever creates it while clearing a real
    /// disable override (§11.10/§11.8).
    pub launchd_enabled_record: bool,
    /// `navd`-named entries in our parent dirs that the manifest doesn't list —
    /// a backstop against manifest drift.
    pub swept_extras: Vec<PathBuf>,
}

impl ResidueReport {
    /// True when nothing observable is left behind.
    pub fn is_clean(&self) -> bool {
        self.fs_residue.is_empty()
            && !self.launchd_loaded
            && !self.launchd_disabled
            && self.swept_extras.is_empty()
    }
}

/// Assert-clean check the verify runner calls. Reports rather than mutates.
pub fn residue(layout: &Layout, ops: &dyn SystemOps) -> Result<ResidueReport> {
    let mut report = ResidueReport::default();
    let manifest = layout.manifest();
    let helper_dir_ours = layout.helper_dir_marker().is_file();

    for artifact in &manifest.fs {
        let leftover = match artifact.kind {
            // `symlink_metadata` doesn't follow symlinks, so it also catches a
            // dangling one — `exists()` would miss it, but `remove_file_if_present`
            // (uninstall) removes it, so residue must see it too.
            FsKind::File | FsKind::Dir => fs::symlink_metadata(&artifact.path).is_ok(),
            FsKind::SharedDir => {
                helper_dir_ours && artifact.path.is_dir() && is_empty_dir(&artifact.path)?
            }
        };
        if leftover {
            report.fs_residue.push(artifact.path.clone());
        }
    }

    report.launchd_loaded = ops.is_loaded(LABEL)?;
    let record = ops.disable_record(LABEL)?;
    report.launchd_disabled = record == Some(true);
    report.launchd_enabled_record = record == Some(false);

    let managed: std::collections::HashSet<&PathBuf> =
        manifest.fs.iter().map(|a| &a.path).collect();
    for dir in sweep_dirs(layout) {
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&dir).with_context(|| format!("sweeping {}", dir.display()))? {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if is_our_namespace(name) && !managed.contains(&path) {
                report.swept_extras.push(path);
            }
        }
    }

    Ok(report)
}

/// Whether `name` looks like one of ours: exactly `navd`, `navd.`-prefixed
/// (e.g. `navd.out.log`), or `com.nav.navd`-prefixed (e.g. a launchd label
/// plist) — narrow enough that an unrelated `com.other.mynavdhelper` isn't
/// swept as a false positive.
fn is_our_namespace(name: &str) -> bool {
    name == "navd" || name.starts_with("navd.") || name.starts_with("com.nav.navd")
}

/// The parent dirs a name sweep inspects for stray `navd`-named artifacts.
fn sweep_dirs(layout: &Layout) -> Vec<PathBuf> {
    let mut dirs = vec![layout.helper_dir()];
    for p in [layout.plist_path(), layout.config_dir(), layout.state_dir()] {
        if let Some(parent) = p.parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    dirs
}

fn is_empty_dir(path: &Path) -> Result<bool> {
    Ok(fs::read_dir(path)?.next().is_none())
}

fn remove_file_if_present(path: &Path) -> Result<bool> {
    if path.exists() || path.is_symlink() {
        fs::remove_file(path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn remove_dir_all_if_present(path: &Path) -> Result<bool> {
    if path.exists() {
        fs::remove_dir_all(path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn remove_shared_dir_if_empty(path: &Path, ours: bool) -> Result<bool> {
    if ours && path.is_dir() && is_empty_dir(path)? {
        fs::remove_dir(path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{Call, FakeSystemOps};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Unique temp prefix, cleaned up on drop — no external tempdir dep.
    struct TempPrefix(PathBuf);

    impl TempPrefix {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "nav-service-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn layout(&self) -> Layout {
            Layout::under(&self.0)
        }
    }

    impl Drop for TempPrefix {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fake_navd(tp: &TempPrefix) -> PathBuf {
        let src = tp.0.join("navd-src");
        fs::write(&src, b"#!/bin/sh\nsleep 1\n").unwrap();
        src
    }

    /// The current uid, read off a file this process creates.
    fn me() -> u32 {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "nav-service-uid-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&p, b"").unwrap();
        let uid = fs::metadata(&p).unwrap().uid();
        let _ = fs::remove_file(&p);
        uid
    }

    fn mode_err(mode: u32) -> String {
        let tp = TempPrefix::new();
        let src = fake_navd(&tp);
        fs::set_permissions(&src, fs::Permissions::from_mode(mode)).unwrap();
        let err = install(&tp.layout(), &FakeSystemOps::new(), &src, &[me()]).unwrap_err();
        format!("{err:#}")
    }

    #[test]
    fn refuses_group_writable() {
        assert!(mode_err(0o775).contains("writable"));
    }

    #[test]
    fn refuses_world_writable() {
        assert!(mode_err(0o757).contains("writable"));
    }

    /// An owner outside the allowed list is refused and nothing is installed.
    #[test]
    fn refuses_other_owner() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let src = fake_navd(&tp);
        let other = me().wrapping_add(1);
        let err = install(&layout, &FakeSystemOps::new(), &src, &[other]).unwrap_err();
        assert!(format!("{err:#}").contains("allowed uids"));
        assert!(!layout.helper_binary().exists());
    }

    /// A symlinked source (Homebrew style) is followed; the report names the
    /// resolved target.
    #[test]
    fn follows_symlink() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let real = fs::canonicalize(fake_navd(&tp)).unwrap();
        let link = tp.0.join("navd-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let report = install(&layout, &FakeSystemOps::new(), &link, &[me()]).unwrap();
        assert_eq!(report.source, real);
        assert_eq!(
            fs::read(layout.helper_binary()).unwrap(),
            fs::read(&real).unwrap()
        );
    }

    /// SHA-256 of "abc" is a published test vector.
    #[test]
    fn reports_sha256() {
        let tp = TempPrefix::new();
        let src = tp.0.join("navd-abc");
        fs::write(&src, b"abc").unwrap();
        let report = install(&tp.layout(), &FakeSystemOps::new(), &src, &[me()]).unwrap();
        assert_eq!(
            report.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn install_creates_every_artifact_and_signs_the_copy() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();

        assert!(layout.helper_binary().is_file());
        assert!(layout.config_dir().is_dir());
        assert!(layout.state_dir().is_dir());
        assert_eq!(
            fs::read_to_string(layout.plist_path()).unwrap(),
            layout.render_plist()
        );

        let calls = ops.calls();
        assert!(calls.contains(&Call::CodesignAdhoc {
            path: layout.helper_binary(),
            identifier: CODESIGN_ID.into(),
        }));
        assert!(calls.contains(&Call::ChownRoot(layout.helper_binary())));
        assert!(calls.contains(&Call::Bootstrap(layout.plist_path())));
    }

    #[test]
    fn install_sets_root_owned_perms_on_a_helper_dir_it_creates() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        assert!(
            ops.calls().contains(&Call::ChownRoot(layout.helper_dir())),
            "a helper dir we create must be chowned root:wheel, not left to umask"
        );
    }

    #[test]
    fn install_does_not_repermission_a_preexisting_shared_helper_dir() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        fs::create_dir_all(layout.helper_dir()).unwrap();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        assert!(
            !ops.calls().contains(&Call::ChownRoot(layout.helper_dir())),
            "must not chown a shared helper dir another installer already owns"
        );
    }

    #[test]
    fn install_is_idempotent_and_rebootstraps() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        let src = fake_navd(&tp);
        install(&layout, &ops, &src, &[me()]).unwrap();
        install(&layout, &ops, &src, &[me()]).unwrap(); // must not error
                                                        // Second install saw a loaded job and tore it out before re-bootstrapping.
        assert!(ops.calls().contains(&Call::Bootout(LABEL.into())));
    }

    #[test]
    fn install_unlinks_a_preexisting_binary_before_copying() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let bin = layout.helper_binary();
        fs::create_dir_all(bin.parent().unwrap()).unwrap();
        fs::write(&bin, b"stale binary").unwrap();
        let ops = FakeSystemOps::new();
        let src = fake_navd(&tp);

        install(&layout, &ops, &src, &[me()]).unwrap();

        assert_eq!(fs::read(&bin).unwrap(), fs::read(&src).unwrap());
    }

    #[test]
    fn install_skips_enable_when_not_disabled() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();

        let calls = ops.calls();
        assert!(
            !calls.contains(&Call::Enable(LABEL.into())),
            "a clean install must not write an enabled record"
        );
        assert!(calls.contains(&Call::Bootstrap(layout.plist_path())));
    }

    #[test]
    fn install_clears_a_disable_override() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::preloaded();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();

        let calls = ops.calls();
        assert!(
            calls.contains(&Call::Enable(LABEL.into())),
            "a real disable override must be cleared"
        );
        assert!(calls.contains(&Call::Bootstrap(layout.plist_path())));
    }

    #[test]
    fn uninstall_then_residue_is_clean() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();

        let report = uninstall(&layout, &ops);
        assert!(report.is_ok(), "uninstall errors: {:?}", report.errors);
        assert!(residue(&layout, &ops).unwrap().is_clean());
        // The empty shared helper dir we created was reclaimed.
        assert!(!layout.helper_dir().exists());
    }

    #[test]
    fn preexisting_empty_helper_dir_survives_install_and_uninstall() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        fs::create_dir_all(layout.helper_dir()).unwrap();
        let ops = FakeSystemOps::new();
        assert!(
            residue(&layout, &ops).unwrap().is_clean(),
            "a pre-existing empty dir is not residue before any install"
        );
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        assert!(!layout.helper_dir_marker().exists());

        let report = uninstall(&layout, &ops);
        assert!(report.is_ok(), "uninstall errors: {:?}", report.errors);
        assert!(
            layout.helper_dir().is_dir(),
            "must not reclaim a dir we didn't create"
        );
        assert!(residue(&layout, &ops).unwrap().is_clean());
    }

    #[test]
    fn install_marks_a_helper_dir_it_creates_and_uninstall_clears_the_marker() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        assert!(layout.helper_dir_marker().is_file());
        // A re-install over our own dir keeps the marker.
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        assert!(layout.helper_dir_marker().is_file());

        uninstall(&layout, &ops);
        assert!(!layout.helper_dir().exists());
        assert!(!layout.helper_dir_marker().exists());
    }

    #[test]
    fn uninstall_crash_after_reclaiming_helper_dir_leaves_the_marker_as_residue() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        // Helper dir gone, marker (in the state dir) not yet removed.
        fs::remove_file(layout.helper_binary()).unwrap();
        fs::remove_dir(layout.helper_dir()).unwrap();

        let report = residue(&layout, &ops).unwrap();
        assert!(report.fs_residue.contains(&layout.state_dir()));
        // Re-running uninstall finishes the job.
        let report = uninstall(&layout, &ops);
        assert!(report.is_ok(), "errors: {:?}", report.errors);
        assert!(residue(&layout, &ops).unwrap().is_clean());
    }

    #[test]
    fn uninstall_tolerates_partial_install() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        // Only the plist exists — install died partway.
        fs::create_dir_all(layout.plist_path().parent().unwrap()).unwrap();
        fs::write(layout.plist_path(), "partial").unwrap();

        let report = uninstall(&layout, &ops);
        assert!(report.is_ok(), "errors: {:?}", report.errors);
        assert!(residue(&layout, &ops).unwrap().is_clean());
    }

    #[test]
    fn uninstall_keeps_the_marker_when_reclaiming_the_helper_dir_fails() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        fs::remove_file(layout.helper_binary()).unwrap();
        let dir = layout.helper_dir();
        // An unreadable dir makes the emptiness check fail.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read_dir(&dir).is_ok() {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
            return; // running as root: permissions don't bite
        }

        let report = uninstall(&layout, &ops);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!report.is_ok());
        assert!(layout.helper_dir_marker().is_file(), "marker must survive");

        let report = uninstall(&layout, &ops);
        assert!(report.is_ok(), "errors: {:?}", report.errors);
        assert!(!dir.exists());
        assert!(residue(&layout, &ops).unwrap().is_clean());
    }

    #[test]
    fn uninstall_leaves_a_nonempty_shared_dir_alone() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        // Another installer's helper lands in the shared dir.
        let foreign = layout.helper_dir().join("other-helper");
        fs::write(&foreign, b"not ours").unwrap();

        uninstall(&layout, &ops);
        assert!(
            layout.helper_dir().is_dir(),
            "must not reclaim a shared dir in use"
        );
        assert!(
            foreign.is_file(),
            "must not delete another installer's file"
        );
        // A non-empty shared dir holding no navd-named file is not our residue.
        assert!(residue(&layout, &ops).unwrap().is_clean());
    }

    #[test]
    fn residue_flags_a_leftover_file() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        // Simulate a teardown that missed the state dir.
        fs::remove_file(layout.helper_binary()).unwrap();
        fs::remove_file(layout.plist_path()).unwrap();
        fs::remove_dir_all(layout.config_dir()).unwrap();

        let report = residue(&layout, &ops).unwrap();
        assert!(!report.is_clean());
        assert!(report.fs_residue.contains(&layout.state_dir()));
    }

    #[test]
    fn residue_name_sweep_catches_unmanaged_artifact() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        // A stray navd-named plist the manifest doesn't know about.
        let dir = layout.plist_path().parent().unwrap().to_path_buf();
        fs::create_dir_all(&dir).unwrap();
        let stray = dir.join("com.nav.navd.helper.plist");
        fs::write(&stray, "stray").unwrap();

        let report = residue(&layout, &ops).unwrap();
        assert!(report.swept_extras.contains(&stray));
        assert!(!report.is_clean());
    }

    #[test]
    fn residue_name_sweep_ignores_an_unrelated_foreign_file() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        // A foreign file that merely contains "navd" as a substring, not ours —
        // keeps the shared helper dir non-empty across uninstall (like the
        // `uninstall_leaves_a_nonempty_shared_dir_alone` case).
        let foreign = layout.helper_dir().join("com.other.mynavdhelper");
        fs::write(&foreign, "not ours").unwrap();
        uninstall(&layout, &ops);

        let report = residue(&layout, &ops).unwrap();
        assert!(
            !report.swept_extras.contains(&foreign),
            "must not sweep an unrelated file that merely contains \"navd\""
        );
        assert!(report.is_clean());
    }

    #[test]
    fn residue_flags_a_dangling_symlink_at_a_managed_path() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();
        // Simulate a teardown that left a broken symlink where the binary was.
        fs::remove_file(layout.helper_binary()).unwrap();
        std::os::unix::fs::symlink("/nonexistent/target", layout.helper_binary()).unwrap();

        let report = residue(&layout, &ops).unwrap();
        assert!(report.fs_residue.contains(&layout.helper_binary()));
        assert!(!report.is_clean());
    }

    #[test]
    fn residue_flags_a_sticky_disable_override() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        // Loaded job cleared, but a disable override lingers.
        let ops = FakeSystemOps::preloaded();
        ops.bootout(LABEL).unwrap();
        let report = residue(&layout, &ops).unwrap();
        assert!(report.launchd_disabled);
        assert!(!report.is_clean());
    }

    #[test]
    fn uninstall_skips_enable_when_not_disabled() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp), &[me()]).unwrap();

        let report = uninstall(&layout, &ops);
        assert!(report.is_ok(), "uninstall errors: {:?}", report.errors);
        assert!(
            !ops.calls().contains(&Call::Enable(LABEL.into())),
            "uninstall must not write an enabled record when none was disabled"
        );
        assert!(residue(&layout, &ops).unwrap().is_clean());
    }

    #[test]
    fn uninstall_clears_a_real_disable_override() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::preloaded();

        uninstall(&layout, &ops);
        assert!(
            ops.calls().contains(&Call::Enable(LABEL.into())),
            "a real disable override must be cleared"
        );
        assert!(!residue(&layout, &ops).unwrap().launchd_disabled);
    }

    #[test]
    fn uninstall_leaves_a_benign_enabled_record_that_stays_clean() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::preloaded();

        uninstall(&layout, &ops);
        let report = residue(&layout, &ops).unwrap();
        assert!(
            report.launchd_enabled_record,
            "clearing a real override leaves a benign enabled record"
        );
        assert!(
            report.is_clean(),
            "a benign enabled record must not defeat clean"
        );
    }
}
