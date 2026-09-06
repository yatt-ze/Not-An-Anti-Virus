//! Install / uninstall / residue-check, driven off one [`Layout`] and one
//! [`SystemOps`] (§11.10). The three share the [`Layout::manifest`] enumeration
//! so teardown can't drift behind install and orphan root-owned files.
//!
//! Filesystem work uses plain `std::fs` against prefixed paths (fakes faithfully
//! under a temp dir); only the privileged operations go through the seam.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::ops::SystemOps;
use crate::{FsKind, Layout, CODESIGN_ID, LABEL, TCC_SERVICE};

const DIR_MODE: u32 = 0o755;
const PLIST_MODE: u32 = 0o644;
const BIN_MODE: u32 = 0o755;

/// Copy `navd` to its root-owned home, lay down state dirs and the plist, and
/// bootstrap the daemon. Idempotent: safe to re-run over an existing install.
///
/// `navd_src` is the binary to copy (resolved next to `navctl` by the caller).
/// Requires the privileges `ops` implies — real installs run as root.
pub fn install(layout: &Layout, ops: &dyn SystemOps, navd_src: &Path) -> Result<()> {
    anyhow::ensure!(
        navd_src.is_file(),
        "navd binary not found at {}",
        navd_src.display()
    );

    // Tear out a still-loaded prior job before overwriting its binary — copying
    // over a running executable can fail with ETXTBSY on a real install.
    if ops.is_loaded(LABEL)? {
        ops.bootout(LABEL)?;
    }

    // Root-owned copy of the daemon (never the Cellar path, §11.10).
    fs::create_dir_all(layout.helper_dir())
        .with_context(|| format!("creating {}", layout.helper_dir().display()))?;
    let bin = layout.helper_binary();
    fs::copy(navd_src, &bin).with_context(|| format!("copying navd to {}", bin.display()))?;
    fs::set_permissions(&bin, fs::Permissions::from_mode(BIN_MODE))?;
    ops.chown_root(&bin)?;
    ops.codesign_adhoc(&bin, CODESIGN_ID)?;

    // Root-owned config and state dirs.
    for dir in [layout.config_dir(), layout.state_dir()] {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE))?;
        ops.chown_root(&dir)?;
    }

    // LaunchDaemon plist, pointing at the copied binary.
    let plist = layout.plist_path();
    if let Some(parent) = plist.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&plist, layout.render_plist())
        .with_context(|| format!("writing {}", plist.display()))?;
    fs::set_permissions(&plist, fs::Permissions::from_mode(PLIST_MODE))?;
    ops.chown_root(&plist)?;

    // Clear any sticky disable override before loading (§11.10), then bootstrap.
    ops.enable(LABEL)?;
    ops.bootstrap(&plist)?;
    Ok(())
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

    // Clear a sticky disable override *before* bootout (it survives bootout).
    if let Err(e) = ops.enable(LABEL) {
        report.errors.push(format!("enable {LABEL}: {e:#}"));
    }
    if let Err(e) = ops.bootout(LABEL) {
        report.errors.push(format!("bootout {LABEL}: {e:#}"));
    }

    for artifact in layout.manifest().fs {
        let path = artifact.path;
        let result = match artifact.kind {
            FsKind::File => remove_file_if_present(&path),
            FsKind::Dir => remove_dir_all_if_present(&path),
            // Reclaim the shared Apple dir only if empty — a non-empty one holds
            // another installer's helper and must be left alone (§11.10).
            FsKind::SharedDir => remove_shared_dir_if_empty(&path),
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
    /// Manifest paths still present (a `SharedDir` only if present *and* empty).
    pub fs_residue: Vec<PathBuf>,
    pub launchd_loaded: bool,
    pub launchd_disabled: bool,
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

    for artifact in &manifest.fs {
        let leftover = match artifact.kind {
            FsKind::File | FsKind::Dir => artifact.path.exists(),
            FsKind::SharedDir => artifact.path.is_dir() && is_empty_dir(&artifact.path)?,
        };
        if leftover {
            report.fs_residue.push(artifact.path.clone());
        }
    }

    report.launchd_loaded = ops.is_loaded(LABEL)?;
    report.launchd_disabled = ops.is_disabled(LABEL)?;

    let managed: std::collections::HashSet<&PathBuf> =
        manifest.fs.iter().map(|a| &a.path).collect();
    for dir in sweep_dirs(layout) {
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&dir).with_context(|| format!("sweeping {}", dir.display()))? {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.contains("navd") && !managed.contains(&path) {
                report.swept_extras.push(path);
            }
        }
    }

    Ok(report)
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

fn remove_shared_dir_if_empty(path: &Path) -> Result<bool> {
    if path.is_dir() && is_empty_dir(path)? {
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

    #[test]
    fn install_creates_every_artifact_and_signs_the_copy() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp)).unwrap();

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
    fn install_is_idempotent_and_rebootstraps() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        let src = fake_navd(&tp);
        install(&layout, &ops, &src).unwrap();
        install(&layout, &ops, &src).unwrap(); // must not error
                                               // Second install saw a loaded job and tore it out before re-bootstrapping.
        assert!(ops.calls().contains(&Call::Bootout(LABEL.into())));
    }

    #[test]
    fn uninstall_then_residue_is_clean() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp)).unwrap();

        let report = uninstall(&layout, &ops);
        assert!(report.is_ok(), "uninstall errors: {:?}", report.errors);
        assert!(residue(&layout, &ops).unwrap().is_clean());
        // The empty shared helper dir we created was reclaimed.
        assert!(!layout.helper_dir().exists());
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
    fn uninstall_leaves_a_nonempty_shared_dir_alone() {
        let tp = TempPrefix::new();
        let layout = tp.layout();
        let ops = FakeSystemOps::new();
        install(&layout, &ops, &fake_navd(&tp)).unwrap();
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
        install(&layout, &ops, &fake_navd(&tp)).unwrap();
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
}
