//! Privileged-install layout for `navd` (§11.10).
//!
//! This crate is the *pure* half of Phase 0b A1: it names every artifact a
//! `navctl service install` creates, renders the LaunchDaemon plist, and
//! exposes it all as one [`Manifest`] so install, uninstall, and the residue
//! check consume a single enumeration and can't drift apart. The side-effecting
//! half (chown, codesign, launchctl, tccutil) lands in a later commit behind a
//! `SystemOps` seam; nothing here touches the system.
//!
//! Paths are derived from a [`Layout`] prefix: `/` for a real install, a
//! temp dir for the `--fake` verify run CI uses. The plist *contents*, however,
//! always name the canonical system paths — a real launchd never sees the
//! prefix, and pinning them keeps the golden file stable.

use std::path::{Path, PathBuf};

pub mod ops;
pub mod orchestrate;

pub use ops::{Call, FakeSystemOps, RealSystemOps, SystemOps};
pub use orchestrate::{install, residue, uninstall, ResidueReport, UninstallReport};

/// launchd job label and system-domain service name.
pub const LABEL: &str = "com.nav.navd";
/// Stable adhoc signing identity applied to the copied binary, so TCC has a
/// consistent handle to scope `tccutil reset` to (design decision, §11.10/§10).
pub const CODESIGN_ID: &str = "com.nav.navd";
/// TCC service whose grant covers `navd`'s reads; reset is scoped to
/// [`CODESIGN_ID`] so no other app's Full Disk Access is touched.
pub const TCC_SERVICE: &str = "SystemPolicyAllFiles";

// Prefix-relative artifact paths. Joined onto the [`Layout`] prefix for
// filesystem ops; prefixed with `/` for the plist's canonical contents.
const HELPER_DIR_REL: &str = "Library/PrivilegedHelperTools";
const HELPER_BIN_REL: &str = "Library/PrivilegedHelperTools/navd";
const PLIST_REL: &str = "Library/LaunchDaemons/com.nav.navd.plist";
const CONFIG_DIR_REL: &str = "etc/navd";
const STATE_DIR_REL: &str = "private/var/db/navd";
const STDOUT_LOG_REL: &str = "private/var/db/navd/navd.out.log";
const STDERR_LOG_REL: &str = "private/var/db/navd/navd.err.log";

fn canonical(rel: &str) -> String {
    format!("/{rel}")
}

/// Where NAV's privileged artifacts live, rooted at a prefix.
///
/// `Layout::system()` roots at `/` (real install); `Layout::under(dir)` roots
/// at a temp dir for the `--fake` verify run. Path accessors join the prefix;
/// [`render_plist`](Layout::render_plist) ignores it (see module docs).
#[derive(Debug, Clone)]
pub struct Layout {
    prefix: PathBuf,
}

impl Layout {
    /// Real-install layout rooted at `/`.
    pub fn system() -> Self {
        Self {
            prefix: PathBuf::from("/"),
        }
    }

    /// Layout rooted at an arbitrary prefix (the `--fake` verify run's temp dir).
    pub fn under(prefix: impl Into<PathBuf>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    pub fn prefix(&self) -> &Path {
        &self.prefix
    }

    /// The shared Apple helper dir. Created only if absent, and reclaimed on
    /// uninstall only if we created it *and* it is empty (§11.10).
    pub fn helper_dir(&self) -> PathBuf {
        self.prefix.join(HELPER_DIR_REL)
    }

    /// The root-owned copy of `navd` the plist points at (never the Cellar path).
    pub fn helper_binary(&self) -> PathBuf {
        self.prefix.join(HELPER_BIN_REL)
    }

    pub fn plist_path(&self) -> PathBuf {
        self.prefix.join(PLIST_REL)
    }

    pub fn config_dir(&self) -> PathBuf {
        self.prefix.join(CONFIG_DIR_REL)
    }

    pub fn state_dir(&self) -> PathBuf {
        self.prefix.join(STATE_DIR_REL)
    }

    /// Full inventory of what install creates and uninstall must remove.
    /// Ordered for teardown: leaf files before the shared dir that holds them.
    pub fn manifest(&self) -> Manifest {
        Manifest {
            fs: vec![
                FsArtifact::new(self.plist_path(), FsKind::File),
                FsArtifact::new(self.helper_binary(), FsKind::File),
                FsArtifact::new(self.config_dir(), FsKind::Dir),
                FsArtifact::new(self.state_dir(), FsKind::Dir),
                // Reclaimed last, and only if we created it and it's now empty.
                FsArtifact::new(self.helper_dir(), FsKind::SharedDir),
            ],
            system: vec![
                SystemArtifact::LaunchdJob {
                    label: LABEL.to_string(),
                },
                SystemArtifact::DisableOverride {
                    label: LABEL.to_string(),
                },
                SystemArtifact::TccGrant {
                    service: TCC_SERVICE.to_string(),
                    identifier: CODESIGN_ID.to_string(),
                },
            ],
        }
    }

    /// The LaunchDaemon plist, naming the canonical system paths regardless of
    /// prefix (a real launchd never sees the prefix; see module docs).
    pub fn render_plist(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \t<key>Label</key>\n\
             \t<string>{label}</string>\n\
             \t<key>ProgramArguments</key>\n\
             \t<array>\n\
             \t\t<string>{program}</string>\n\
             \t</array>\n\
             \t<key>RunAtLoad</key>\n\
             \t<true/>\n\
             \t<key>KeepAlive</key>\n\
             \t<true/>\n\
             \t<key>UserName</key>\n\
             \t<string>root</string>\n\
             \t<key>StandardOutPath</key>\n\
             \t<string>{stdout}</string>\n\
             \t<key>StandardErrorPath</key>\n\
             \t<string>{stderr}</string>\n\
             </dict>\n\
             </plist>\n",
            label = LABEL,
            program = canonical(HELPER_BIN_REL),
            stdout = canonical(STDOUT_LOG_REL),
            stderr = canonical(STDERR_LOG_REL),
        )
    }
}

/// How a filesystem artifact is removed on uninstall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    File,
    /// Remove recursively.
    Dir,
    /// A shared Apple dir: created only if absent, reclaimed only if we created
    /// it and it is empty — never delete a dir another installer populated.
    SharedDir,
}

/// A filesystem path install creates and the residue check asserts absent.
#[derive(Debug, Clone)]
pub struct FsArtifact {
    pub path: PathBuf,
    pub kind: FsKind,
}

impl FsArtifact {
    fn new(path: PathBuf, kind: FsKind) -> Self {
        Self { path, kind }
    }
}

/// Non-filesystem state install registers and uninstall must clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemArtifact {
    /// A launchd job in the system domain (removed with `bootout`).
    LaunchdJob { label: String },
    /// A sticky launchd `disable` override that survives `bootout`; cleared with
    /// `enable` before teardown so no ghost override is left behind.
    DisableOverride { label: String },
    /// A TCC/FDA grant. Best-effort scoped reset only — the one artifact with no
    /// guaranteed programmatic removal, reported rather than claimed clean (§11.8).
    TccGrant { service: String, identifier: String },
}

/// The complete artifact inventory: filesystem plus system state.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub fs: Vec<FsArtifact>,
    pub system: Vec<SystemArtifact>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join_the_prefix() {
        let l = Layout::under("/tmp/navtest");
        assert_eq!(
            l.helper_binary(),
            PathBuf::from("/tmp/navtest/Library/PrivilegedHelperTools/navd")
        );
        assert_eq!(
            l.plist_path(),
            PathBuf::from("/tmp/navtest/Library/LaunchDaemons/com.nav.navd.plist")
        );
        assert_eq!(l.config_dir(), PathBuf::from("/tmp/navtest/etc/navd"));
        assert_eq!(
            l.state_dir(),
            PathBuf::from("/tmp/navtest/private/var/db/navd")
        );
    }

    #[test]
    fn system_layout_roots_at_slash() {
        let l = Layout::system();
        assert_eq!(
            l.helper_binary(),
            PathBuf::from("/Library/PrivilegedHelperTools/navd")
        );
    }

    #[test]
    fn manifest_covers_every_created_path() {
        let l = Layout::under("/tmp/navtest");
        let m = l.manifest();
        for p in [
            l.plist_path(),
            l.helper_binary(),
            l.config_dir(),
            l.state_dir(),
            l.helper_dir(),
        ] {
            assert!(
                m.fs.iter().any(|a| a.path == p),
                "manifest is missing {p:?}"
            );
        }
        assert!(m.fs.iter().any(|a| a.kind == FsKind::SharedDir));
    }

    #[test]
    fn manifest_tracks_launchd_disable_override_and_tcc() {
        let m = Layout::system().manifest();
        assert!(m
            .system
            .iter()
            .any(|a| matches!(a, SystemArtifact::LaunchdJob { .. })));
        assert!(m
            .system
            .iter()
            .any(|a| matches!(a, SystemArtifact::DisableOverride { .. })));
        assert!(m
            .system
            .iter()
            .any(|a| matches!(a, SystemArtifact::TccGrant { .. })));
    }

    #[test]
    fn plist_is_prefix_independent() {
        assert_eq!(
            Layout::system().render_plist(),
            Layout::under("/tmp/navtest").render_plist(),
            "plist contents must name canonical paths, not the prefix"
        );
    }

    #[test]
    fn plist_matches_golden() {
        assert_eq!(
            Layout::system().render_plist(),
            include_str!("../tests/golden/com.nav.navd.plist"),
        );
    }
}
