//! The `SystemOps` seam: the privileged, un-fakeable operations install and
//! uninstall need (chown-to-root, adhoc re-sign, launchctl, tccutil).
//!
//! Everything a temp-dir prefix *can* fake — creating, copying, and removing
//! files — is done with plain `std::fs` against [`Layout`](crate::Layout)
//! paths, so the `--fake` verify run exercises the real filesystem logic. Only
//! the operations that genuinely differ off a real root install live here, so
//! CI can drive the orchestration through [`FakeSystemOps`] while the real run
//! uses [`RealSystemOps`].

use std::path::{Path, PathBuf};

use anyhow::Result;

/// Privileged operations that a temp-dir prefix cannot fake.
///
/// Implementors either perform them ([`RealSystemOps`], sudo) or record and
/// simulate them ([`FakeSystemOps`], CI). All are safe to call more than once.
pub trait SystemOps {
    /// Set `path`'s owner to `root:wheel`.
    fn chown_root(&self, path: &Path) -> Result<()>;
    /// Adhoc re-sign `path` with a stable identifier, so TCC has a consistent
    /// handle to scope `tccutil reset` to (§11.10/§10).
    fn codesign_adhoc(&self, path: &Path, identifier: &str) -> Result<()>;
    /// Bootstrap the LaunchDaemon at `plist` into the system domain.
    fn bootstrap(&self, plist: &Path) -> Result<()>;
    /// Tear the job `label` out of the system domain. Not-loaded is not an error.
    fn bootout(&self, label: &str) -> Result<()>;
    /// Clear any sticky `disable` override on `label` (survives `bootout`).
    fn enable(&self, label: &str) -> Result<()>;
    /// Whether `label` is currently a job in the system domain.
    fn is_loaded(&self, label: &str) -> Result<bool>;
    /// `label`'s record in launchd's disabled-services DB: `None` if absent,
    /// `Some(true)` if disabled, `Some(false)` if a benign enabled record
    /// lingers (§11.10).
    fn disable_record(&self, label: &str) -> Result<Option<bool>>;
    /// Whether `label` carries a persistent `disable` override.
    fn is_disabled(&self, label: &str) -> Result<bool> {
        Ok(self.disable_record(label)? == Some(true))
    }
    /// Best-effort scoped reset of a TCC grant. Attempting it is success —
    /// a missing grant is not an error (see the honest-residual note in §11.8).
    fn tccutil_reset(&self, service: &str, identifier: &str) -> Result<()>;
}

/// Parse `launchctl print-disabled system` output for `label`'s record.
///
/// The disabled DB has one line per label, either word form
/// (`"label" => disabled` / `"label" => enabled`) or boolean form
/// (`"label" => true` / `"label" => false`) depending on macOS version.
/// Matches `label` as a quoted token so e.g. `com.nav.navd.helper` can't
/// collide with a query for `com.nav.navd`.
fn parse_disable_record(text: &str, label: &str) -> Option<bool> {
    let needle = format!("\"{label}\"");
    for line in text.lines() {
        let Some((left, right)) = line.split_once("=>") else {
            continue;
        };
        if left.trim() != needle {
            continue;
        }
        return match right.trim().to_ascii_lowercase().as_str() {
            "true" | "disabled" => Some(true),
            "false" | "enabled" => Some(false),
            _ => None,
        };
    }
    None
}

/// The real macOS implementation. Requires root for the launchd/chown paths.
#[derive(Debug, Default)]
pub struct RealSystemOps;

impl RealSystemOps {
    fn launchctl(args: &[&str]) -> Result<std::process::Output> {
        Ok(std::process::Command::new("launchctl")
            .args(args)
            .output()?)
    }
}

impl SystemOps for RealSystemOps {
    fn chown_root(&self, path: &Path) -> Result<()> {
        // root:wheel == 0:0. `std::os::unix::fs::chown` is stable since 1.73.
        std::os::unix::fs::chown(path, Some(0), Some(0))?;
        Ok(())
    }

    fn codesign_adhoc(&self, path: &Path, identifier: &str) -> Result<()> {
        let out = std::process::Command::new("codesign")
            .args(["-f", "-s", "-", "-i", identifier])
            .arg(path)
            .output()?;
        anyhow::ensure!(
            out.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(())
    }

    fn bootstrap(&self, plist: &Path) -> Result<()> {
        let out = std::process::Command::new("launchctl")
            .args(["bootstrap", "system"])
            .arg(plist)
            .output()?;
        anyhow::ensure!(
            out.status.success(),
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(())
    }

    fn bootout(&self, label: &str) -> Result<()> {
        // A not-loaded service returns non-zero; that's the desired end state,
        // so bootout is idempotent and never treated as a failure.
        Self::launchctl(&["bootout", &format!("system/{label}")])?;
        Ok(())
    }

    fn enable(&self, label: &str) -> Result<()> {
        Self::launchctl(&["enable", &format!("system/{label}")])?;
        Ok(())
    }

    fn is_loaded(&self, label: &str) -> Result<bool> {
        Ok(Self::launchctl(&["print", &format!("system/{label}")])?
            .status
            .success())
    }

    fn disable_record(&self, label: &str) -> Result<Option<bool>> {
        let out = Self::launchctl(&["print-disabled", "system"])?;
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(parse_disable_record(&text, label))
    }

    fn tccutil_reset(&self, service: &str, identifier: &str) -> Result<()> {
        // Best-effort: a non-zero exit (e.g. no such grant) is not a failure —
        // only a failure to *run* tccutil is. This is the one artifact with no
        // guaranteed removal, reported by the residue check, not asserted clean.
        std::process::Command::new("tccutil")
            .args(["reset", service, identifier])
            .output()?;
        Ok(())
    }
}

/// A recorded [`SystemOps`] call, for asserting the orchestration issued the
/// right privileged operations in the `--fake` verify run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    ChownRoot(PathBuf),
    CodesignAdhoc { path: PathBuf, identifier: String },
    Bootstrap(PathBuf),
    Bootout(String),
    Enable(String),
    TccutilReset { service: String, identifier: String },
}

/// Records and simulates [`SystemOps`] without touching the system, so CI can
/// drive install/uninstall against a temp-dir prefix. Tracks the launchd
/// loaded/disabled state the orchestration branches on.
#[derive(Debug, Default)]
pub struct FakeSystemOps {
    calls: std::cell::RefCell<Vec<Call>>,
    loaded: std::cell::Cell<bool>,
    disable_record: std::cell::Cell<Option<bool>>,
}

impl FakeSystemOps {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from a state that already has the job loaded and disabled — for
    /// testing idempotent re-install and disable-override cleanup.
    pub fn preloaded() -> Self {
        let f = Self::new();
        f.loaded.set(true);
        f.disable_record.set(Some(true));
        f
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.borrow().clone()
    }

    fn record(&self, call: Call) {
        self.calls.borrow_mut().push(call);
    }
}

impl SystemOps for FakeSystemOps {
    fn chown_root(&self, path: &Path) -> Result<()> {
        self.record(Call::ChownRoot(path.to_path_buf()));
        Ok(())
    }

    fn codesign_adhoc(&self, path: &Path, identifier: &str) -> Result<()> {
        self.record(Call::CodesignAdhoc {
            path: path.to_path_buf(),
            identifier: identifier.to_string(),
        });
        Ok(())
    }

    fn bootstrap(&self, plist: &Path) -> Result<()> {
        self.record(Call::Bootstrap(plist.to_path_buf()));
        self.loaded.set(true);
        Ok(())
    }

    fn bootout(&self, label: &str) -> Result<()> {
        self.record(Call::Bootout(label.to_string()));
        self.loaded.set(false);
        Ok(())
    }

    fn enable(&self, label: &str) -> Result<()> {
        self.record(Call::Enable(label.to_string()));
        // A benign enabled record lingers, matching real launchd (§11.10).
        self.disable_record.set(Some(false));
        Ok(())
    }

    fn is_loaded(&self, _label: &str) -> Result<bool> {
        Ok(self.loaded.get())
    }

    fn disable_record(&self, _label: &str) -> Result<Option<bool>> {
        Ok(self.disable_record.get())
    }

    fn tccutil_reset(&self, service: &str, identifier: &str) -> Result<()> {
        self.record(Call::TccutilReset {
            service: service.to_string(),
            identifier: identifier.to_string(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_simulates_launchd_state() {
        let f = FakeSystemOps::new();
        assert!(!f.is_loaded("x").unwrap());
        f.bootstrap(Path::new("/p.plist")).unwrap();
        assert!(f.is_loaded("x").unwrap());
        f.bootout("x").unwrap();
        assert!(!f.is_loaded("x").unwrap());
    }

    #[test]
    fn fake_enable_clears_disable_override() {
        let f = FakeSystemOps::preloaded();
        assert!(f.is_disabled("x").unwrap());
        f.enable("x").unwrap();
        assert!(!f.is_disabled("x").unwrap());
    }

    #[test]
    fn fake_enable_leaves_a_benign_enabled_record() {
        let f = FakeSystemOps::preloaded();
        f.enable("x").unwrap();
        assert_eq!(f.disable_record("x").unwrap(), Some(false));
        assert!(!f.is_disabled("x").unwrap());
    }

    #[test]
    fn parse_disable_record_boolean_form() {
        assert_eq!(
            parse_disable_record("\"com.nav.navd\" => true", "com.nav.navd"),
            Some(true)
        );
        assert_eq!(
            parse_disable_record("\"com.nav.navd\" => false", "com.nav.navd"),
            Some(false)
        );
    }

    #[test]
    fn parse_disable_record_word_form() {
        assert_eq!(
            parse_disable_record("\"com.nav.navd\" => disabled", "com.nav.navd"),
            Some(true)
        );
        assert_eq!(
            parse_disable_record("\"com.nav.navd\" => enabled", "com.nav.navd"),
            Some(false)
        );
    }

    #[test]
    fn parse_disable_record_absent_label_is_none() {
        assert_eq!(
            parse_disable_record("\"com.other.thing\" => true", "com.nav.navd"),
            None
        );
    }

    #[test]
    fn parse_disable_record_does_not_collide_on_substring() {
        // Only a longer, related label is present — must not match the shorter query.
        let text = "\"com.nav.navd.helper\" => true";
        assert_eq!(parse_disable_record(text, "com.nav.navd"), None);
    }

    #[test]
    fn fake_records_calls_in_order() {
        let f = FakeSystemOps::new();
        f.chown_root(Path::new("/a")).unwrap();
        f.tccutil_reset("S", "id").unwrap();
        assert_eq!(
            f.calls(),
            vec![
                Call::ChownRoot(PathBuf::from("/a")),
                Call::TccutilReset {
                    service: "S".into(),
                    identifier: "id".into()
                },
            ]
        );
    }
}
