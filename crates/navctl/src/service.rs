//! `navctl service {install,uninstall,status}` — navd's privileged system
//! lifecycle (§11.10). Install and uninstall drive `nav-service`'s
//! one-manifest orchestration against the real system layout and need root;
//! status is read-only but reports launchd state only when run as root.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use nav_service::{install, uninstall, Layout, RealSystemOps, SystemOps, LABEL};

use crate::exit;

/// True when running with effective uid 0.
fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments, has no preconditions, and never fails.
    unsafe { libc::geteuid() == 0 }
}

/// The `navd` binary shipped next to the running `navctl` — the source install
/// copies to the root-owned helper path (§11.10: never the Cellar/target path).
fn navd_source() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolving navctl's own path")?;
    let dir = exe.parent().context("navctl has no parent directory")?;
    Ok(dir.join("navd"))
}

pub fn run_install() -> ExitCode {
    if !is_root() {
        eprintln!("navctl: `service install` must run as root (try: sudo navctl service install)");
        return exit::code(exit::OPERATIONAL_ERROR);
    }
    let navd_src = match navd_source() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("navctl: {e:#}");
            return exit::code(exit::OPERATIONAL_ERROR);
        }
    };
    match install(&Layout::system(), &RealSystemOps, &navd_src) {
        Ok(()) => {
            println!("navd installed and bootstrapped ({LABEL}).");
            exit::code(exit::CLEAN)
        }
        Err(e) => {
            eprintln!("navctl: install failed: {e:#}");
            exit::code(exit::OPERATIONAL_ERROR)
        }
    }
}

pub fn run_uninstall() -> ExitCode {
    if !is_root() {
        eprintln!(
            "navctl: `service uninstall` must run as root (try: sudo navctl service uninstall)"
        );
        return exit::code(exit::OPERATIONAL_ERROR);
    }
    let report = uninstall(&Layout::system(), &RealSystemOps);
    for path in &report.removed {
        println!("removed {}", path.display());
    }
    // The FDA/TCC grant reset is best-effort and can't be asserted clean — say
    // so rather than implying a guarantee (§11.8).
    println!("Full Disk Access grant reset (best-effort); verify in System Settings if needed.");

    if report.is_ok() {
        println!("navd uninstalled.");
        exit::code(exit::CLEAN)
    } else {
        for err in &report.errors {
            eprintln!("navctl: uninstall: {err}");
        }
        exit::code(exit::OPERATIONAL_ERROR)
    }
}

pub fn run_status() -> ExitCode {
    let layout = Layout::system();
    for (label, path) in [
        ("navd binary", layout.helper_binary()),
        ("plist", layout.plist_path()),
        ("config dir", layout.config_dir()),
        ("state dir", layout.state_dir()),
    ] {
        let state = if path.exists() { "present" } else { "absent" };
        println!("{label:<12} {state}");
    }

    // launchctl's system domain is only reliably readable as root; without it,
    // report the job state as unknown rather than guessing "not loaded".
    if is_root() {
        let ops = RealSystemOps;
        match ops.is_loaded(LABEL) {
            Ok(true) => println!("{:<12} loaded", "launchd job"),
            Ok(false) => println!("{:<12} not loaded", "launchd job"),
            Err(e) => println!("{:<12} unknown ({e:#})", "launchd job"),
        }
        if matches!(ops.is_disabled(LABEL), Ok(true)) {
            println!("{:<12} disable override present", "launchd");
        }
    } else {
        println!(
            "{:<12} unknown (run as root to query launchd)",
            "launchd job"
        );
    }
    exit::code(exit::CLEAN)
}
