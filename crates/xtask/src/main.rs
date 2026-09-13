//! Dev runner for the install/uninstall/residue orchestration (§11.10). `verify
//! --fake` drives it against a temp prefix with `FakeSystemOps` (what CI runs);
//! `verify --real` drives the same calls against `/` with `RealSystemOps`
//! under sudo. Both modes exercise one code path so they can't drift apart.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};

use nav_service::{
    install, residue, uninstall, FakeSystemOps, Layout, RealSystemOps, CODESIGN_ID, LABEL,
};

#[derive(Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run install/uninstall/residue end-to-end and assert every step.
    Verify {
        /// Temp prefix + fake privileged ops (default; CI-safe).
        #[arg(long, conflicts_with = "real")]
        fake: bool,
        /// Real `/` prefix + real privileged ops. Requires root.
        #[arg(long, conflicts_with = "fake")]
        real: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify { real, .. } => {
            if real {
                verify_real()
            } else {
                verify_fake()
            }
        }
    }
}

fn verify_fake() -> Result<()> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tempdir =
        std::env::temp_dir().join(format!("nav-xtask-verify-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&tempdir).with_context(|| format!("creating {}", tempdir.display()))?;

    let result = run_verify_fake(&tempdir);
    if result.is_ok() {
        let _ = std::fs::remove_dir_all(&tempdir);
    }
    result
}

fn run_verify_fake(tempdir: &std::path::Path) -> Result<()> {
    let placeholder = tempdir.join("navd-placeholder");
    std::fs::write(&placeholder, b"navd")
        .with_context(|| format!("writing {}", placeholder.display()))?;

    let layout = Layout::under(tempdir);
    let ops = FakeSystemOps::new();

    println!("installing...");
    install(&layout, &ops, &placeholder)?;

    ensure!(layout.helper_binary().is_file(), "helper binary missing");
    ensure!(layout.plist_path().is_file(), "plist missing");
    ensure!(layout.config_dir().is_dir(), "config dir missing");
    ensure!(layout.state_dir().is_dir(), "state dir missing");
    ensure!(
        std::fs::read_to_string(layout.plist_path())? == layout.render_plist(),
        "plist contents don't match the golden render"
    );

    let calls = ops.calls();
    for expected in [
        nav_service::Call::Bootstrap(layout.plist_path()),
        nav_service::Call::ChownRoot(layout.helper_binary()),
        nav_service::Call::ChownRoot(layout.helper_dir()),
        nav_service::Call::ChownRoot(layout.config_dir()),
        nav_service::Call::ChownRoot(layout.state_dir()),
        nav_service::Call::CodesignAdhoc {
            path: layout.helper_binary(),
            identifier: CODESIGN_ID.into(),
        },
        nav_service::Call::Enable(LABEL.into()),
    ] {
        ensure!(
            calls.contains(&expected),
            "missing expected call: {expected:?}"
        );
    }
    println!("install: OK");

    // Re-install must be idempotent and tear out the now-loaded job first.
    install(&layout, &ops, &placeholder)?;
    ensure!(
        ops.calls()
            .contains(&nav_service::Call::Bootout(LABEL.into())),
        "re-install did not bootout the previously loaded job"
    );
    println!("idempotent re-install: OK");

    let report = uninstall(&layout, &ops);
    ensure!(report.is_ok(), "uninstall errors: {:?}", report.errors);
    println!("uninstall: OK");

    ensure!(
        residue(&layout, &ops)?.is_clean(),
        "residue after uninstall is not clean"
    );
    ensure!(
        !layout.helper_dir().exists(),
        "helper dir we created was not reclaimed"
    );
    println!("residue: OK");

    println!("verify (fake): OK");
    Ok(())
}

fn verify_real() -> Result<()> {
    // SAFETY: geteuid takes no arguments and never fails.
    let euid = unsafe { libc::geteuid() };
    ensure!(
        euid == 0,
        "verify --real must run as root (try: sudo cargo xtask verify --real)"
    );

    let exe = std::env::current_exe()?;
    let navd = exe
        .parent()
        .context("xtask binary has no parent dir")?
        .join("navd");
    if !navd.is_file() {
        bail!(
            "navd binary not found at {} — run `cargo build -p navd` first",
            navd.display()
        );
    }

    let layout = Layout::system();
    let ops = RealSystemOps;

    println!("installing...");
    install(&layout, &ops, &navd)?;
    println!("install: OK");

    let report = uninstall(&layout, &ops);
    for path in &report.removed {
        println!("removed: {}", path.display());
    }
    for err in &report.errors {
        println!("error: {err}");
    }
    ensure!(report.is_ok(), "uninstall errors: {:?}", report.errors);
    println!("uninstall: OK");

    let res = residue(&layout, &ops)?;
    ensure!(
        res.is_clean(),
        "residue after uninstall is not clean: {res:?}"
    );
    println!("note: the TCC/FDA grant reset is best-effort and excluded from residue (§11.8)");

    println!("verify (real): OK");
    Ok(())
}
