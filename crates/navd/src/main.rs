//! `navd` — NAV's privileged daemon.
//!
//! Phase 0b A1 scope: a minimal stay-alive skeleton, so the LaunchDaemon that
//! `navctl service install` bootstraps has a real target to keep running
//! (§11.10). It links `nav-core` but runs no event sources, socket, or
//! scanning pipeline yet — those are A2 onward (§12); building them here would
//! be ahead of phase.
//!
//! Lifecycle: log a startup line, block until SIGTERM/SIGINT (launchd
//! `bootout` sends SIGTERM), then log a shutdown line and exit 0 so a teardown
//! reads as a clean stop rather than a crash.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Poll interval of the stay-alive loop — the worst-case latency between a
/// termination signal and a clean exit. launchd allows far longer before it
/// escalates `bootout` to SIGKILL, so a second is comfortably within budget.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Set by the signal handler, polled by the run loop to exit cleanly.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Async-signal-safe: an atomic store is the only thing it does.
extern "C" fn on_terminate(_signum: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    let handler = on_terminate as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: the handler only performs an atomic store, which is
    // async-signal-safe; installing it has no other precondition.
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

fn main() {
    install_signal_handlers();

    // stdout/stderr are the plist's log paths (§11.10) — this is how the
    // `--real` verify run confirms the daemon actually came up under launchd.
    println!(
        "navd starting (pid {}, engine {}): stay-alive skeleton, no event sources yet (§12).",
        std::process::id(),
        nav_core::ENGINE_VERSION
    );

    while !SHUTDOWN.load(Ordering::SeqCst) {
        thread::sleep(POLL_INTERVAL);
    }

    println!("navd shutting down on signal.");
}
