//! End-to-end coverage of the daemon lifecycle bare `navd` (no args) enters
//! — the exact invocation the installed LaunchDaemon plist runs (§11.10).

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn navd_bin() -> &'static str {
    env!("CARGO_BIN_EXE_navd")
}

/// Bare `navd` must route to the stay-alive daemon loop (not a clap usage
/// error) and then shut down cleanly on SIGTERM — the signal launchd's
/// `bootout` sends. Blocks on the daemon's startup line before sending the
/// signal: that line prints only after `install_signal_handlers()`
/// (`daemon.rs`), so reading it back guarantees the handler is already live,
/// closing the race that made an earlier version of this test flaky.
#[test]
fn no_args_daemon_starts_and_exits_clean_on_sigterm() {
    let mut child = Command::new(navd_bin())
        .stdout(Stdio::piped())
        .spawn()
        .expect("navd with no args spawns");

    // Keep draining stdout for the child's whole life, not just until the
    // startup line: dropping the read end early closes the pipe, and the
    // child's later shutdown `println!` then panics on the resulting
    // broken-pipe write error instead of exiting clean.
    let stdout = child.stdout.take().expect("stdout was piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut sent = false;
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break, // EOF or read error: child closed stdout.
                Ok(_) => {
                    if !sent && line.contains("navd starting") {
                        let _ = tx.send(line.clone());
                        sent = true;
                    }
                }
            }
        }
    });
    let startup_line = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("navd should print its startup line");
    assert!(
        startup_line.contains("navd starting"),
        "unexpected startup output: {startup_line}"
    );

    // SAFETY: `kill` with a valid pid and SIGTERM has no preconditions
    // beyond the pid being ours, which it is (`child.id()`).
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "navd did not exit within 10s of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    assert!(status.success(), "SIGTERM after startup should exit clean");
}
