//! Bounded child-process capture: a timeout and a per-stream output cap, so
//! a hung or chatty external tool cannot stall or exhaust a scan (§11.8).

use std::ffi::OsStr;
use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Bytes kept from each of a child's stdout and stderr.
pub const MAX_CAPTURE: usize = 1024 * 1024;
/// How long output is collected once the child exits; a helper holding the
/// pipe open must not hang the caller.
pub const PIPE_GRACE: Duration = Duration::from_secs(2);

/// Captured result of one child process.
pub struct Captured {
    /// `None` if the child was killed at the timeout or on cancel.
    pub status: Option<ExitStatus>,
    pub stdout: Vec<u8>,
    /// Output was truncated at [`MAX_CAPTURE`] or not received in time.
    pub stdout_cut: bool,
    pub stderr: Vec<u8>,
    /// As `stdout_cut`, for stderr.
    pub stderr_cut: bool,
    /// Killed at the timeout or on cancel.
    pub timed_out: bool,
}

impl Captured {
    /// Exited with status 0 before the timeout.
    pub fn success(&self) -> bool {
        !self.timed_out && self.status.is_some_and(|s| s.success())
    }
}

/// Runs `program` with empty stdin, keeping up to [`MAX_CAPTURE`] of each
/// output stream (drained concurrently so the child never blocks), killed
/// at `timeout` or once `cancel` becomes non-zero.
pub fn run_capped(
    program: impl AsRef<OsStr>,
    args: &[&OsStr],
    timeout: Duration,
    cancel: Option<&AtomicI32>,
) -> io::Result<Captured> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = wait_until(&mut child, deadline, cancel)?;
    // Not received in time counts as cut, so the output is not trusted. One
    // grace window covers both pipes.
    let grace_end = Instant::now() + PIPE_GRACE;
    let left = || grace_end.saturating_duration_since(Instant::now());
    let (stdout, stdout_cut) = stdout.recv_timeout(left()).unwrap_or((Vec::new(), true));
    let (stderr, stderr_cut) = stderr.recv_timeout(left()).unwrap_or((Vec::new(), true));
    Ok(Captured {
        status,
        stdout,
        stdout_cut,
        stderr,
        stderr_cut,
        timed_out,
    })
}

fn wait_until(
    child: &mut Child,
    deadline: Instant,
    cancel: Option<&AtomicI32>,
) -> io::Result<(Option<ExitStatus>, bool)> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok((Some(status), false)),
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        }
        let cancelled = cancel.is_some_and(|c| c.load(Ordering::SeqCst) != 0);
        if cancelled || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok((None, true));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Reads `pipe` to EOF on a thread, keeping the first [`MAX_CAPTURE`] bytes;
/// the flag is true if more was discarded.
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut cut = false;
        let Some(mut pipe) = pipe else {
            let _ = tx.send((kept, cut));
            return;
        };
        let mut buf = [0u8; 8192];
        loop {
            match pipe.read(&mut buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = MAX_CAPTURE - kept.len();
                    kept.extend_from_slice(&buf[..n.min(room)]);
                    cut |= n > room;
                }
            }
        }
        let _ = tx.send((kept, cut));
    });
    rx
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn os(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    #[test]
    fn capture_is_capped_and_drained() {
        let out = run_capped(
            "/bin/sh",
            &[os("-c"), os("head -c 3000000 /dev/zero; echo err >&2")],
            Duration::from_secs(30),
            None,
        )
        .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.len(), MAX_CAPTURE);
        assert!(out.stdout_cut);
        assert_eq!(out.stderr, b"err\n");
        assert!(!out.stderr_cut);
    }

    #[test]
    fn a_slow_child_is_killed_at_the_timeout() {
        let start = Instant::now();
        let out = run_capped("/bin/sleep", &[os("30")], Duration::from_millis(200), None).unwrap();
        assert!(out.timed_out);
        assert!(!out.success());
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_cancel_flag_kills_the_child() {
        let flag = AtomicI32::new(2);
        let out = run_capped(
            "/bin/sleep",
            &[os("30")],
            Duration::from_secs(30),
            Some(&flag),
        )
        .unwrap();
        assert!(out.timed_out);
    }

    #[test]
    fn a_pipe_held_open_counts_as_cut_on_stderr() {
        let out = run_capped(
            "/bin/sh",
            &[os("-c"), os("(sleep 5 >&2 &) ; exit 0")],
            Duration::from_secs(30),
            None,
        )
        .unwrap();
        assert!(out.stderr_cut);
    }
}
