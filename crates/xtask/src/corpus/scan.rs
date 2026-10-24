//! Running navctl over planned chunks on a worker pool.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{bail, Context, Result};

use super::plan::{plan, Chunk, Plan};
use super::Tuning;

/// Default scan roots on macOS.
fn default_roots() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    vec![
        "/usr/bin".into(),
        "/Applications".into(),
        "/opt/homebrew/Cellar".into(),
        home.join(".cargo/bin"),
        home.join("Library/Application Support/Steam"),
    ]
}

/// Roots to scan: `tuning.roots`, else the macOS defaults.
pub fn resolve_roots(tuning: &Tuning) -> Result<Vec<PathBuf>> {
    if !tuning.roots.is_empty() {
        return tuning.roots.iter().map(|r| super::absolute(r)).collect();
    }
    if cfg!(target_os = "macos") {
        Ok(default_roots())
    } else {
        bail!("no ROOTS given and there are no default roots on this platform")
    }
}

/// Plans `tuning`'s roots, printing the planner's notes. Errors if nothing
/// is left to scan.
pub fn plan_roots(tuning: &Tuning) -> Result<Plan> {
    let planned = plan(&resolve_roots(tuning)?, tuning.split_at);
    for note in &planned.notes {
        println!("note: {note}");
    }
    if planned.chunks.is_empty() {
        bail!("nothing to scan: every root is missing or empty");
    }
    Ok(planned)
}

/// One navctl build and where its results go.
pub struct Target<'a> {
    pub navctl: &'a Path,
    pub out: &'a Path,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub files: usize,
    /// Chunks that exited outside 0–3 (including death by signal).
    pub failed: usize,
    pub with_stderr: usize,
}

struct Sink {
    out: BufWriter<File>,
    err: BufWriter<File>,
    err_path: PathBuf,
    summary: Summary,
}

/// Runs every chunk of `planned` with each target's navctl, back to back per
/// chunk so the builds see the same files. Appends each run's stdout to the
/// target's `out` and failure/stderr records to `<out>.err`.
pub fn run(targets: &[Target], planned: &Plan, jobs: Option<usize>) -> Result<Vec<Summary>> {
    let start = Instant::now();
    let chunks = &planned.chunks;
    let total = chunks.len();
    let jobs = match jobs {
        Some(0) => bail!("--jobs must be at least 1"),
        Some(n) => n,
        None => std::thread::available_parallelism().map_or(1, |n| n.get()),
    }
    .min(total.max(1));

    let mut sinks = Vec::new();
    let mut navctls = Vec::new();
    for t in targets {
        navctls.push(super::absolute(t.navctl)?);
        let out = super::absolute(t.out)?;
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let err_path = PathBuf::from(format!("{}.err", out.display()));
        sinks.push(Mutex::new(Sink {
            out: BufWriter::new(File::create(&out).with_context(|| out.display().to_string())?),
            err: BufWriter::new(
                File::create(&err_path).with_context(|| err_path.display().to_string())?,
            ),
            err_path,
            summary: Summary::default(),
        }));
    }
    println!(
        "{total} chunk(s) x {} build(s) on {jobs} worker(s)",
        targets.len()
    );

    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let failure: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    let step = (total / 20).max(1);
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(chunk) = chunks.get(i) else { break };
                if failure.lock().unwrap().is_some() {
                    break;
                }
                for (navctl, sink) in navctls.iter().zip(&sinks) {
                    if let Err(e) = run_chunk(navctl, chunk, sink) {
                        failure.lock().unwrap().get_or_insert(e);
                        return;
                    }
                }
                let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                if d % step == 0 || d == total {
                    println!("{d}/{total} chunks");
                }
            });
        }
    });
    if let Some(e) = failure.into_inner().unwrap() {
        return Err(e);
    }

    let mut summaries = Vec::new();
    for (t, sink) in targets.iter().zip(sinks) {
        let mut sink = sink.into_inner().unwrap();
        sink.out.flush()?;
        sink.err.flush()?;
        let s = sink.summary;
        println!(
            "{}: {} file(s); {} chunk(s) failed, {} with stderr (see {})",
            t.navctl.display(),
            s.files,
            s.failed,
            s.with_stderr,
            sink.err_path.display(),
        );
        summaries.push(s);
    }
    println!("elapsed {:.1?}", start.elapsed());
    Ok(summaries)
}

/// Runs navctl on one chunk and records its output. Errors only if navctl
/// can't be spawned or a sink can't be written.
fn run_chunk(navctl: &Path, chunk: &Chunk, sink: &Mutex<Sink>) -> Result<()> {
    let mut cmd = Command::new(navctl);
    cmd.arg("scan");
    if chunk.recursive {
        cmd.arg("--recursive");
    }
    cmd.arg("--json").arg(&chunk.path);
    let output = cmd
        .output()
        .with_context(|| format!("running {}", navctl.display()))?;
    let code = output.status.code();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let files = output
        .stdout
        .split(|&b| b == b'\n')
        .filter(|l| l.first() == Some(&b'{'))
        .count();

    let mut s = sink.lock().unwrap();
    s.out.write_all(&output.stdout)?;
    if !output.stdout.is_empty() && !output.stdout.ends_with(b"\n") {
        s.out.write_all(b"\n")?;
    }
    s.summary.files += files;
    // 0–3 are verdicts; 4, other codes and signals mean navctl itself failed.
    let failed = !matches!(code, Some(0..=3));
    let has_stderr = !stderr.trim().is_empty();
    if failed || has_stderr {
        s.summary.failed += usize::from(failed);
        s.summary.with_stderr += usize::from(has_stderr);
        let code = code.map_or_else(|| "signal".to_string(), |c| c.to_string());
        writeln!(
            s.err,
            "path: {}\nexit: {code}\nstderr: {}\n",
            chunk.path.display(),
            stderr.trim_end()
        )?;
    }
    Ok(())
}
