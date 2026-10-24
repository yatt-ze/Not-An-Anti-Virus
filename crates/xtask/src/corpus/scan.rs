//! Running navctl over planned chunks on a worker pool.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{bail, Context, Result};

use super::plan::{plan, Chunk};
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

#[derive(Debug, Default)]
pub struct Summary {
    pub files: usize,
    pub chunks: usize,
    pub exit4: usize,
    pub with_stderr: usize,
}

struct Sinks {
    out: BufWriter<File>,
    err: BufWriter<File>,
    done: usize,
    summary: Summary,
}

/// Scans `tuning`'s roots with `navctl`, appending each chunk's stdout to
/// `out` and error records to `<out>.err`. Chunk output is written whole, so
/// lines never interleave.
pub fn run(navctl: &Path, out: &Path, tuning: &Tuning) -> Result<Summary> {
    let start = Instant::now();
    let navctl = super::absolute(navctl)?;
    let out = super::absolute(out)?;
    let roots = resolve_roots(tuning)?;
    let planned = plan(&roots, tuning.split_at);
    for note in &planned.notes {
        println!("note: {note}");
    }
    let chunks = planned.chunks;
    let total = chunks.len();
    let jobs = match tuning.jobs {
        Some(0) => bail!("--jobs must be at least 1"),
        Some(n) => n,
        None => std::thread::available_parallelism().map_or(1, |n| n.get()),
    }
    .min(total.max(1));

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let err_path = PathBuf::from(format!("{}.err", out.display()));
    let sinks = Mutex::new(Sinks {
        out: BufWriter::new(File::create(&out).with_context(|| out.display().to_string())?),
        err: BufWriter::new(
            File::create(&err_path).with_context(|| err_path.display().to_string())?,
        ),
        done: 0,
        summary: Summary {
            chunks: total,
            ..Default::default()
        },
    });
    println!("{total} chunk(s) on {jobs} worker(s)");

    let next = AtomicUsize::new(0);
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
                if let Err(e) = run_chunk(&navctl, chunk, &sinks, total, step) {
                    failure.lock().unwrap().get_or_insert(e);
                    break;
                }
            });
        }
    });
    if let Some(e) = failure.into_inner().unwrap() {
        return Err(e);
    }

    let mut sinks = sinks.into_inner().unwrap();
    sinks.out.flush()?;
    sinks.err.flush()?;
    let s = sinks.summary;
    println!(
        "scanned {} file(s) in {} chunk(s); {} chunk(s) exited 4, {} with stderr (see {}); {:.1?}",
        s.files,
        s.chunks,
        s.exit4,
        s.with_stderr,
        err_path.display(),
        start.elapsed()
    );
    Ok(s)
}

/// Runs navctl on one chunk and records its output. Errors only if navctl
/// can't be spawned or a sink can't be written.
fn run_chunk(
    navctl: &Path,
    chunk: &Chunk,
    sinks: &Mutex<Sinks>,
    total: usize,
    step: usize,
) -> Result<()> {
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

    let mut s = sinks.lock().unwrap();
    s.out.write_all(&output.stdout)?;
    if !output.stdout.is_empty() && !output.stdout.ends_with(b"\n") {
        s.out.write_all(b"\n")?;
    }
    s.summary.files += files;
    let has_stderr = !stderr.trim().is_empty();
    if code == Some(4) || has_stderr {
        s.summary.exit4 += usize::from(code == Some(4));
        s.summary.with_stderr += usize::from(has_stderr);
        let code = code.map_or_else(|| "signal".to_string(), |c| c.to_string());
        writeln!(
            s.err,
            "path: {}\nexit: {code}\nstderr: {}\n",
            chunk.path.display(),
            stderr.trim_end()
        )?;
    }
    s.done += 1;
    if s.done % step == 0 || s.done == total {
        println!("{}/{total} chunks", s.done);
    }
    Ok(())
}
