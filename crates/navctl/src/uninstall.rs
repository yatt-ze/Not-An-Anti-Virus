//! `navctl uninstall` (§8, §11.5): the `navd` service, then a NAV-managed CLI,
//! its PATH line and its install receipt (§13).
//!
//! Debug builds read three test-only overrides: `NAV_TEST_ROOT` (act as
//! root), `NAV_TEST_SUDO_HOME` (the home `SUDO_UID` resolves to) and
//! `NAV_TEST_SERVICE_ROOT` (a fake service layout and no launchd).

use std::fs;
use std::io::{IsTerminal, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use nav_service::{
    on_disk, residue, uninstall, FakeSystemOps, Layout, RealSystemOps, SystemOps, LABEL,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::exit;

/// Contract with `install.sh` (§13): matched exactly.
const PATH_MARKER: &str = "# Added by the NAV installer; navctl uninstall removes it";
const RECEIPT_REL: &str = ".local/share/nav/install-receipt.json";
const RECEIPT_MAX: u64 = 64 * 1024;

#[derive(Deserialize)]
struct Receipt {
    schema: u32,
    binary_path: String,
    binary_sha256: String,
    path_edit: Option<String>,
}

/// A failure: one `error:` line, optional detail lines, then the next step.
struct Failure {
    msg: String,
    detail: Vec<String>,
    next: String,
    cmd: Option<String>,
}

impl Failure {
    fn new(msg: impl Into<String>, next: impl Into<String>) -> Self {
        Failure {
            msg: msg.into(),
            detail: Vec::new(),
            next: next.into(),
            cmd: None,
        }
    }

    fn cmd(mut self, cmd: String) -> Self {
        self.cmd = Some(cmd);
        self
    }
}

/// `s` with control characters replaced, for text from paths and I/O errors.
fn san(s: &str) -> String {
    nav_core::terminal_safe(s).into_owned()
}

/// Output styling: colour per stream, only on a terminal with `NO_COLOR` unset.
struct Ui {
    out_tty: bool,
    out_color: bool,
    err_color: bool,
}

impl Ui {
    fn detect() -> Ui {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        let out_tty = std::io::stdout().is_terminal();
        Ui {
            out_tty,
            out_color: out_tty && !no_color,
            err_color: std::io::stderr().is_terminal() && !no_color,
        }
    }

    fn paint(on: bool, code: &str, s: &str) -> String {
        if on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn out(&self, line: &str) {
        nav_core::raw_println!("{line}");
    }

    fn head(&self, s: &str) {
        self.out(&Self::paint(self.out_color, "1", s));
    }

    fn step(&self, s: &str) {
        let tick = if self.out_tty { "✓" } else { "-" };
        self.out(&format!(
            "  {} {s}",
            Self::paint(self.out_color, "32", tick)
        ));
    }

    fn note(&self, s: &str) {
        let dot = if self.out_tty { "·" } else { "-" };
        self.out(&format!("  {} {s}", Self::paint(self.out_color, "33", dot)));
    }

    fn detail(&self, s: &str) {
        self.out(&format!("    {}", Self::paint(self.out_color, "2", s)));
    }

    /// A command to copy, highlighted for stdout.
    fn cmd(&self, s: &str) -> String {
        Self::paint(self.out_color, "36", &san(s))
    }

    fn error(&self, f: &Failure) {
        let mut text = format!(
            "{} {}\n",
            Self::paint(self.err_color, "1;31", "error:"),
            f.msg
        );
        for d in &f.detail {
            text.push_str(&format!("  {d}\n"));
        }
        text.push_str(&f.next);
        if let Some(c) = &f.cmd {
            text.push(' ');
            text.push_str(&Self::paint(self.err_color, "36", &san(c)));
        }
        text.push('\n');
        nav_core::presentation::emit(true, &text);
    }
}

fn is_root() -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("NAV_TEST_ROOT").is_some() {
        return true;
    }
    crate::service::is_root()
}

/// Who is being uninstalled and where their files and the service live.
struct Env {
    root: bool,
    uid: Option<u32>,
    gid: Option<u32>,
    home: PathBuf,
    home_canon: PathBuf,
    layout: Layout,
    fake_service: bool,
}

impl Env {
    fn ops(&self) -> Box<dyn SystemOps> {
        if self.fake_service {
            Box::new(FakeSystemOps::new())
        } else {
            Box::new(RealSystemOps)
        }
    }

    fn receipt_path(&self) -> PathBuf {
        self.home.join(RECEIPT_REL)
    }

    /// `p` with the home directory shown as `~`, safe to print.
    fn show(&self, p: &Path) -> String {
        for h in [&self.home, &self.home_canon] {
            if let Ok(rest) = p.strip_prefix(h) {
                return san(&format!("~/{}", rest.display()));
            }
        }
        san(&p.display().to_string())
    }

    /// `p` as a shell word: `~/…` or bare when plain, else single-quoted.
    fn shell_arg(&self, p: &Path) -> String {
        for h in [&self.home, &self.home_canon] {
            if let Ok(rest) = p.strip_prefix(h) {
                let t = format!("~/{}", rest.display());
                if plain_word(&t) {
                    return t;
                }
            }
        }
        shell_word(&p.display().to_string())
    }

    /// `p` is inside the user's home, with symlinks resolved.
    fn within_home(&self, p: &Path) -> bool {
        fs::canonicalize(p).is_ok_and(|c| c.starts_with(&self.home_canon))
    }

    /// Under root, `meta` must belong to the invoking user.
    fn owned(&self, meta: &fs::Metadata) -> bool {
        !self.root || Some(meta.uid()) == self.uid
    }
}

/// The user behind `sudo` as (uid, gid, home): `SUDO_UID` resolved through
/// the password database.
fn sudo_user() -> Result<(u32, u32, PathBuf), String> {
    let uid: u32 = std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|u| *u != 0)
        .ok_or("SUDO_UID is missing or invalid, so NAV can't tell whose files to remove")?;
    #[cfg(debug_assertions)]
    let over = std::env::var_os("NAV_TEST_SUDO_HOME").map(PathBuf::from);
    #[cfg(not(debug_assertions))]
    let over: Option<PathBuf> = None;
    let (gid, dir) = match over {
        // SAFETY: getgid takes no arguments and never fails.
        Some(d) => (unsafe { libc::getgid() }, d),
        None => {
            // SAFETY: getpwuid returns null or a pointer into static
            // storage; read before any other passwd call, one thread.
            let pw = unsafe { libc::getpwuid(uid) };
            if pw.is_null() {
                return Err(format!("SUDO_UID {uid} is not a known user"));
            }
            // SAFETY: pw is non-null; pw_dir is a NUL-terminated string.
            let (gid, d) = unsafe { ((*pw).pw_gid, std::ffi::CStr::from_ptr((*pw).pw_dir)) };
            (
                gid,
                PathBuf::from(std::ffi::OsStr::from_bytes(d.to_bytes())),
            )
        }
    };
    if !dir.is_absolute() {
        return Err(format!("SUDO_UID {uid} has no usable home directory"));
    }
    Ok((uid, gid, dir))
}

/// Under real root, permanently becomes the sudo user, so the home-directory
/// steps can't be redirected (swapped symlinks) to anything that user
/// couldn't already change. A no-op otherwise.
fn drop_to_user(env: &Env, exe: &Path) -> Result<(), Failure> {
    let (Some(uid), Some(gid)) = (env.uid, env.gid) else {
        return Ok(());
    };
    if !crate::service::is_root() {
        return Ok(());
    }
    // SAFETY: plain credential syscalls on a one-element array; order is
    // groups, gid, then uid, since setuid gives up the right to the others.
    let ok = unsafe {
        libc::setgroups(1, &gid) == 0
            && libc::setgid(gid) == 0
            && libc::setuid(uid) == 0
            && libc::geteuid() == uid
    };
    if ok {
        return Ok(());
    }
    Err(Failure::new(
        format!(
            "could not switch to your user: {}",
            std::io::Error::last_os_error()
        ),
        "Your files were left in place. Finish without sudo:",
    )
    .cmd(format!("{} uninstall", env.shell_arg(exe))))
}

fn resolve_env(exe: &Path) -> Result<Env, Failure> {
    let root = is_root();
    let (uid, gid, home) = if root {
        match sudo_user() {
            Ok((u, g, h)) => (Some(u), Some(g), h),
            Err(m) => {
                return Err(
                    Failure::new(m, "Run it through sudo from your own account:").cmd(format!(
                        "sudo {} uninstall",
                        shell_word(&exe.display().to_string())
                    )),
                )
            }
        }
    } else {
        match std::env::var_os("HOME").map(PathBuf::from) {
            Some(h) if h.is_absolute() => (None, None, h),
            _ => {
                return Err(Failure::new(
                    "HOME is not set to an absolute path",
                    "Set HOME to your home directory and rerun.",
                ))
            }
        }
    };
    let home_canon = fs::canonicalize(&home).unwrap_or_else(|_| home.clone());

    #[cfg(debug_assertions)]
    let fake = std::env::var_os("NAV_TEST_SERVICE_ROOT").map(PathBuf::from);
    #[cfg(not(debug_assertions))]
    let fake: Option<PathBuf> = None;
    let (layout, fake_service) = match fake {
        Some(p) => (Layout::under(p), true),
        None => (Layout::system(), false),
    };
    Ok(Env {
        root,
        uid,
        gid,
        home,
        home_canon,
        layout,
        fake_service,
    })
}

/// True if `s` needs no quoting as a shell word (a leading `~` expands).
fn plain_word(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+@:,=~".contains(c))
}

/// `s` as one shell word, single-quoted unless plain.
fn shell_word(s: &str) -> String {
    if plain_word(s) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

enum ReceiptState {
    Missing,
    Unreadable(String),
    Found(Receipt),
}

fn load_receipt(env: &Env) -> ReceiptState {
    let path = env.receipt_path();
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ReceiptState::Missing,
        Err(e) => return ReceiptState::Unreadable(e.to_string()),
    };
    if !meta.file_type().is_file() {
        return ReceiptState::Unreadable("not a regular file".into());
    }
    if meta.len() > RECEIPT_MAX {
        return ReceiptState::Unreadable("too large".into());
    }
    if !env.owned(&meta) {
        return ReceiptState::Unreadable("not owned by you".into());
    }
    if !env.within_home(path.parent().unwrap_or(&path)) {
        return ReceiptState::Unreadable("outside your home directory".into());
    }
    match fs::read(&path) {
        Ok(b) => match serde_json::from_slice::<Receipt>(&b) {
            Ok(r) if r.schema == 1 && Path::new(&r.binary_path).is_absolute() => {
                ReceiptState::Found(r)
            }
            Ok(_) => ReceiptState::Unreadable("unsupported contents".into()),
            Err(e) => ReceiptState::Unreadable(e.to_string()),
        },
        Err(e) => ReceiptState::Unreadable(e.to_string()),
    }
}

/// True if any part of the service exists: files, strays or (as root) launchd state.
fn service_present(env: &Env, ops: &dyn SystemOps) -> Result<bool, Failure> {
    let probe = |e: String| {
        Failure::new(
            format!("could not check for the navd service: {}", san(&e)),
            "Nothing was removed. Check launchctl, then rerun.",
        )
    };
    if !on_disk(&env.layout)
        .map_err(|e| probe(format!("{e:#}")))?
        .is_empty()
    {
        return Ok(true);
    }
    match ops.is_loaded(LABEL) {
        Ok(true) => return Ok(true),
        Ok(false) => {}
        Err(e) if env.root => return Err(probe(format!("{e:#}"))),
        Err(_) => {}
    }
    if env.root {
        match ops.is_disabled(LABEL) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(e) => return Err(probe(format!("{e:#}"))),
        }
    }
    Ok(false)
}

fn remove_service(env: &Env, ops: &dyn SystemOps, exe: &Path) -> Result<(), Failure> {
    let report = uninstall(&env.layout, ops);
    let mut problems: Vec<String> = report.errors.iter().map(|e| san(e)).collect();
    match residue(&env.layout, ops) {
        Ok(r) if !r.is_clean() => {
            if problems.is_empty() {
                for p in r.fs_residue.iter().chain(&r.swept_extras) {
                    problems.push(format!("{} is still there", env.show(p)));
                }
            }
            if r.launchd_loaded {
                problems.push(format!("launchd still lists {LABEL}"));
            }
            if r.launchd_disabled {
                problems.push(format!("launchd still has a disable override on {LABEL}"));
            }
        }
        Ok(_) => {}
        Err(e) => problems.push(san(&format!("{e:#}"))),
    }
    if problems.is_empty() {
        return Ok(());
    }
    let mut f = Failure::new(
        "could not fully remove the navd service",
        "Nothing else was removed. Fix that, then rerun:",
    )
    .cmd(format!("sudo {} uninstall", env.shell_arg(exe)));
    f.detail = problems;
    Err(f)
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Removes the installed binary; its failure keeps the receipt.
fn remove_binary(env: &Env, ui: &Ui, r: &Receipt, exe: &Path) -> Result<(), Failure> {
    let bin = Path::new(&r.binary_path);
    let shown = env.show(bin);
    let fail = |why: String| {
        Failure::new(
            format!("could not remove {shown}: {}", san(&why)),
            "The install receipt was kept, so you can finish with:",
        )
        .cmd(format!("{} uninstall", env.shell_arg(exe)))
    };
    match fs::symlink_metadata(bin) {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => return Err(fail("not a regular file".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ui.note(&format!("{shown} was already gone"));
            return Ok(());
        }
        Err(e) => return Err(fail(e.to_string())),
    }
    if let Ok(now) = sha256_file(bin) {
        if now != r.binary_sha256 {
            ui.note(&format!(
                "{shown} was modified since it was installed; removing it anyway"
            ));
        }
    }
    fs::remove_file(bin).map_err(|e| fail(e.to_string()))?;
    ui.step(&format!("Removed {shown}"));
    Ok(())
}

/// What a startup file's NAV block looks like.
enum Block {
    /// Marker lines found; the rewritten contents and how many are left.
    Found {
        new: Vec<u8>,
        left: usize,
    },
    Gone,
    Changed,
}

/// Removes each marker line directly followed by a line `is_export` accepts.
fn strip_block(data: &[u8], is_export: &dyn Fn(&[u8]) -> bool) -> Block {
    let lines: Vec<&[u8]> = data.split(|b| *b == b'\n').collect();
    let mut keep: Vec<&[u8]> = Vec::with_capacity(lines.len());
    let (mut markers, mut removed) = (0, 0);
    let mut i = 0;
    while i < lines.len() {
        // A CRLF marker still counts as ours, but never matches exactly.
        let bare = lines[i].strip_suffix(b"\r").unwrap_or(lines[i]);
        if bare == PATH_MARKER.as_bytes() {
            markers += 1;
            if lines[i] == bare && lines.get(i + 1).is_some_and(|l| is_export(l)) {
                removed += 1;
                i += 2;
                continue;
            }
        }
        keep.push(lines[i]);
        i += 1;
    }
    if markers == 0 {
        Block::Gone
    } else if removed == 0 {
        Block::Changed
    } else {
        Block::Found {
            new: keep.join(&b'\n'),
            left: markers - removed,
        }
    }
}

/// True if `line` is the export line install.sh writes for install directory
/// `dir`: `export PATH="<dir>:$PATH"`, with `$` and backtick escaped, or the
/// literal `$HOME/.local/bin` when that is the directory. The directory is
/// compared after resolving symlinks, since the user may have given a link.
fn is_export(env: &Env, dir: &Path, line: &[u8]) -> bool {
    let Some(value) = std::str::from_utf8(line)
        .ok()
        .and_then(|s| s.strip_prefix("export PATH=\""))
        .and_then(|s| s.strip_suffix(":$PATH\""))
    else {
        return false;
    };
    if value == "$HOME/.local/bin" {
        return dir == env.home_canon.join(".local/bin") || dir == env.home.join(".local/bin");
    }
    let mut path = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(e @ ('$' | '`')) => path.push(e),
                _ => return false,
            },
            '$' | '`' | '"' => return false,
            _ => path.push(c),
        }
    }
    Path::new(&path).is_absolute() && fs::canonicalize(&path).is_ok_and(|c| c == dir)
}

/// Replaces `path` through a same-directory temp file, keeping mode and owner.
fn rewrite(path: &Path, data: &[u8], meta: &fs::Metadata) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{name}.nav-uninstall.{}", std::process::id()));
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o7777))?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Removes the installer's PATH block when it is safe to; otherwise keeps it
/// and says why. A write error keeps the receipt.
fn remove_path_block(env: &Env, ui: &Ui, r: &Receipt) -> Result<(), Failure> {
    let Some(edit) = &r.path_edit else {
        return Ok(());
    };
    let rc = Path::new(edit);
    let shown = env.show(rc);
    let keep = |why: &str, how: &str| {
        ui.note(&format!("Kept the PATH line in {shown}: {why}"));
        ui.detail(how);
    };
    let by_hand = format!("Delete the \"{PATH_MARKER}\" line and the line after it yourself.");

    let name = rc.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let parent = rc.parent().unwrap_or(rc);
    if !rc.is_absolute() || !matches!(name, ".zshrc" | ".bash_profile") || !env.within_home(parent)
    {
        keep("it isn't a startup file NAV edits", &by_hand);
        return Ok(());
    }
    let meta = match fs::symlink_metadata(rc) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ui.note(&format!(
                "{shown} no longer exists, so no PATH line to remove"
            ));
            return Ok(());
        }
        Err(e) => {
            return Err(path_failure(&shown, &e.to_string()));
        }
    };
    if !meta.file_type().is_file() || !env.owned(&meta) {
        keep("it isn't a plain file you own", &by_hand);
        return Ok(());
    }

    let bin = Path::new(&r.binary_path);
    let dir = bin.parent().unwrap_or(bin);
    let others = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .any(|e| !matches!(e.file_name().to_str(), Some("navctl" | ".DS_Store"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    };
    if others {
        keep(
            &format!("{} also holds other programs", env.show(dir)),
            "Remove it yourself when nothing else needs that directory.",
        );
        return Ok(());
    }

    let data = fs::read(rc).map_err(|e| path_failure(&shown, &e.to_string()))?;
    match strip_block(&data, &|l| is_export(env, dir, l)) {
        Block::Gone => ui.note(&format!("The PATH line was already gone from {shown}")),
        Block::Changed => keep("it no longer matches what the installer wrote", &by_hand),
        Block::Found { new, left } => {
            rewrite(rc, &new, &meta).map_err(|e| path_failure(&shown, &e.to_string()))?;
            ui.step(&format!("Removed the PATH line from {shown}"));
            if left > 0 {
                ui.note(&format!(
                    "{left} other NAV marker line(s) in {shown} don't match and were kept"
                ));
            }
        }
    }
    Ok(())
}

fn path_failure(shown: &str, why: &str) -> Failure {
    Failure::new(
        format!("could not update {shown}: {}", san(why)),
        "navctl was removed; the install receipt was kept. Delete the NAV marker line and the line after it yourself.",
    )
}

/// Removes the receipt, then its directory if that left it empty.
fn remove_receipt(env: &Env, ui: &Ui) -> Result<(), Failure> {
    let path = env.receipt_path();
    let dir = path.parent().unwrap_or(&path).to_path_buf();
    let shown = env.show(&path);
    match fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_file() => fs::remove_file(&path).map_err(|e| {
            Failure::new(
                format!("could not remove {shown}: {}", san(&e.to_string())),
                "Remove it yourself:",
            )
            .cmd(format!("rm {}", env.shell_arg(&path)))
        })?,
        Ok(_) => {
            return Err(Failure::new(
                format!("{shown} is not a regular file, so it was left alone"),
                "Check it, then remove it yourself.",
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Failure::new(
                format!("could not remove {shown}: {}", san(&e.to_string())),
                "Remove it yourself:",
            )
            .cmd(format!("rm {}", env.shell_arg(&path))))
        }
    }
    let empty = fs::symlink_metadata(&dir).is_ok_and(|m| m.file_type().is_dir())
        && fs::read_dir(&dir).is_ok_and(|mut d| d.next().is_none());
    if !empty {
        ui.step("Removed the install receipt");
        return Ok(());
    }
    match fs::remove_dir(&dir) {
        Ok(()) => ui.step(&format!(
            "Removed the install receipt and {}",
            env.show(&dir)
        )),
        Err(e) => {
            ui.step("Removed the install receipt");
            return Err(Failure::new(
                format!(
                    "could not remove {}: {}",
                    env.show(&dir),
                    san(&e.to_string())
                ),
                "Remove it yourself:",
            )
            .cmd(format!("rmdir {}", env.shell_arg(&dir))));
        }
    }
    Ok(())
}

/// The package manager's removal command for an unmanaged `navctl` at `exe`.
fn package_hint(env: &Env, exe: &Path) -> (String, Option<String>) {
    let comps: Vec<_> = exe.components().collect();
    if let Some(i) = comps.iter().position(|c| c.as_os_str() == "Cellar") {
        if let Some(name) = comps.get(i + 1).and_then(|c| c.as_os_str().to_str()) {
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.@+".contains(c))
            {
                return (
                    "Remove it with:".into(),
                    Some(format!("brew uninstall {name}")),
                );
            }
        }
    }
    let cargo_bin = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| env.home.join(".cargo"))
        .join("bin");
    let in_cargo = [
        cargo_bin,
        env.home.join(".cargo/bin"),
        env.home_canon.join(".cargo/bin"),
    ]
    .iter()
    .any(|d| exe.parent() == Some(d.as_path()));
    if in_cargo {
        return (
            "Remove it with:".into(),
            Some("cargo uninstall navctl".into()),
        );
    }
    (format!("Remove {} yourself.", env.show(exe)), None)
}

fn execute(ui: &Ui) -> Result<(), Failure> {
    let exe_raw = std::env::current_exe().map_err(|e| {
        Failure::new(
            format!("cannot locate navctl: {}", san(&e.to_string())),
            "Nothing was removed. Rerun it by its full path.",
        )
    })?;
    let exe = fs::canonicalize(&exe_raw).unwrap_or(exe_raw);
    let env = resolve_env(&exe)?;
    let ops = env.ops();

    let receipt = load_receipt(&env);
    let managed = match &receipt {
        ReceiptState::Found(r) => Path::new(&r.binary_path) == exe,
        _ => false,
    };
    let present = service_present(&env, ops.as_ref())?;

    if present && !env.root {
        return Err(Failure::new(
            "the navd service is installed, and removing it needs root",
            "Nothing was removed. Run:",
        )
        .cmd(format!("sudo {} uninstall", env.shell_arg(&exe))));
    }

    let version = env!("CARGO_PKG_VERSION");
    if managed {
        ui.head(&format!("Uninstalling navctl {version}"));
    } else if present {
        ui.head("Uninstalling the navd service");
    }
    if present {
        remove_service(&env, ops.as_ref(), &exe)?;
        ui.step("Removed the navd service");
        ui.detail("Full Disk Access grant reset is best-effort; check System Settings.");
    }
    drop_to_user(&env, &exe)?;

    let ReceiptState::Found(r) = &receipt else {
        return unmanaged(ui, &env, &exe, present, &receipt);
    };
    if !managed {
        return unmanaged(ui, &env, &exe, present, &receipt);
    }

    remove_binary(&env, ui, r, &exe)?;
    remove_path_block(&env, ui, r)?;
    remove_receipt(&env, ui)?;
    ui.out("");
    ui.head("Uninstalled navctl");
    Ok(())
}

/// Reports a CLI this installer doesn't manage, which stays in place.
fn unmanaged(
    ui: &Ui,
    env: &Env,
    exe: &Path,
    present: bool,
    receipt: &ReceiptState,
) -> Result<(), Failure> {
    if present {
        ui.out("");
    }
    match receipt {
        ReceiptState::Unreadable(why) => ui.out(&format!(
            "Left {} alone: it couldn't be read ({}).",
            env.show(&env.receipt_path()),
            san(why)
        )),
        ReceiptState::Found(r) => ui.out(&format!(
            "The install receipt is for {}, not this navctl, so it was left alone.",
            env.show(Path::new(&r.binary_path))
        )),
        ReceiptState::Missing => {}
    }
    ui.out("navctl wasn't installed by the NAV installer, so it was left in place.");
    match package_hint(env, exe) {
        (text, Some(cmd)) => ui.out(&format!("{text} {}", ui.cmd(&cmd))),
        (text, None) => ui.out(&text),
    }
    Ok(())
}

pub fn run() -> ExitCode {
    let ui = Ui::detect();
    match execute(&ui) {
        Ok(()) => exit::code(exit::CLEAN),
        Err(f) => {
            ui.error(&f);
            exit::code(exit::OPERATIONAL_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXP: &str = "export PATH=\"$HOME/.local/bin:$PATH\"";

    fn block(text: &str) -> Block {
        strip_block(text.as_bytes(), &|l| l == EXP.as_bytes())
    }

    #[test]
    fn strips_exact_pair() {
        let text = format!("a\n{PATH_MARKER}\n{EXP}\nb\n");
        match block(&text) {
            Block::Found { new, left } => {
                assert_eq!(new, b"a\nb\n");
                assert_eq!(left, 0);
            }
            _ => panic!("expected a block"),
        }
    }

    #[test]
    fn keeps_edited_pair() {
        let text = format!("{PATH_MARKER}\n{EXP} # mine\n");
        assert!(matches!(block(&text), Block::Changed));
        let crlf = format!("{PATH_MARKER}\r\n{EXP}\r\n");
        assert!(matches!(block(&crlf), Block::Changed));
        assert!(matches!(block("alias a=b\n"), Block::Gone));
    }

    #[test]
    fn counts_unmatched_marker() {
        let text = format!("{PATH_MARKER}\nx\n{PATH_MARKER}\n{EXP}\n");
        match block(&text) {
            Block::Found { new, left } => {
                assert_eq!(left, 1);
                assert_eq!(new, format!("{PATH_MARKER}\nx\n").into_bytes());
            }
            _ => panic!("expected a block"),
        }
    }

    #[test]
    fn colour_on_tty() {
        let ui = Ui {
            out_tty: true,
            out_color: true,
            err_color: true,
        };
        assert_eq!(Ui::paint(ui.out_color, "1", "x"), "\x1b[1mx\x1b[0m");
        assert_eq!(ui.cmd("sudo navctl"), "\x1b[36msudo navctl\x1b[0m");
        let plain = Ui {
            out_tty: false,
            out_color: false,
            err_color: false,
        };
        assert_eq!(plain.cmd("a b"), "a b");
        assert_eq!(Ui::paint(false, "1", "x"), "x");
    }

    #[test]
    fn drop_noop_unprivileged() {
        // SAFETY: getuid/getgid take no arguments and never fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let env = Env {
            root: true,
            uid: Some(uid),
            gid: Some(gid),
            home: PathBuf::from("/h"),
            home_canon: PathBuf::from("/h"),
            layout: Layout::under("/nonexistent"),
            fake_service: true,
        };
        if !crate::service::is_root() {
            assert!(drop_to_user(&env, Path::new("/x/navctl")).is_ok());
        }
    }

    #[test]
    fn shell_words() {
        assert_eq!(shell_word("/a/b-c.d"), "/a/b-c.d");
        assert_eq!(shell_word("/a b"), "'/a b'");
        assert_eq!(shell_word("/a'b"), "'/a'\\''b'");
    }
}
