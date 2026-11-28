//! `benign prepare`: unpack cached items under `<out>/<id>/` for the survey
//! script (§11.1b). Nothing is executed and no script inside an item runs.
//!
//! Layout per kind: `dmg` mounted at `mnt/`, `pkg` expanded to `pkg/`,
//! `zip`/`app`/`tar` unpacked to `files/`, `script` copied by file name,
//! `git` checked out at `repo/`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use super::fetch::{blob_path, bundle_path, git_step};
use super::manifest::{Item, Kind};
use crate::malware::{Problem, Report};

/// `url`'s last path segment cut to `[A-Za-z0-9._-]`, or `script`.
pub(super) fn script_name(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default();
    let clean: String = last
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    if clean.is_empty() || clean.chars().all(|c| c == '.') {
        "script".into()
    } else {
        clean
    }
}

/// Runs `cmd`, failing with `what` and its stderr on nonzero exit.
fn run(cmd: &mut Command, what: &str) -> Result<(), Problem> {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {what}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(Problem::Fail(format!("{what} failed: {}", err.trim())))
}

/// Mounts a disk image read-only; `Y` on stdin accepts any licence prompt.
fn attach(image: &Path, mnt: &Path) -> Result<(), Problem> {
    let mut child = Command::new("hdiutil")
        .args([
            "attach",
            "-readonly",
            "-nobrowse",
            "-noautoopen",
            "-mountpoint",
        ])
        .arg(mnt)
        .arg(image)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running hdiutil")?;
    if let Some(mut stdin) = child.stdin.take() {
        // The image may not prompt and exit first; a broken pipe is fine.
        let _ = stdin.write_all(b"Y\n");
    }
    let out = child.wait_with_output().context("waiting for hdiutil")?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(Problem::Fail(format!(
        "hdiutil attach failed: {}",
        err.trim()
    )))
}

/// Removes a previous run's directory, detaching its image first.
fn clean(dir: &Path) -> Result<()> {
    let mnt = dir.join("mnt");
    if mnt.exists() {
        let _ = Command::new("hdiutil")
            .args(["detach", "-quiet", "-force"])
            .arg(&mnt)
            .status();
    }
    if dir.symlink_metadata().is_ok() {
        std::fs::remove_dir_all(dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    Ok(())
}

fn unpack(item: &Item, cache: &Path, dir: &Path) -> Result<(), Problem> {
    if item.kind == Kind::Git {
        let commit = item.commit.as_deref().unwrap();
        let bundle = bundle_path(cache, commit);
        if !bundle.is_file() {
            return Err(Problem::Fail("bundle not in the cache".into()));
        }
        let bundle = crate::corpus::absolute(&bundle)?;
        let repo = dir.join("repo");
        std::fs::create_dir(&repo).with_context(|| format!("creating {}", repo.display()))?;
        let refspec = "refs/nav/pin:refs/nav/pin";
        git_step(&repo, &["init", "--quiet"], "git init")?;
        let b = bundle.to_string_lossy();
        git_step(&repo, &["fetch", "--quiet", &b, refspec], "git fetch")?;
        return git_step(
            &repo,
            &["checkout", "--quiet", "--detach", commit],
            "git checkout",
        );
    }
    let sha = item.sha256.as_deref().filter(|_| item.recorded());
    let sha = sha.ok_or_else(|| Problem::Fail("not recorded in the manifest".into()))?;
    let blob = blob_path(cache, sha);
    if !blob.is_file() {
        return Err(Problem::Fail("not in the cache".into()));
    }
    let blob = crate::corpus::absolute(&blob)?;
    match item.kind {
        Kind::Dmg => {
            let mnt = dir.join("mnt");
            std::fs::create_dir(&mnt).with_context(|| format!("creating {}", mnt.display()))?;
            attach(&blob, &mnt)
        }
        Kind::Pkg => run(
            Command::new("pkgutil")
                .arg("--expand-full")
                .arg(&blob)
                .arg(dir.join("pkg")),
            "pkgutil",
        ),
        Kind::Zip | Kind::App => run(
            Command::new("ditto")
                .args(["-x", "-k"])
                .arg(&blob)
                .arg(dir.join("files")),
            "ditto",
        ),
        Kind::Tar => {
            let files = dir.join("files");
            std::fs::create_dir(&files).with_context(|| format!("creating {}", files.display()))?;
            run(
                Command::new("tar")
                    .arg("-xf")
                    .arg(&blob)
                    .arg("-C")
                    .arg(&files)
                    .arg("--no-same-owner"),
                "tar",
            )
        }
        Kind::Script => {
            let dest = dir.join(script_name(item.url.as_deref().unwrap_or_default()));
            std::fs::copy(&blob, &dest)
                .with_context(|| format!("copying to {}", dest.display()))?;
            Ok(())
        }
        Kind::Git => unreachable!("handled above"),
    }
}

/// Unpacks each item from `cache` into `out/<id>/`, one line per item, and
/// lists the prepared ones in `out/index.tsv` as `id<TAB>category<TAB>kind`.
/// The cache is trusted: `fetch` has already hashed it.
pub fn prepare(items: &[&Item], cache: &Path, out: &Path) -> Result<Report> {
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let mut report = Report::default();
    let mut index = String::new();
    for item in items {
        let dir = out.join(&item.id);
        clean(&dir)?;
        std::fs::create_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
        match unpack(item, cache, &dir) {
            Ok(()) => {
                report.pass(&item.id);
                let (c, k) = (item.category.label(), item.kind.label());
                index.push_str(&format!("{}\t{c}\t{k}\n", item.id));
            }
            Err(Problem::Fail(why)) => report.fail(&item.id, &why),
            Err(Problem::Tool(e)) => return Err(e),
        }
    }
    let path = out.join("index.tsv");
    std::fs::write(&path, index).with_context(|| format!("writing {}", path.display()))?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benign::manifest::Manifest;
    use crate::malware::hash::{file_digest, hex};
    use crate::malware::test_util::TempDir;
    use sha2::{Digest, Sha256};

    #[test]
    fn names_scripts_safely() {
        assert_eq!(script_name("https://e.com/x/install.sh?a=b"), "install.sh");
        assert_eq!(script_name("https://e.com/"), "script");
        assert_eq!(script_name("https://e.com/.."), "script");
        assert_eq!(script_name("https://e.com/a%2Fb c"), "a2Fbc");
    }

    /// Puts `file` into the cache under its hash and returns a manifest item.
    fn cached(t: &TempDir, file: &Path, kind: &str, url: &str) -> String {
        let m = file_digest(file).unwrap();
        let cache = t.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::copy(file, cache.join(&m.sha256)).unwrap();
        format!(
            "[[item]]\nid = \"{kind}-1\"\ncategory = \"installer\"\nkind = \"{kind}\"\nurl = \"{url}\"\nsha256 = \"{}\"\nbytes = {}\n",
            m.sha256, m.bytes
        )
    }

    fn prep(t: &TempDir, text: &str) -> (Report, std::path::PathBuf) {
        let m = Manifest::parse(text).unwrap();
        let items: Vec<&Item> = m.items.iter().collect();
        let out = t.path().join("out");
        let r = prepare(&items, &t.path().join("cache"), &out).unwrap();
        (r, out)
    }

    #[test]
    fn unpacks_tar_and_script() {
        let t = TempDir::new("benign-prep");
        let src = t.path().join("src");
        std::fs::create_dir_all(src.join("d")).unwrap();
        std::fs::write(src.join("d/f"), "hello").unwrap();
        let tar = t.path().join("a.tar");
        let st = Command::new("tar")
            .arg("-cf")
            .arg(&tar)
            .arg("-C")
            .arg(&src)
            .arg("d")
            .status()
            .expect("tar is required to run this test");
        assert!(st.success());
        let script = t.path().join("s");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();
        let text = format!(
            "{}{}",
            cached(&t, &tar, "tar", "https://e.com/a.tar"),
            cached(&t, &script, "script", "https://e.com/i.sh")
        );
        let (r, out) = prep(&t, &text);
        assert_eq!((r.ok, r.failed), (2, 0), "{:?}", r.failures);
        assert_eq!(
            std::fs::read_to_string(out.join("tar-1/files/d/f")).unwrap(),
            "hello"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("script-1/i.sh")).unwrap(),
            "#!/bin/sh\n"
        );
        let index = std::fs::read_to_string(out.join("index.tsv")).unwrap();
        assert_eq!(
            index,
            "tar-1\tinstaller\ttar\nscript-1\tinstaller\tscript\n"
        );
    }

    #[test]
    fn missing_cache_fails() {
        let t = TempDir::new("benign-prep-miss");
        let h = hex(&Sha256::digest(b"x"));
        let text = format!(
            "[[item]]\nid = \"a\"\ncategory = \"drm\"\nkind = \"tar\"\nurl = \"https://e.com/a\"\nsha256 = \"{h}\"\nbytes = 1\n\n[[item]]\nid = \"b\"\ncategory = \"drm\"\nkind = \"tar\"\nurl = \"https://e.com/b\"\n"
        );
        let (r, _) = prep(&t, &text);
        assert_eq!((r.ok, r.failed), (0, 2));
        assert!(r.failures[0].1.contains("cache"));
        assert!(r.failures[1].1.contains("recorded"));
    }

    #[test]
    fn rerun_replaces_old_dir() {
        let t = TempDir::new("benign-prep-rerun");
        let script = t.path().join("s");
        std::fs::write(&script, "x").unwrap();
        let text = cached(&t, &script, "script", "https://e.com/i.sh");
        let (_, out) = prep(&t, &text);
        std::fs::write(out.join("script-1/stale"), "").unwrap();
        let (r, out) = prep(&t, &text);
        assert_eq!(r.ok, 1);
        assert!(!out.join("script-1/stale").exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unpacks_zip_with_ditto() {
        let t = TempDir::new("benign-prep-zip");
        let src = t.path().join("Foo.app");
        std::fs::create_dir_all(src.join("Contents")).unwrap();
        std::fs::write(src.join("Contents/x"), "hi").unwrap();
        let zip = t.path().join("a.zip");
        let st = Command::new("ditto")
            .args(["-c", "-k", "--keepParent"])
            .arg(&src)
            .arg(&zip)
            .status()
            .unwrap();
        assert!(st.success());
        let text = cached(&t, &zip, "app", "https://e.com/Foo.zip");
        let (r, out) = prep(&t, &text);
        assert_eq!(r.ok, 1, "{:?}", r.failures);
        assert!(out.join("app-1/files/Foo.app/Contents/x").is_file());
    }
}
