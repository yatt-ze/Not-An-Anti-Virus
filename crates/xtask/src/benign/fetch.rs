//! `benign fetch` and `benign verify`: fill and check the download cache
//! (§11.1b). URL items live at `<cache>/<sha256>`, git items at
//! `<cache>/git/<commit>.bundle`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};

use super::manifest::{record_text, Item, Kind};
use crate::malware::fetch::{unique_name, Cleanup};
use crate::malware::hash::file_digest;
use crate::malware::{Problem, Report};

/// curl's `--max-filesize`: 16 GiB, so a hijacked URL cannot fill the VM disk.
const MAX_DOWNLOAD: &str = "17179869184";

/// Ref the bundled commit is stored under.
const PIN_REF: &str = "refs/nav/pin";

pub fn blob_path(cache: &Path, sha256: &str) -> PathBuf {
    cache.join(sha256)
}

pub fn bundle_path(cache: &Path, commit: &str) -> PathBuf {
    cache.join("git").join(format!("{commit}.bundle"))
}

/// Where bytes come from; replaced in tests so they never touch the network.
pub struct Sources<'a> {
    /// Downloads `url` to the given path.
    pub download: &'a dyn Fn(&str, &Path) -> Result<(), Problem>,
    /// Bundles `commit` of GitHub `repo` into the given path.
    pub bundle: &'a dyn Fn(&str, &str, &Path) -> Result<(), Problem>,
}

pub const REAL: Sources<'static> = Sources {
    download: &curl_download,
    bundle: &github_bundle,
};

/// Per-item outcomes plus the items left out for drift.
#[derive(Default)]
pub struct Summary {
    pub report: Report,
    pub refreshed: usize,
}

impl Summary {
    /// Prints the totals; 2 if any item failed, else 0. Drift is not a failure.
    pub fn finish(self) -> ExitCode {
        println!(
            "{} ok, {} failed, {} to refresh",
            self.report.ok, self.report.failed, self.refreshed
        );
        ExitCode::from(if self.report.failed > 0 { 2 } else { 0 })
    }
}

/// What `fetch` does beyond filling the cache.
pub struct Record<'a> {
    /// The manifest file to rewrite with new hashes.
    pub manifest: &'a Path,
}

fn curl_download(url: &str, dest: &Path) -> Result<(), Problem> {
    let status = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "30",
            "--speed-limit",
            "1000",
            "--speed-time",
            "120",
            "--max-filesize",
            MAX_DOWNLOAD,
            "--retry",
            "2",
            "-o",
        ])
        .arg(dest)
        .arg("--url")
        .arg(url)
        .status()
        .context("running curl")?;
    if status.success() {
        Ok(())
    } else {
        Err(Problem::Fail(format!("download failed ({status})")))
    }
}

fn github_bundle(repo: &str, commit: &str, dest: &Path) -> Result<(), Problem> {
    bundle_commit(&format!("https://github.com/{repo}.git"), commit, dest)
}

/// `git` in `dir` with prompts off and the caller's repository variables
/// removed, so it never touches a repository the caller is running inside
/// (e.g. a commit hook's index).
pub(super) fn git_cmd(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir).env("GIT_TERMINAL_PROMPT", "0");
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_COMMON_DIR",
        "GIT_PREFIX",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

/// Runs `git` in `dir`; a failure becomes `Fail(what)`.
pub(super) fn git_step(dir: &Path, args: &[&str], what: &str) -> Result<(), Problem> {
    let out = git_cmd(dir).args(args).output().context("running git")?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(Problem::Fail(format!("{what}: {}", err.trim())))
    }
}

/// Clones `source` and writes a bundle holding only `commit` (and its
/// history) to `dest`. Fails if the clone lacks the commit.
pub fn bundle_commit(source: &str, commit: &str, dest: &Path) -> Result<(), Problem> {
    let parent = dest.parent().context("bundle path has no parent")?;
    let tmp = parent.join(unique_name("clone"));
    let _guard = Cleanup::dir(tmp.clone());
    std::fs::create_dir(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let mut clone = vec!["clone", "--quiet", "--no-checkout"];
    if source.starts_with("https://") {
        clone.extend([
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
        ]);
    }
    clone.extend(["--", source, "repo"]);
    git_step(&tmp, &clone, "clone failed")?;
    let repo = tmp.join("repo");
    let rev = format!("{commit}^{{commit}}");
    git_step(
        &repo,
        &["cat-file", "-e", &rev],
        "commit not found in the repo",
    )?;
    git_step(&repo, &["update-ref", PIN_REF, commit], "update-ref failed")?;
    let dest = crate::corpus::absolute(dest)?;
    let dest = dest.to_string_lossy();
    git_step(
        &repo,
        &["bundle", "create", &dest, PIN_REF],
        "bundle failed",
    )
}

/// Fetches `bundle` into a scratch repository and checks it yields `commit`;
/// this is git's own integrity check.
pub fn check_bundle(bundle: &Path, commit: &str) -> Result<(), Problem> {
    let bundle = crate::corpus::absolute(bundle)?;
    let parent = bundle.parent().context("bundle path has no parent")?;
    let tmp = parent.join(unique_name("verify"));
    let _guard = Cleanup::dir(tmp.clone());
    std::fs::create_dir(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let refspec = format!("{PIN_REF}:{PIN_REF}");
    git_step(&tmp, &["init", "--quiet", "--bare"], "git init failed")?;
    let b = bundle.to_string_lossy();
    git_step(
        &tmp,
        &["fetch", "--quiet", &b, &refspec],
        "bundle is corrupt",
    )?;
    let rev = format!("{commit}^{{commit}}");
    git_step(
        &tmp,
        &["rev-parse", "--verify", &rev],
        "bundle lacks the commit",
    )?;
    let out = git_cmd(&tmp)
        .args(["rev-parse", PIN_REF])
        .output()
        .context("running git")?;
    if String::from_utf8_lossy(&out.stdout).trim() != commit {
        return Err(Problem::Fail("bundle pins a different commit".into()));
    }
    Ok(())
}

/// Adds the cached file's path to a `Fail`, so the fix (delete it) is obvious.
fn name_path(r: Result<(), Problem>, path: &Path) -> Result<(), Problem> {
    r.map_err(|e| match e {
        Problem::Fail(why) => {
            Problem::Fail(format!("{why} (delete {} and refetch)", path.display()))
        }
        tool => tool,
    })
}

/// Hashes the cached `blob` against the item's recorded `sha256` and `bytes`.
fn check_blob(item: &Item, blob: &Path) -> Result<(), Problem> {
    let m = file_digest(blob)?;
    if Some(&m.sha256) != item.sha256.as_ref() || Some(m.bytes) != item.bytes {
        return Err(Problem::Fail(format!(
            "cached file is corrupt: {} bytes, sha256 {} does not match the manifest (delete {} and refetch)",
            m.bytes,
            m.sha256,
            blob.display()
        )));
    }
    Ok(())
}

/// Rewrites `sha256` and `bytes` of item `id` in the manifest file.
fn write_record(manifest: &Path, id: &str, sha256: &str, bytes: u64) -> Result<()> {
    let text = std::fs::read_to_string(manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let new = record_text(&text, id, sha256, bytes)?;
    let tmp = manifest.with_file_name(unique_name("manifest"));
    let _guard = Cleanup::file(tmp.clone());
    std::fs::write(&tmp, new).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, manifest).with_context(|| format!("replacing {}", manifest.display()))
}

/// Fills `cache` for `items`, one line per item. Without `record`, an
/// unrecorded item fails and a changed URL prints `refresh:` and is left out.
/// With it, new hashes are accepted and written to the manifest.
pub fn fetch(
    items: &[&Item],
    cache: &Path,
    src: &Sources,
    record: Option<&Record>,
) -> Result<Summary> {
    std::fs::create_dir_all(cache.join("git"))
        .with_context(|| format!("creating {}", cache.display()))?;
    let mut s = Summary::default();
    for item in items {
        let res = match item.kind {
            Kind::Git => fetch_git(item, cache, src),
            _ => fetch_url(item, cache, src, record, &mut s),
        };
        match res {
            Ok(Done::Ok) => s.report.pass(&item.id),
            Ok(Done::Left) => {}
            Err(Problem::Fail(why)) => s.report.fail(&item.id, &why),
            Err(Problem::Tool(e)) => return Err(e),
        }
    }
    Ok(s)
}

enum Done {
    Ok,
    /// Left out for drift; neither ok nor failed.
    Left,
}

fn fetch_git(item: &Item, cache: &Path, src: &Sources) -> Result<Done, Problem> {
    let (repo, commit) = (
        item.repo.as_deref().unwrap(),
        item.commit.as_deref().unwrap(),
    );
    let dest = bundle_path(cache, commit);
    if dest.is_file() {
        name_path(check_bundle(&dest, commit), &dest)?;
        return Ok(Done::Ok);
    }
    let tmp = cache.join("git").join(unique_name("bundle"));
    let _guard = Cleanup::file(tmp.clone());
    (src.bundle)(repo, commit, &tmp)?;
    check_bundle(&tmp, commit)?;
    std::fs::rename(&tmp, &dest).with_context(|| format!("moving to {}", dest.display()))?;
    Ok(Done::Ok)
}

fn fetch_url(
    item: &Item,
    cache: &Path,
    src: &Sources,
    record: Option<&Record>,
    s: &mut Summary,
) -> Result<Done, Problem> {
    let url = item.url.as_deref().unwrap();
    if let (Some(want), true) = (&item.sha256, item.recorded()) {
        let blob = blob_path(cache, want);
        if blob.is_file() {
            check_blob(item, &blob)?;
            return Ok(Done::Ok);
        }
    } else if record.is_none() {
        return Err(Problem::Fail(
            "not recorded; run `benign fetch --record` in the VM".into(),
        ));
    }
    let tmp = cache.join(unique_name("download"));
    let _guard = Cleanup::file(tmp.clone());
    (src.download)(url, &tmp)?;
    let got = file_digest(&tmp)?;
    let same = item.sha256.as_deref() == Some(got.sha256.as_str()) && item.bytes == Some(got.bytes);
    if !same && item.recorded() {
        match record {
            None => {
                let old = item.sha256.as_deref().unwrap_or_default();
                println!("refresh: {} {old} -> {}", item.id, got.sha256);
                s.refreshed += 1;
                return Ok(Done::Left);
            }
            Some(_) => println!("recorded new bytes for {}", item.id),
        }
    }
    let blob = blob_path(cache, &got.sha256);
    std::fs::rename(&tmp, &blob).with_context(|| format!("moving to {}", blob.display()))?;
    if let (false, Some(r)) = (same, record) {
        write_record(r.manifest, &item.id, &got.sha256, got.bytes)?;
    }
    Ok(Done::Ok)
}

/// Re-hashes the cache for `items` without network access.
pub fn verify(items: &[&Item], cache: &Path) -> Result<Summary> {
    let mut s = Summary::default();
    for item in items {
        let res = match (item.kind, &item.sha256, &item.commit) {
            (Kind::Git, _, Some(c)) => {
                let b = bundle_path(cache, c);
                if b.is_file() {
                    name_path(check_bundle(&b, c), &b)
                } else {
                    Err(Problem::Fail("bundle not in the cache".into()))
                }
            }
            (_, Some(h), _) if item.recorded() => {
                let b = blob_path(cache, h);
                if b.is_file() {
                    check_blob(item, &b)
                } else {
                    Err(Problem::Fail("not in the cache".into()))
                }
            }
            _ => Err(Problem::Fail("not recorded in the manifest".into())),
        };
        match res {
            Ok(()) => s.report.pass(&item.id),
            Err(Problem::Fail(why)) => s.report.fail(&item.id, &why),
            Err(Problem::Tool(e)) => return Err(e),
        }
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::benign::manifest::Manifest;
    use crate::malware::hash::hex;
    use crate::malware::test_util::TempDir;
    use sha2::{Digest, Sha256};

    fn sha_hex(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }

    fn manifest(extra: &str) -> String {
        format!(
            "[[item]]\nid = \"a\"\ncategory = \"installer\"\nkind = \"pkg\"\nurl = \"https://e.com/a\"\n{extra}"
        )
    }

    fn recorded(body: &[u8]) -> String {
        manifest(&format!(
            "sha256 = \"{}\"\nbytes = {}\n",
            sha_hex(body),
            body.len()
        ))
    }

    /// Fetches with a download that serves `body` and counts its calls.
    fn run(
        t: &TempDir,
        text: &str,
        body: &[u8],
        record: bool,
    ) -> (Summary, usize, std::path::PathBuf) {
        let mpath = t.path().join("benign.toml");
        std::fs::write(&mpath, text).unwrap();
        let m = Manifest::parse(text).unwrap();
        let calls = Cell::new(0);
        let download = |_: &str, dest: &Path| {
            calls.set(calls.get() + 1);
            std::fs::write(dest, body).map_err(|e| Problem::Tool(e.into()))
        };
        let bundle = |_: &str, _: &str, _: &Path| -> Result<(), Problem> { panic!("no git") };
        let src = Sources {
            download: &download,
            bundle: &bundle,
        };
        let items: Vec<&Item> = m.items.iter().collect();
        let rec = Record { manifest: &mpath };
        let s = fetch(
            &items,
            &t.path().join("cache"),
            &src,
            record.then_some(&rec),
        )
        .unwrap();
        (s, calls.get(), mpath)
    }

    #[test]
    fn downloads_then_hits_cache() {
        let t = TempDir::new("benign-dl");
        let text = recorded(b"pkg");
        let (s, calls, _) = run(&t, &text, b"pkg", false);
        assert_eq!((s.report.ok, s.report.failed, calls), (1, 0, 1));
        assert!(blob_path(&t.path().join("cache"), &sha_hex(b"pkg")).is_file());
        let (s, calls, _) = run(&t, &text, b"unused", false);
        assert_eq!((s.report.ok, calls), (1, 0));
        let m = Manifest::parse(&text).unwrap();
        let v = verify(&m.items.iter().collect::<Vec<_>>(), &t.path().join("cache")).unwrap();
        assert_eq!((v.report.ok, v.report.failed), (1, 0));
    }

    #[test]
    fn corrupt_cache_fails() {
        let t = TempDir::new("benign-bad");
        let text = recorded(b"pkg");
        run(&t, &text, b"pkg", false);
        let blob = blob_path(&t.path().join("cache"), &sha_hex(b"pkg"));
        std::fs::write(&blob, b"tampered").unwrap();
        let (s, calls, _) = run(&t, &text, b"pkg", false);
        assert_eq!((s.report.failed, s.refreshed, calls), (1, 0, 0));
        assert!(s.report.failures[0].1.contains("corrupt"));
        assert!(s.report.failures[0].1.contains("delete "));
        let m = Manifest::parse(&text).unwrap();
        let v = verify(&m.items.iter().collect::<Vec<_>>(), &t.path().join("cache")).unwrap();
        assert_eq!(v.report.failed, 1);
    }

    /// A changed URL without `--record` prints a refresh line and leaves
    /// the item out; it is neither ok nor failed, and the manifest is untouched.
    #[test]
    fn drift_refreshes() {
        let t = TempDir::new("benign-drift");
        let text = recorded(b"old");
        let (s, calls, mpath) = run(&t, &text, b"new bytes", false);
        assert_eq!((s.report.ok, s.report.failed, s.refreshed), (0, 0, 1));
        assert_eq!(calls, 1);
        assert_eq!(std::fs::read_to_string(&mpath).unwrap(), text);
        let cache = t.path().join("cache");
        assert!(!blob_path(&cache, &sha_hex(b"new bytes")).exists());
        // Only the git dir remains: no stray temp download.
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 1);
    }

    #[test]
    fn record_accepts_drift() {
        let t = TempDir::new("benign-rec");
        let text = format!("# keep\n{}", recorded(b"old"));
        let (s, _, mpath) = run(&t, &text, b"new bytes", true);
        assert_eq!((s.report.ok, s.refreshed), (1, 0));
        let now = std::fs::read_to_string(&mpath).unwrap();
        assert!(now.starts_with("# keep\n"));
        let m = Manifest::parse(&now).unwrap();
        assert_eq!(
            m.items[0].sha256.as_deref(),
            Some(sha_hex(b"new bytes").as_str())
        );
        assert_eq!(m.items[0].bytes, Some(9));
        assert!(blob_path(&t.path().join("cache"), &sha_hex(b"new bytes")).is_file());
    }

    #[test]
    fn unrecorded_needs_record() {
        let t = TempDir::new("benign-unrec");
        let text = manifest("");
        let (s, calls, _) = run(&t, &text, b"pkg", false);
        assert_eq!((s.report.failed, calls), (1, 0));
        assert!(s.report.failures[0].1.contains("not recorded"));
        let (s, _, mpath) = run(&t, &text, b"pkg", true);
        assert_eq!(s.report.ok, 1);
        let m = Manifest::load(&mpath).unwrap();
        assert!(m.items[0].recorded());
        assert_eq!(m.items[0].bytes, Some(3));
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = git_cmd(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@e.com"])
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .expect("git is required to run this test");
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn bundles_and_verifies_commit() {
        let t = TempDir::new("benign-git");
        let repo = t.path().join("up");
        std::fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "--quiet"]);
        std::fs::write(repo.join("f"), "x").unwrap();
        git(&repo, &["add", "f"]);
        git(&repo, &["commit", "--quiet", "-m", "one"]);
        let commit = git(&repo, &["rev-parse", "HEAD"]);
        std::fs::write(repo.join("f"), "y").unwrap();
        git(&repo, &["commit", "--quiet", "-am", "two"]);

        let text = format!(
            "[[item]]\nid = \"g\"\ncategory = \"dev-tools\"\nkind = \"git\"\nrepo = \"o/r\"\ncommit = \"{commit}\"\n"
        );
        let m = Manifest::parse(&text).unwrap();
        let items: Vec<&Item> = m.items.iter().collect();
        let download = |_: &str, _: &Path| -> Result<(), Problem> { panic!("no url") };
        let up = repo.to_string_lossy().into_owned();
        let bundle = |_: &str, c: &str, d: &Path| bundle_commit(&up, c, d);
        let src = Sources {
            download: &download,
            bundle: &bundle,
        };
        let cache = t.path().join("cache");
        let s = fetch(&items, &cache, &src, None).unwrap();
        assert_eq!((s.report.ok, s.report.failed), (1, 0));
        assert!(bundle_path(&cache, &commit).is_file());
        assert_eq!(std::fs::read_dir(cache.join("git")).unwrap().count(), 1);
        let v = verify(&items, &cache).unwrap();
        assert_eq!(v.report.ok, 1);
        // The bundle holds the pinned commit only, not the later one.
        let b = bundle_path(&cache, &commit);
        let heads = git(&cache, &["bundle", "list-heads", &b.to_string_lossy()]);
        assert!(heads.starts_with(&commit), "{heads}");

        std::fs::write(&b, b"junk").unwrap();
        assert_eq!(verify(&items, &cache).unwrap().report.failed, 1);
    }

    #[test]
    fn missing_commit_fails() {
        let t = TempDir::new("benign-nocommit");
        let repo = t.path().join("up");
        std::fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "--quiet"]);
        std::fs::write(repo.join("f"), "x").unwrap();
        git(&repo, &["add", "f"]);
        git(&repo, &["commit", "--quiet", "-m", "one"]);
        let dest = t.path().join("out.bundle");
        let r = bundle_commit(&repo.to_string_lossy(), &"a".repeat(40), &dest);
        assert!(matches!(r, Err(Problem::Fail(w)) if w.contains("commit not found")));
        assert!(!dest.exists());
    }
}
