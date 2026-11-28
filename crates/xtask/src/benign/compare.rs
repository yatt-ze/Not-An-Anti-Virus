//! `benign compare` (guest side): scans the cached downloads as published,
//! plus git checkouts, with a base and a new navctl and gates the diff with
//! the corpus rules (§11.1b).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};

use super::fetch::{blob_path, bundle_path, git_step};
use super::manifest::{Item, Kind};
use crate::build::{build_pair, git, resolve_dirs, PairSpec};
use crate::corpus::plan::{Chunk, Plan};
use crate::corpus::scan::{run as scan, Target};
use crate::corpus::{diff, parse};
use crate::malware::fetch::{unique_name, Cleanup};
use crate::malware::Problem;

/// File name an item is staged under: the URL's last segment, with the
/// kind's extension appended unless the name already ends with it (a tar may
/// end in `.tar`, `.tar.gz`, `.tgz`, `.tar.xz` or `.tar.bz2`), so navctl sees
/// a recognisable name.
pub fn published_name(item: &Item) -> String {
    let name = super::prepare::script_name(item.url.as_deref().unwrap_or_default());
    let (exts, add): (&[&str], &str) = match item.kind {
        Kind::Dmg => (&[".dmg"], ".dmg"),
        Kind::Pkg => (&[".pkg"], ".pkg"),
        Kind::Zip | Kind::App => (&[".zip"], ".zip"),
        Kind::Tar => (&[".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2"], ".tar"),
        Kind::Script | Kind::Git => return name,
    };
    let lower = name.to_ascii_lowercase();
    if exts.iter().any(|e| lower.ends_with(e)) {
        name
    } else {
        format!("{name}{add}")
    }
}

/// Checks out `commit` from `bundle` into `work_tree` with the repository
/// kept apart in a scratch dir, so the tree holds no `.git` to scan.
fn checkout_clean(bundle: &Path, commit: &str, work_tree: &Path) -> Result<(), Problem> {
    let scratch = work_tree.with_file_name(unique_name("gitdir"));
    let _guard = Cleanup::dir(scratch.clone());
    let bundle = crate::corpus::absolute(bundle)?;
    let (g, w) = (scratch.to_string_lossy(), work_tree.to_string_lossy());
    let gd = format!("--git-dir={g}");
    git_step(
        Path::new("."),
        &["init", "--quiet", "--bare", &g],
        "git init",
    )?;
    let b = bundle.to_string_lossy();
    let refspec = "refs/nav/pin:refs/nav/pin";
    git_step(
        Path::new("."),
        &[&gd, "fetch", "--quiet", &b, refspec],
        "git fetch",
    )?;
    std::fs::create_dir(work_tree).with_context(|| format!("creating {w}"))?;
    let wt = format!("--work-tree={w}");
    git_step(
        Path::new("."),
        &[&gd, &wt, "checkout", "--quiet", "--detach", commit],
        "git checkout",
    )
}

/// Hard-links `src` to `dest`, copying when the filesystems differ.
fn link_or_copy(src: &Path, dest: &Path) -> Result<()> {
    if std::fs::hard_link(src, dest).is_err() {
        std::fs::copy(src, dest).with_context(|| format!("copying to {}", dest.display()))?;
    }
    Ok(())
}

/// Stages each item under `root/<id>/` (downloads as published, git
/// checkouts without `.git`) and returns one chunk per staged item plus
/// `(id, reason)` for items that could not be staged.
pub fn stage(items: &[&Item], cache: &Path, root: &Path) -> Result<(Plan, Vec<(String, String)>)> {
    std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let mut plan = Plan::default();
    let mut failed = Vec::new();
    for item in items {
        let dir = root.join(&item.id);
        if dir.symlink_metadata().is_ok() {
            std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
        }
        std::fs::create_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let res = match (item.kind, &item.commit, &item.sha256) {
            (Kind::Git, Some(c), _) => {
                let bundle = bundle_path(cache, c);
                let work = dir.join("repo");
                let r = if bundle.is_file() {
                    checkout_clean(&bundle, c, &work)
                } else {
                    Err(Problem::Fail("bundle not in the cache".into()))
                };
                r.map(|()| Chunk {
                    path: work,
                    recursive: true,
                })
            }
            (_, _, Some(h)) if item.recorded() => {
                let blob = blob_path(cache, h);
                let dest = dir.join(published_name(item));
                if blob.is_file() {
                    link_or_copy(&blob, &dest)
                        .map(|()| Chunk {
                            path: dest,
                            recursive: false,
                        })
                        .map_err(Into::into)
                } else {
                    Err(Problem::Fail("not in the cache".into()))
                }
            }
            _ => Err(Problem::Fail("not recorded in the manifest".into())),
        };
        match res {
            Ok(chunk) => plan.chunks.push(chunk),
            Err(Problem::Fail(why)) => {
                println!("FAIL {}: {why}", item.id);
                failed.push((item.id.clone(), why));
            }
            Err(Problem::Tool(e)) => return Err(e),
        }
    }
    Ok((plan, failed))
}

pub struct CompareOpts<'a> {
    pub items: &'a [&'a Item],
    pub cache: &'a Path,
    /// Staging root, rebuilt each run.
    pub stage_dir: &'a Path,
    pub base: &'a str,
    pub out_dir: Option<&'a Path>,
    pub jobs: Option<usize>,
}

/// Builds base and new navctl in one shared target dir, scans the staged set
/// with both, writes `report.txt`, `base.jsonl` and `new.jsonl`, and gates.
/// Exit 2 if the corpus gate fails, an item could not be staged or a navctl
/// run failed.
pub fn run(o: &CompareOpts) -> Result<ExitCode> {
    let (plan, failed) = stage(o.items, o.cache, o.stage_dir)?;
    if plan.chunks.is_empty() {
        println!("no item could be staged; nothing to scan");
        return Ok(ExitCode::from(2));
    }
    let repo = PathBuf::from(git(Path::new("."), &["rev-parse", "--show-toplevel"])?);
    let (target_dir, out_dir) = resolve_dirs(&repo, o.out_dir, "xtask-benign")?;
    let (navctl_base, navctl_new) = build_pair(&PairSpec {
        repo: &repo,
        base_rev: o.base,
        out_dir: &out_dir,
        new_target: &target_dir,
        base_target: &target_dir,
        stale_root: &repo.join("target/xtask-benign"),
    })?;
    let (base_jsonl, new_jsonl) = (out_dir.join("base.jsonl"), out_dir.join("new.jsonl"));
    // codesign's revocation answer depends on its cache; warm it first so
    // base and new do not disagree on revoked binaries (§11.1a, #150).
    println!("warm-up pass (results discarded)");
    let warm = [Target {
        navctl: &navctl_base,
        out: &out_dir.join("warmup.jsonl"),
    }];
    scan(&warm, &plan, o.jobs)?;
    let targets = [
        Target {
            navctl: &navctl_base,
            out: &base_jsonl,
        },
        Target {
            navctl: &navctl_new,
            out: &new_jsonl,
        },
    ];
    let summaries = scan(&targets, &plan, o.jobs)?;
    let report = diff::diff(&parse::load(&base_jsonl)?, &parse::load(&new_jsonl)?);
    let mut text = diff::render(&report, false);
    for (id, why) in &failed {
        text.push_str(&format!("not staged: {id}: {why}\n"));
    }
    for (s, which) in summaries.iter().zip(["base", "new"]) {
        for p in &s.failed_paths {
            text.push_str(&format!("navctl ({which}) failed on {}\n", p.display()));
        }
    }
    let report_path = out_dir.join("report.txt");
    std::fs::write(&report_path, &text).with_context(|| report_path.display().to_string())?;
    println!("\n{text}");
    println!("report: {}", report_path.display());
    let clean = failed.is_empty() && summaries.iter().all(|s| s.failed == 0);
    Ok(if clean && report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(diff::REGRESSION_EXIT)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benign::fetch::{bundle_commit, git_cmd};
    use crate::benign::manifest::Manifest;
    use crate::malware::hash::file_digest;
    use crate::malware::test_util::TempDir;

    fn item(kind: &str, url: &str) -> Item {
        let text = format!(
            "[[item]]\nid = \"a\"\ncategory = \"drm\"\nkind = \"{kind}\"\nurl = \"{url}\"\n"
        );
        Manifest::parse(&text).unwrap().items.remove(0)
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
    fn names_follow_the_url() {
        assert_eq!(
            published_name(&item("dmg", "https://e.com/A_1.dmg")),
            "A_1.dmg"
        );
        assert_eq!(
            published_name(&item("dmg", "https://e.com/download")),
            "download.dmg"
        );
        assert_eq!(published_name(&item("app", "https://e.com/get")), "get.zip");
        assert_eq!(
            published_name(&item("app", "https://e.com/App-2.1")),
            "App-2.1.zip"
        );
        assert_eq!(
            published_name(&item("pkg", "https://e.com/dl.php")),
            "dl.php.pkg"
        );
        assert_eq!(published_name(&item("dmg", "https://e.com/A.DMG")), "A.DMG");
        assert_eq!(
            published_name(&item("tar", "https://e.com/x.tar.xz")),
            "x.tar.xz"
        );
        assert_eq!(published_name(&item("tar", "https://e.com/x.tgz")), "x.tgz");
        assert_eq!(
            published_name(&item("tar", "https://e.com/x.gz")),
            "x.gz.tar"
        );
        assert_eq!(
            published_name(&item("script", "https://e.com/install")),
            "install"
        );
    }

    #[test]
    fn stages_downloads_and_checkouts() {
        let t = TempDir::new("benign-stage");
        let cache = t.path().join("cache");
        std::fs::create_dir_all(cache.join("git")).unwrap();

        let blob_src = t.path().join("blob");
        std::fs::write(&blob_src, "dmg bytes").unwrap();
        let m = file_digest(&blob_src).unwrap();
        std::fs::copy(&blob_src, cache.join(&m.sha256)).unwrap();

        let repo = t.path().join("up");
        std::fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "--quiet"]);
        std::fs::write(repo.join("f"), "x").unwrap();
        git(&repo, &["add", "f"]);
        git(&repo, &["commit", "--quiet", "-m", "one"]);
        let commit = git(&repo, &["rev-parse", "HEAD"]);
        let bundle = bundle_path(&cache, &commit);
        assert!(bundle_commit(&repo.to_string_lossy(), &commit, &bundle).is_ok());

        let text = format!(
            "[[item]]\nid = \"d\"\ncategory = \"drm\"\nkind = \"dmg\"\nurl = \"https://e.com/X.dmg\"\nsha256 = \"{}\"\nbytes = {}\n\n\
             [[item]]\nid = \"g\"\ncategory = \"dev-tools\"\nkind = \"git\"\nrepo = \"o/r\"\ncommit = \"{commit}\"\n\n\
             [[item]]\nid = \"u\"\ncategory = \"drm\"\nkind = \"zip\"\nurl = \"https://e.com/u.zip\"\n\n\
             [[item]]\nid = \"m\"\ncategory = \"drm\"\nkind = \"pkg\"\nurl = \"https://e.com/m.pkg\"\nsha256 = \"{}\"\nbytes = 1\n",
            m.sha256,
            m.bytes,
            "0".repeat(64)
        );
        let manifest = Manifest::parse(&text).unwrap();
        let items: Vec<&Item> = manifest.items.iter().collect();
        let root = t.path().join("stage");
        let (plan, failed) = stage(&items, &cache, &root).unwrap();

        assert_eq!(plan.chunks.len(), 2);
        assert_eq!(plan.chunks[0].path, root.join("d/X.dmg"));
        assert!(!plan.chunks[0].recursive);
        assert_eq!(
            std::fs::read_to_string(&plan.chunks[0].path).unwrap(),
            "dmg bytes"
        );
        assert_eq!(plan.chunks[1].path, root.join("g/repo"));
        assert!(plan.chunks[1].recursive);
        assert!(root.join("g/repo/f").is_file());
        assert!(!root.join("g/repo/.git").exists());
        let ids: Vec<&str> = failed.iter().map(|(i, _)| i.as_str()).collect();
        assert_eq!(ids, ["u", "m"]);
        assert!(failed[0].1.contains("recorded") && failed[1].1.contains("cache"));
        // A rerun starts clean.
        std::fs::write(root.join("d/stale"), "").unwrap();
        stage(&items, &cache, &root).unwrap();
        assert!(!root.join("d/stale").exists());
    }
}
