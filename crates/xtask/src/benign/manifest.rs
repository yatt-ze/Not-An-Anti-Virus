//! The committed benign survey manifest (§11.1b): parsing, validation, and
//! the line-level rewrite behind `fetch --record`.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;

use crate::vm::validate_sha;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(rename = "item")]
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    AdminScripts,
    DevTools,
    Drm,
    Credentials,
    Messaging,
    SecurityAgent,
    RemoteAccess,
    Installer,
}

impl Category {
    /// The manifest spelling.
    pub fn label(self) -> &'static str {
        match self {
            Category::AdminScripts => "admin-scripts",
            Category::DevTools => "dev-tools",
            Category::Drm => "drm",
            Category::Credentials => "credentials",
            Category::Messaging => "messaging",
            Category::SecurityAgent => "security-agent",
            Category::RemoteAccess => "remote-access",
            Category::Installer => "installer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Dmg,
    Pkg,
    Zip,
    Tar,
    /// A zipped `.app`, unpacked like `zip`.
    App,
    Script,
    Git,
}

impl Kind {
    /// The manifest spelling.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Dmg => "dmg",
            Kind::Pkg => "pkg",
            Kind::Zip => "zip",
            Kind::Tar => "tar",
            Kind::App => "app",
            Kind::Script => "script",
            Kind::Git => "git",
        }
    }
}

/// One survey item. A `url` item carries `sha256` and `bytes` once recorded;
/// a `git` item carries `repo` and `commit` instead.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub id: String,
    pub category: Category,
    pub kind: Kind,
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub bytes: Option<u64>,
    /// GitHub `owner/name`, `git` items only.
    pub repo: Option<String>,
    pub commit: Option<String>,
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_repo(repo: &str) -> bool {
    let part = |p: &str| {
        !matches!(p, "" | "." | "..")
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    matches!(repo.split_once('/'), Some((o, n)) if part(o) && part(n))
}

impl Item {
    /// True once `sha256` and `bytes` are both set (or for a `git` item).
    pub fn recorded(&self) -> bool {
        self.kind == Kind::Git || (self.sha256.is_some() && self.bytes.is_some())
    }

    fn validate(&self) -> Result<()> {
        ensure!(valid_id(&self.id), "id {:?} must match [a-z0-9-]+", self.id);
        if self.kind == Kind::Git {
            ensure!(
                self.url.is_none() && self.sha256.is_none() && self.bytes.is_none(),
                "git items take repo and commit, not url, sha256 or bytes"
            );
            let (Some(repo), Some(commit)) = (&self.repo, &self.commit) else {
                bail!("git items need both repo and commit");
            };
            ensure!(valid_repo(repo), "repo {repo:?} must be GitHub owner/name");
            validate_sha(commit)?;
            return Ok(());
        }
        ensure!(
            self.repo.is_none() && self.commit.is_none(),
            "repo and commit are only for kind git"
        );
        let url = self.url.as_deref().context("missing url")?;
        ensure!(
            url.starts_with("https://")
                && url.len() > "https://".len()
                && !url.bytes().any(|b| b.is_ascii_control() || b == b' '),
            "url {url:?} must be a plain https:// URL"
        );
        match (&self.sha256, self.bytes) {
            (Some(h), Some(b)) => {
                ensure!(is_hex(h, 64), "sha256 must be 64 lowercase hex digits");
                ensure!(b > 0, "bytes must be positive");
            }
            (None, None) => {}
            _ => bail!("sha256 and bytes must be recorded together"),
        }
        Ok(())
    }
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Manifest> {
        let m: Manifest = toml::from_str(text).context("parsing benign manifest")?;
        ensure!(!m.items.is_empty(), "benign manifest has no items");
        let mut seen = HashSet::new();
        for it in &m.items {
            it.validate().with_context(|| format!("item {:?}", it.id))?;
            ensure!(seen.insert(&it.id), "duplicate id {:?}", it.id);
        }
        Ok(m)
    }

    pub fn load(path: &Path) -> Result<Manifest> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Manifest::parse(&text).with_context(|| path.display().to_string())
    }
}

/// The key of a `key = value` line, if it is one.
fn line_key(line: &str) -> Option<&str> {
    let (k, _) = line.split_once('=')?;
    let k = k.trim();
    (!k.is_empty() && !k.starts_with(['#', '[']) && !k.contains(' ')).then_some(k)
}

/// `text` with `sha256` and `bytes` set on item `id`, keeping every other
/// line, comment and the item order. New lines go after the item's `url`.
pub fn record_text(text: &str, id: &str, sha256: &str, bytes: u64) -> Result<String> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let section = |l: &str| l.trim_start().starts_with('[');
    let id_line = |l: &str| {
        line_key(l) == Some("id")
            && l.split_once('=')
                .is_some_and(|(_, v)| v.trim().trim_matches('"') == id)
    };
    let mut found = None;
    for (i, l) in lines.iter().enumerate() {
        if l.trim() == "[[item]]" {
            let end = lines[i + 1..]
                .iter()
                .position(|l| section(l))
                .map_or(lines.len(), |n| i + 1 + n);
            if lines[i + 1..end].iter().any(|l| id_line(l)) {
                found = Some((i + 1, end));
                break;
            }
        }
    }
    let (start, end) = found.with_context(|| format!("no item {id:?} in the manifest"))?;
    let mut out: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    let (mut sha_at, mut bytes_at, mut url_at) = (None, None, None);
    for (i, l) in lines.iter().enumerate().take(end).skip(start) {
        match line_key(l) {
            Some("sha256") => sha_at = Some(i),
            Some("bytes") => bytes_at = Some(i),
            Some("url") => url_at = Some(i),
            _ => {}
        }
    }
    let sha_line = format!("sha256 = \"{sha256}\"\n");
    let bytes_line = format!("bytes = {bytes}\n");
    match (sha_at, bytes_at) {
        (Some(s), Some(b)) => {
            out[s] = sha_line;
            out[b] = bytes_line;
        }
        _ => {
            for at in [sha_at, bytes_at].into_iter().flatten() {
                out[at] = String::new();
            }
            let url_at = url_at.with_context(|| format!("item {id:?} has no url line"))?;
            if !out[url_at].ends_with('\n') {
                out[url_at].push('\n');
            }
            out[url_at].push_str(&sha_line);
            out[url_at].push_str(&bytes_line);
        }
    }
    let new = out.concat();
    Manifest::parse(&new).context("rewritten manifest no longer validates")?;
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const C: &str = "6013fa5e6ef57fc599ba1cb7f727dd8fea963c90";

    fn url_item(extra: &str) -> String {
        format!(
            "[[item]]\nid = \"a-1\"\ncategory = \"installer\"\nkind = \"pkg\"\nurl = \"https://e.com/a.pkg\"\n{extra}"
        )
    }

    fn err(text: &str) -> String {
        format!("{:#}", Manifest::parse(text).unwrap_err())
    }

    #[test]
    fn accepts_valid_items() {
        let text = format!(
            "{}\n[[item]]\nid = \"g\"\ncategory = \"admin-scripts\"\nkind = \"git\"\nrepo = \"o/r.x\"\ncommit = \"{C}\"\n",
            url_item(&format!("sha256 = \"{H}\"\nbytes = 3\n"))
        );
        let m = Manifest::parse(&text).unwrap();
        assert_eq!(m.items.len(), 2);
        assert!(m.items.iter().all(Item::recorded));
        let unrecorded = Manifest::parse(&url_item("")).unwrap();
        assert!(!unrecorded.items[0].recorded());
    }

    #[test]
    fn rejects_bad_ids() {
        assert!(err(&url_item("").replace("a-1", "A_1")).contains("[a-z0-9-]+"));
        let dup = format!("{}{}", url_item(""), url_item(""));
        assert!(err(&dup).contains("duplicate"));
    }

    #[test]
    fn rejects_bad_urls() {
        for bad in [
            "http://e.com/a",
            "https://",
            "ftp://e.com",
            "https://e.com/a b",
        ] {
            let t = url_item("").replace("https://e.com/a.pkg", bad);
            assert!(err(&t).contains("https"), "{bad}");
        }
    }

    #[test]
    fn rejects_bad_hashes() {
        assert!(err(&url_item(&format!("sha256 = \"{H}\"\n"))).contains("together"));
        assert!(err(&url_item("sha256 = \"ab\"\nbytes = 1\n")).contains("64"));
        let upper = H.to_uppercase();
        assert!(err(&url_item(&format!("sha256 = \"{upper}\"\nbytes = 1\n"))).contains("64"));
        assert!(err(&url_item(&format!("sha256 = \"{H}\"\nbytes = 0\n"))).contains("positive"));
    }

    #[test]
    fn kind_source_agreement() {
        let git = |extra: &str| {
            format!("[[item]]\nid = \"g\"\ncategory = \"dev-tools\"\nkind = \"git\"\n{extra}")
        };
        assert!(err(&git("repo = \"o/r\"\n")).contains("both"));
        let short = format!("repo = \"o/r\"\ncommit = \"{}\"\n", &C[..39]);
        assert!(err(&git(&short)).contains("40-hex"));
        let bad_repo = format!("repo = \"../r\"\ncommit = \"{C}\"\n");
        assert!(err(&git(&bad_repo)).contains("owner/name"));
        let with_url = format!("repo = \"o/r\"\ncommit = \"{C}\"\nurl = \"https://e.com\"\n");
        assert!(err(&git(&with_url)).contains("not url"));
        let url_with_repo = url_item(&format!("repo = \"o/r\"\ncommit = \"{C}\"\n"));
        assert!(err(&url_with_repo).contains("only for"));
        let no_url = "[[item]]\nid = \"a\"\ncategory = \"drm\"\nkind = \"zip\"\n";
        assert!(err(no_url).contains("url"));
    }

    #[test]
    fn rejects_unknowns() {
        assert!(err(&url_item("extra = 1\n")).contains("extra"));
        assert!(err(&url_item("").replace("installer", "games")).contains("games"));
        assert!(Manifest::parse("").is_err());
    }

    #[test]
    fn record_inserts_after_url() {
        let text = format!(
            "# top\n{}# keep me\n\n[[item]]\nid = \"b\"\ncategory = \"drm\"\nkind = \"zip\"\nurl = \"https://e.com/b.zip\"",
            url_item("")
        );
        let out = record_text(&text, "b", H, 9).unwrap();
        assert!(out.starts_with("# top\n"));
        assert!(out.contains("# keep me\n"));
        assert!(out.ends_with(&format!("zip\"\nsha256 = \"{H}\"\nbytes = 9\n")));
        let m = Manifest::parse(&out).unwrap();
        assert!(m.items[0].sha256.is_none());
        assert_eq!(m.items[1].bytes, Some(9));
    }

    #[test]
    fn record_replaces_in_place() {
        let h2 = "f".repeat(64);
        let text = format!(
            "{}# note\n{}",
            url_item(&format!("sha256 = \"{H}\"\nbytes = 3\n")),
            url_item("").replace("a-1", "a-2")
        );
        let out = record_text(&text, "a-1", &h2, 7).unwrap();
        assert!(out.contains(&format!("sha256 = \"{h2}\"\nbytes = 7\n# note\n")));
        assert!(!out.contains(H));
        let m = Manifest::parse(&out).unwrap();
        assert!(m.items[1].sha256.is_none());
        assert!(record_text(&text, "nope", &h2, 7).is_err());
    }

    #[test]
    fn committed_manifest_parses() {
        let path = crate::malware::real_world_dir().join("benign.toml");
        Manifest::load(&path).unwrap();
    }
}
