//! Reading `navctl scan --json` output back into [`ScanResult`]s.

use std::collections::BTreeSet;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use nav_core::model::ScanResult;
use nav_core::SCAN_JSON_SCHEMA_VERSION;

/// Parses JSONL from `reader`, skipping lines that don't start with `{`.
/// Errors on malformed JSON or any `schema_version` other than
/// [`SCAN_JSON_SCHEMA_VERSION`].
pub fn parse_jsonl(reader: impl BufRead) -> Result<Vec<ScanResult>> {
    let mut out = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let n = i + 1;
        let line = line.with_context(|| format!("reading line {n}"))?;
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).with_context(|| format!("line {n}: invalid JSON"))?;
        let version = value.get("schema_version").and_then(|v| v.as_u64());
        if version != Some(u64::from(SCAN_JSON_SCHEMA_VERSION)) {
            bail!(
                "line {n}: schema_version {version:?}, expected {SCAN_JSON_SCHEMA_VERSION}; \
                 rebuild both navctl binaries from compatible revisions"
            );
        }
        out.push(
            serde_json::from_value(value).with_context(|| format!("line {n}: not a ScanResult"))?,
        );
    }
    Ok(out)
}

/// [`parse_jsonl`] over the file at `path`.
pub fn load(path: &Path) -> Result<Vec<ScanResult>> {
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    parse_jsonl(std::io::BufReader::new(f)).with_context(|| path.display().to_string())
}

/// Scan targets that `<jsonl>.err` records as stopped by navctl's walk
/// budget (exit 3 with "scan budget reached"). No `.err` file means none.
pub fn load_budget_stopped(jsonl: &Path) -> Result<BTreeSet<PathBuf>> {
    let err = PathBuf::from(format!("{}.err", jsonl.display()));
    match std::fs::read_to_string(&err) {
        Ok(text) => Ok(budget_stopped(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(e).with_context(|| err.display().to_string()),
    }
}

/// Parses `.err` records (`path:` / `exit:` / `stderr:` lines, as
/// `scan::run_chunk` writes them) for budget-stopped targets.
pub fn budget_stopped(err_text: &str) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    let lines: Vec<&str> = err_text.lines().collect();
    let starts: Vec<usize> = (0..lines.len())
        .filter(|&i| {
            lines[i].starts_with("path: ")
                && lines.get(i + 1).is_some_and(|l| l.starts_with("exit: "))
        })
        .collect();
    for (k, &i) in starts.iter().enumerate() {
        let end = starts.get(k + 1).copied().unwrap_or(lines.len());
        let record = &lines[i..end];
        let exit_3 = record[1] == "exit: 3";
        let stopped = record[2..]
            .iter()
            .any(|l| l.contains("scan budget reached"));
        if exit_3 && stopped {
            out.insert(PathBuf::from(&record[0]["path: ".len()..]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = r#"{"schema_version":1,"path":"/a","score":3,"confidence":"low","completeness":"complete","signals":[],"recommendation":"no-action","engine_version":"x","evaluated_at":0}"#;

    #[test]
    fn skips_non_json_lines() {
        let input = format!("warning: something\n\n{LINE}\n  \nnote\n{LINE}\n");
        let rs = parse_jsonl(input.as_bytes()).unwrap();
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].score, 3);
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let bad = LINE.replace("\"schema_version\":1", "\"schema_version\":999");
        let err = parse_jsonl(bad.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("schema_version"), "{err}");
    }

    #[test]
    fn rejects_missing_schema_version() {
        let bad = LINE.replace("\"schema_version\":1,", "");
        assert!(parse_jsonl(bad.as_bytes()).is_err());
    }

    #[test]
    fn budget_stopped_keeps_only_exit_3_budget_records() {
        let err = "\
path: /Applications/Xcode.app
exit: 3
stderr: navctl: partial coverage — scan budget reached (max-files); more of /Applications/Xcode.app was not scanned

path: /usr/bin
exit: 3
stderr: navctl: /usr/bin/x: not fully checked
second stderr line

path: /opt/crashed
exit: 4
stderr: navctl: partial coverage — scan budget reached (max-files); more of /opt/crashed was not scanned

path: /Users/me/Cities.app
exit: 3
stderr: navctl: something first
navctl: partial coverage — scan budget reached (max-total-bytes); more of /Users/me/Cities.app was not scanned
";
        let got: Vec<_> = budget_stopped(err).into_iter().collect();
        assert_eq!(
            got,
            vec![
                PathBuf::from("/Applications/Xcode.app"),
                PathBuf::from("/Users/me/Cities.app"),
            ]
        );
    }

    #[test]
    fn budget_stopped_of_empty_text_is_empty() {
        assert!(budget_stopped("").is_empty());
    }
}
