//! Reading `navctl scan --json` output back into [`ScanResult`]s.

use std::io::BufRead;
use std::path::Path;

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
}
