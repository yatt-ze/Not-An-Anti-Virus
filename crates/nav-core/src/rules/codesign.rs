//! Code-signing status (§5.2). Shells out to `codesign` for now; the full
//! design wants a Security.framework check via a Swift shim (§3). Non-macOS
//! reports `NotApplicable` rather than guessing.
//!
//! Per §5.1, "unsigned" alone is a small generic signal — significant only in
//! combination, which is the caller's job.

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::model::{MatchedSignal, SignalCategory};

pub struct UnsignedBinaryRule;

impl Default for UnsignedBinaryRule {
    fn default() -> Self {
        UnsignedBinaryRule
    }
}

impl Rule for UnsignedBinaryRule {
    fn id(&self) -> &'static str {
        "unsigned-binary"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::ProvenanceConcern
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        // Signing is a property of a file on disk; container-extracted content
        // has none, and its `ctx.path` is a label this crate invented.
        if !ctx.is_file_backed() {
            return Err(RuleOutcome::NotApplicable);
        }
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;

        // `codesign -dv` says "not signed at all" for anything it doesn't
        // recognize (text, tarball, `.pkg` — whose xar signature it can't
        // read), so gate on Mach-O magic first or the rule calls a README an
        // unsigned binary (§10/§11.8).
        if !crate::macho::is_macho_magic(content) {
            return Ok(None);
        }
        signing_status(&ctx.path)
    }
}

#[cfg(target_os = "macos")]
fn signing_status(path: &std::path::Path) -> Result<Option<MatchedSignal>, RuleOutcome> {
    use std::process::Command;

    let output = Command::new("codesign")
        .arg("-dv")
        .arg("--verbose=2")
        .arg(path)
        .output()
        .map_err(|_| RuleOutcome::NotApplicable)?;

    // `codesign -dv` exits non-zero for unsigned binaries *and* for genuine
    // errors, so match the specific "not signed" message, not the exit code.
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        return Ok(None); // signed; notarization status is a separate check
    }

    if stderr.contains("code object is not signed at all") {
        Ok(Some(MatchedSignal {
            id: "unsigned-binary".to_string(),
            weight: 4,
            description: "binary is not code-signed".to_string(),
            category: SignalCategory::ProvenanceConcern,
        }))
    } else {
        // codesign missing or some other inconclusive error — don't claim
        // "unsigned" for something we didn't determine.
        Err(RuleOutcome::NotApplicable)
    }
}

#[cfg(not(target_os = "macos"))]
fn signing_status(_path: &std::path::Path) -> Result<Option<MatchedSignal>, RuleOutcome> {
    Err(RuleOutcome::NotApplicable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContentSource, ScanContext};
    use std::path::PathBuf;

    fn ctx(name: &str, body: &[u8]) -> ScanContext {
        ScanContext {
            path: PathBuf::from(name),
            content: Some(body.to_vec()),
            truncated: false,
            file_len: Some(body.len() as u64),
            source: ContentSource::File,
        }
    }

    /// Without the Mach-O gate this rule fired on every non-binary file
    /// scanned, adding a permanent +4.
    #[test]
    fn things_that_are_not_code_objects_are_not_unsigned_binaries() {
        let cases: [(&str, &[u8]); 5] = [
            ("readme.txt", b"just some notes\n"),
            ("build.sh", b"#!/bin/sh\ncargo build\n"),
            ("archive.tar.gz", b"\x1f\x8b\x08\x00\x00\x00\x00\x00"),
            ("installer.pkg", b"xar!\x00\x1c\x00\x01"),
            ("empty", b""),
        ];
        for (name, body) in cases {
            assert!(
                matches!(UnsignedBinaryRule.evaluate(&ctx(name, body)), Ok(None)),
                "{name} is not a code object and must not be reported as an unsigned binary"
            );
        }
    }

    /// Content lifted out of a container has no file to ask about.
    #[test]
    fn embedded_content_is_not_applicable() {
        let c = ScanContext::from_embedded_bytes(
            "installer.pkg!Scripts/preinstall",
            b"#!/bin/sh\nexit 0\n".to_vec(),
            false,
        );
        assert!(matches!(
            UnsignedBinaryRule.evaluate(&c),
            Err(RuleOutcome::NotApplicable)
        ));
    }
}
