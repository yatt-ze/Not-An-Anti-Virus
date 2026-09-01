//! Code-signing status (§5.2). Shells out to `codesign` for now; the full
//! design wants a Security.framework check via a Swift shim (§3). Non-macOS
//! reports `NotApplicable` rather than guessing.
//!
//! Per §5.1, "unsigned" alone is a small generic signal — significant only in
//! combination, which is the caller's job.

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::model::{MatchedSignal, SignalCategory};

/// What `codesign -dv` says about a code object's signature. Doesn't yet say
/// anything about revocation or notarization — those are separate checks
/// layered on top of `Signed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DvStatus {
    Unsigned,
    /// Ad-hoc, self-applied by hand (`codesign -s -`) — carries no identity.
    AdHocManual,
    /// Ad-hoc, but stamped on automatically by the linker at build time.
    /// Every Apple Silicon binary gets one of these; it says nothing about
    /// provenance and must not be scored the same as a manual ad-hoc sign.
    AdHocLinkerSigned,
    /// A real (non-ad-hoc) identity — Developer ID, Apple, or otherwise.
    Signed,
}

/// Parses `codesign -dv --verbose=4` output. `codesign -dv` writes its report
/// to stderr, not stdout, regardless of exit status.
fn classify_dv(success: bool, stderr: &str) -> Result<DvStatus, RuleOutcome> {
    if success {
        return Ok(if stderr.contains("Signature=adhoc") {
            if stderr.contains("linker-signed") {
                DvStatus::AdHocLinkerSigned
            } else {
                DvStatus::AdHocManual
            }
        } else {
            DvStatus::Signed
        });
    }
    // `codesign -dv` exits non-zero for unsigned binaries *and* for genuine
    // errors, so match the specific "not signed" message, not the exit code.
    if stderr.contains("code object is not signed at all") {
        Ok(DvStatus::Unsigned)
    } else {
        // codesign missing or some other inconclusive error — don't claim
        // a status we didn't actually determine.
        Err(RuleOutcome::NotApplicable)
    }
}

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

        if run_codesign_dv(&ctx.path)? == DvStatus::Unsigned {
            Ok(Some(MatchedSignal {
                id: "unsigned-binary".to_string(),
                weight: 4,
                description: "binary is not code-signed".to_string(),
                category: SignalCategory::ProvenanceConcern,
            }))
        } else {
            Ok(None) // signed (ad-hoc or real) — other rules' concern
        }
    }
}

/// Runs `codesign -dv` and classifies the result. The classification logic
/// (`classify_dv`) is platform-independent and unit-tested directly; only the
/// process spawn is behind the platform gate.
fn run_codesign_dv(path: &std::path::Path) -> Result<DvStatus, RuleOutcome> {
    let (success, stderr) = spawn_codesign_dv(path)?;
    classify_dv(success, &stderr)
}

#[cfg(target_os = "macos")]
fn spawn_codesign_dv(path: &std::path::Path) -> Result<(bool, String), RuleOutcome> {
    use std::process::Command;

    // `codesign -dv` writes its report to stderr regardless of exit status.
    let output = Command::new("codesign")
        .arg("-dv")
        .arg("--verbose=4")
        .arg(path)
        .output()
        .map_err(|_| RuleOutcome::NotApplicable)?;

    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

#[cfg(not(target_os = "macos"))]
fn spawn_codesign_dv(_path: &std::path::Path) -> Result<(bool, String), RuleOutcome> {
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

    #[test]
    fn classify_dv_unsigned() {
        let stderr = "/tmp/x: code object is not signed at all\n";
        assert_eq!(classify_dv(false, stderr), Ok(DvStatus::Unsigned));
    }

    #[test]
    fn classify_dv_other_failure_is_not_applicable() {
        let stderr = "codesign: /tmp/x: no such file\n";
        assert_eq!(classify_dv(false, stderr), Err(RuleOutcome::NotApplicable));
    }

    #[test]
    fn classify_dv_real_identity() {
        let stderr = "Executable=/tmp/x\n\
             Authority=Developer ID Application: Example Corp (TEAMID1234)\n\
             Authority=Developer ID Certification Authority\n\
             Authority=Apple Root CA\n";
        assert_eq!(classify_dv(true, stderr), Ok(DvStatus::Signed));
    }

    #[test]
    fn classify_dv_manual_adhoc() {
        // `codesign -s -` after the fact: no linker-signed flag.
        let stderr = "Executable=/tmp/x\n\
             CodeDirectory v=20400 size=... flags=0x2(adhoc) hashes=...\n\
             Signature=adhoc\n";
        assert_eq!(classify_dv(true, stderr), Ok(DvStatus::AdHocManual));
    }

    #[test]
    fn classify_dv_linker_signed_adhoc() {
        // Every Apple Silicon binary looks like this out of the linker —
        // must not be conflated with a hand-applied ad-hoc signature.
        let stderr = "Executable=/tmp/x\n\
             CodeDirectory v=20400 size=... flags=0x20002(adhoc,linker-signed) hashes=...\n\
             Signature=adhoc\n";
        assert_eq!(classify_dv(true, stderr), Ok(DvStatus::AdHocLinkerSigned));
    }
}
