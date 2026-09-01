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

/// Weight for a binary carrying a hand-applied ad-hoc signature — no real
/// identity, but not as bare as `unsigned-binary`'s "no signature at all".
const ADHOC_MANUAL_WEIGHT: i32 = 3;

/// Notes a binary signed ad-hoc *by hand* (`codesign -s -`), as distinct
/// from the linker-applied ad-hoc signature every Apple Silicon binary
/// carries by default. The latter is scored nowhere — see `DvStatus`.
pub struct AdHocSignedRule;

impl Default for AdHocSignedRule {
    fn default() -> Self {
        AdHocSignedRule
    }
}

impl Rule for AdHocSignedRule {
    fn id(&self) -> &'static str {
        "adhoc-signed-binary"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::ProvenanceConcern
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        if !ctx.is_file_backed() {
            return Err(RuleOutcome::NotApplicable);
        }
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;
        if !crate::macho::is_macho_magic(content) {
            return Ok(None);
        }

        if run_codesign_dv(&ctx.path)? == DvStatus::AdHocManual {
            Ok(Some(MatchedSignal {
                id: "adhoc-signed-binary".to_string(),
                weight: ADHOC_MANUAL_WEIGHT,
                description: "binary carries a hand-applied ad-hoc signature (no identity)"
                    .to_string(),
                category: SignalCategory::ProvenanceConcern,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Weight for a revoked code-signing certificate. Apple revokes Developer ID
/// certs almost exclusively in response to confirmed abuse, so — unlike a
/// bare `unsigned-binary` — this is a narrow, high-specificity signal (§5.1)
/// rather than a broad "trust me less" category.
const REVOKED_CERT_WEIGHT: i32 = 14;

/// Notes a binary whose (real, non-ad-hoc) signing certificate has been
/// revoked since it was signed. Only meaningful for a real identity — an
/// unsigned or ad-hoc binary has no certificate to revoke, so this rule
/// doesn't even ask about those.
pub struct RevokedSignatureRule;

impl Default for RevokedSignatureRule {
    fn default() -> Self {
        RevokedSignatureRule
    }
}

impl Rule for RevokedSignatureRule {
    fn id(&self) -> &'static str {
        "revoked-code-signature"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::TrustReduction
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        if !ctx.is_file_backed() {
            return Err(RuleOutcome::NotApplicable);
        }
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;
        if !crate::macho::is_macho_magic(content) {
            return Ok(None);
        }

        // Revocation is a property of a real certificate; unsigned/ad-hoc
        // binaries have none, so don't spend a `codesign --verify` call on them.
        if run_codesign_dv(&ctx.path)? != DvStatus::Signed {
            return Ok(None);
        }

        if run_codesign_verify(&ctx.path)? {
            Ok(Some(MatchedSignal {
                id: "revoked-code-signature".to_string(),
                weight: REVOKED_CERT_WEIGHT,
                description: "code-signing certificate has been revoked".to_string(),
                category: SignalCategory::TrustReduction,
            }))
        } else {
            Ok(None)
        }
    }
}

/// Runs `codesign --verify` and reports whether the failure was specifically
/// a revoked certificate, as opposed to any other reason verification failed
/// (modified resource, broken seal, …) — those aren't this rule's claim to make.
fn run_codesign_verify(path: &std::path::Path) -> Result<bool, RuleOutcome> {
    let stderr = spawn_codesign_verify(path)?;
    Ok(indicates_revocation(&stderr))
}

fn indicates_revocation(stderr: &str) -> bool {
    // Covers both the literal CSSMERR_TP_CERT_REVOKED constant `codesign`
    // reports and any future rewording that still says "revoked".
    stderr.to_lowercase().contains("revoked")
}

#[cfg(target_os = "macos")]
fn spawn_codesign_verify(path: &std::path::Path) -> Result<String, RuleOutcome> {
    use std::process::Command;

    // `--verify` writes its report to stderr too; exit status alone doesn't
    // distinguish "revoked" from "tampered" from "missing resource".
    let output = Command::new("codesign")
        .arg("--verify")
        .arg("--deep")
        .arg("--strict")
        .arg("-v")
        .arg(path)
        .output()
        .map_err(|_| RuleOutcome::NotApplicable)?;

    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn spawn_codesign_verify(_path: &std::path::Path) -> Result<String, RuleOutcome> {
    Err(RuleOutcome::NotApplicable)
}

/// Weight for a real-identity-signed binary that hasn't been notarized.
/// Small — plenty of legitimate CLI tools and direct-distribution software
/// (most of the Homebrew/Rust/Go corpus §12 tests against) never goes
/// through notarization at all.
const UNNOTARIZED_WEIGHT: i32 = 2;

/// Negative: notarization is a *contributing* negative signal (§5.2), not an
/// automatic benign override, so it nudges the score down rather than
/// zeroing or capping it.
const NOTARIZED_WEIGHT: i32 = -3;

/// Notes a real-identity-signed binary that has not been notarized by Apple.
pub struct UnnotarizedSignedRule;

impl Default for UnnotarizedSignedRule {
    fn default() -> Self {
        UnnotarizedSignedRule
    }
}

impl Rule for UnnotarizedSignedRule {
    fn id(&self) -> &'static str {
        "signed-not-notarized"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::ProvenanceConcern
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        if !ctx.is_file_backed() {
            return Err(RuleOutcome::NotApplicable);
        }
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;
        if !crate::macho::is_macho_magic(content) {
            return Ok(None);
        }
        // Notarization presupposes a real identity to submit for notarization.
        if run_codesign_dv(&ctx.path)? != DvStatus::Signed {
            return Ok(None);
        }

        match run_spctl_source(&ctx.path)?.as_deref() {
            Some(source) if notarization_from_source(source) == Some(false) => {
                Ok(Some(MatchedSignal {
                    id: "signed-not-notarized".to_string(),
                    weight: UNNOTARIZED_WEIGHT,
                    description: "binary is signed but has not been notarized by Apple".to_string(),
                    category: SignalCategory::ProvenanceConcern,
                }))
            }
            _ => Ok(None),
        }
    }
}

/// Notes a binary that Apple has notarized — a contributing negative signal
/// (§5.2), not an automatic benign override, so a notarized binary exhibiting
/// otherwise-suspicious behavior is still scoreable.
pub struct NotarizedRule;

impl Default for NotarizedRule {
    fn default() -> Self {
        NotarizedRule
    }
}

impl Rule for NotarizedRule {
    fn id(&self) -> &'static str {
        "notarized-binary"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::Informational
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        if !ctx.is_file_backed() {
            return Err(RuleOutcome::NotApplicable);
        }
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;
        if !crate::macho::is_macho_magic(content) {
            return Ok(None);
        }
        if run_codesign_dv(&ctx.path)? != DvStatus::Signed {
            return Ok(None);
        }

        match run_spctl_source(&ctx.path)?.as_deref() {
            Some(source) if notarization_from_source(source) == Some(true) => {
                Ok(Some(MatchedSignal {
                    id: "notarized-binary".to_string(),
                    weight: NOTARIZED_WEIGHT,
                    description: "binary is signed and notarized by Apple".to_string(),
                    category: SignalCategory::Informational,
                }))
            }
            _ => Ok(None),
        }
    }
}

/// `Some(true)` notarized, `Some(false)` signed but not notarized, `None` for
/// any other `spctl` source (Apple System, Mac App Store, …) — notarization
/// isn't a meaningful concept for those, so this stays silent rather than
/// guessing (§10, §11.8).
fn notarization_from_source(source: &str) -> Option<bool> {
    match source {
        "Notarized Developer ID" => Some(true),
        // Older macOS reports plain "Developer ID" for accepted-but-unnotarized
        // assessments; newer macOS spells the rejected case out explicitly.
        "Developer ID" | "Unnotarized Developer ID" => Some(false),
        _ => None,
    }
}

/// Runs `spctl -a -t exec` and pulls out its `source=` line, if any.
fn run_spctl_source(path: &std::path::Path) -> Result<Option<String>, RuleOutcome> {
    let output = spawn_spctl_assess(path)?;
    Ok(parse_spctl_source(&output).map(str::to_string))
}

fn parse_spctl_source(output: &str) -> Option<&str> {
    output
        .lines()
        .find_map(|l| l.trim().strip_prefix("source="))
}

#[cfg(target_os = "macos")]
fn spawn_spctl_assess(path: &std::path::Path) -> Result<String, RuleOutcome> {
    use std::process::Command;

    // `spctl -a` writes its assessment (including `source=`) to stderr.
    let output = Command::new("spctl")
        .arg("-a")
        .arg("-t")
        .arg("exec")
        .arg("-vv")
        .arg(path)
        .output()
        .map_err(|_| RuleOutcome::NotApplicable)?;

    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn spawn_spctl_assess(_path: &std::path::Path) -> Result<String, RuleOutcome> {
    Err(RuleOutcome::NotApplicable)
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

    /// Same gate as `unsigned-binary` — a non-code-object is never ad-hoc.
    #[test]
    fn things_that_are_not_code_objects_are_not_adhoc_signed() {
        assert!(matches!(
            AdHocSignedRule.evaluate(&ctx("readme.txt", b"just some notes\n")),
            Ok(None)
        ));
    }

    #[test]
    fn things_that_are_not_code_objects_are_not_revoked() {
        assert!(matches!(
            RevokedSignatureRule.evaluate(&ctx("readme.txt", b"just some notes\n")),
            Ok(None)
        ));
    }

    #[test]
    fn indicates_revocation_matches_the_real_error_constant() {
        assert!(indicates_revocation(
            "test-binary: CSSMERR_TP_CERT_REVOKED\n"
        ));
    }

    #[test]
    fn indicates_revocation_is_false_for_a_clean_verify() {
        assert!(!indicates_revocation(
            "test-binary: valid on disk\ntest-binary: satisfies its Designated Requirement\n"
        ));
    }

    /// A verify failure for an unrelated reason (tampered resource, broken
    /// seal, …) is not this rule's claim to make — don't say "revoked".
    #[test]
    fn indicates_revocation_is_false_for_an_unrelated_verify_failure() {
        assert!(!indicates_revocation(
            "test-binary: a sealed resource is missing or invalid\n"
        ));
    }

    #[test]
    fn things_that_are_not_code_objects_are_not_scored_for_notarization() {
        assert!(matches!(
            UnnotarizedSignedRule.evaluate(&ctx("readme.txt", b"just some notes\n")),
            Ok(None)
        ));
        assert!(matches!(
            NotarizedRule.evaluate(&ctx("readme.txt", b"just some notes\n")),
            Ok(None)
        ));
    }

    #[test]
    fn parse_spctl_source_reads_the_source_line() {
        let out = "/tmp/App.app: accepted\n\
             source=Notarized Developer ID\n\
             origin=Developer ID Application: Example Corp (TEAMID1234)\n";
        assert_eq!(parse_spctl_source(out), Some("Notarized Developer ID"));
    }

    #[test]
    fn parse_spctl_source_is_none_without_a_source_line() {
        assert_eq!(parse_spctl_source("/tmp/x: rejected\n"), None);
    }

    #[test]
    fn notarization_from_source_classifies_known_sources() {
        assert_eq!(
            notarization_from_source("Notarized Developer ID"),
            Some(true)
        );
        assert_eq!(notarization_from_source("Developer ID"), Some(false));
        assert_eq!(
            notarization_from_source("Unnotarized Developer ID"),
            Some(false)
        );
    }

    /// Apple System and Mac App Store binaries aren't a "signed but not
    /// notarized" case — the concept doesn't apply, so stay silent.
    #[test]
    fn notarization_from_source_is_none_for_apple_and_app_store_sources() {
        assert_eq!(notarization_from_source("Apple System"), None);
        assert_eq!(notarization_from_source("Mac App Store"), None);
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
