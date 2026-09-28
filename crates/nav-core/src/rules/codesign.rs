//! Code-signing status (§5.2). Shells out to `codesign` for now; the full
//! design wants a Security.framework check via a Swift shim (§3). Non-macOS
//! reports `NotApplicable` rather than guessing.
//!
//! Per §5.1, "unsigned" alone is a small generic signal — significant only in
//! combination, which is the caller's job.

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::macho::{CS_ADHOC, CS_LINKER_SIGNED};
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

/// False if `path`'s string form contains a newline or carriage return. Both
/// `codesign` and `spctl` echo the scanned path back into the stderr we parse
/// line-anchored; a path containing a line break could forge an extra line
/// (e.g. a fake `source=` or `CodeDirectory` line) (§11.9/#31). Callers treat
/// a `false` result as "couldn't check" (§11.8), never "clean".
fn path_is_line_safe(path: &std::path::Path) -> bool {
    let s = path.to_string_lossy();
    !s.contains('\n') && !s.contains('\r')
}

/// Finds the sole line in `codesign -dv --verbose=4` output that starts with
/// `CodeDirectory `. Real output for a code object carries exactly one; a
/// signer-chosen field that embeds a newline (e.g. `codesign -i`'s identifier)
/// can echo a second line shaped like it, so anything but exactly one is
/// forged, not parsed — `None` (§11.9/#31).
fn single_code_directory_line(stderr: &str) -> Option<&str> {
    let mut lines = stderr
        .lines()
        .filter(|line| line.trim_start().starts_with("CodeDirectory "));
    let only = lines.next()?;
    lines.next().is_none().then_some(only)
}

/// Parses the numeric `flags=0x<hex>` token off a `CodeDirectory` line.
fn code_directory_flags(code_directory_line: &str) -> Option<u32> {
    code_directory_line
        .split("flags=0x")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_hexdigit()).next())
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
}

/// True if `code_directory_line` (the sole `CodeDirectory` line, see
/// [`single_code_directory_line`]) carries the linker-applied ad-hoc
/// signature, as opposed to a hand-applied one. Prefers parsing its numeric
/// `flags=0x<hex>` token and testing `CS_LINKER_SIGNED`; falls back to a
/// textual `"linker-signed"` match on the line when the token is missing or
/// malformed.
fn is_linker_signed(code_directory_line: &str) -> bool {
    code_directory_flags(code_directory_line)
        .map(|flags| flags & CS_LINKER_SIGNED != 0)
        .unwrap_or_else(|| code_directory_line.contains("linker-signed"))
}

/// Parses `codesign -dv --verbose=4` output. `codesign -dv` writes its report
/// to stderr, not stdout, regardless of exit status. Line-anchored (§11.9/#31)
/// since `codesign` echoes the scanned path (e.g. `Executable=<path>`) into
/// the same stream, and a crafted filename must not be able to forge a match.
///
/// A signer-chosen field can go further and inject a whole extra
/// `CodeDirectory `-prefixed line (a multi-line `-i` identifier); requiring
/// exactly one such line before trusting its flags closes that gap (#31).
fn classify_dv(success: bool, stderr: &str) -> Result<DvStatus, RuleOutcome> {
    if success {
        let cd_line = single_code_directory_line(stderr).ok_or(RuleOutcome::NotApplicable)?;
        return Ok(match code_directory_flags(cd_line) {
            // Numeric flags parsed: ad-hoc/linker-signed come straight from
            // the bits — the `Signature=adhoc` line is not consulted.
            Some(flags) if flags & CS_ADHOC == 0 => DvStatus::Signed,
            Some(flags) if flags & CS_LINKER_SIGNED != 0 => DvStatus::AdHocLinkerSigned,
            Some(_) => DvStatus::AdHocManual,
            // Flags token missing or malformed: fall back to the textual
            // markers, as before #31's hardening.
            None => {
                let is_adhoc = stderr.lines().any(|line| line.trim() == "Signature=adhoc");
                if !is_adhoc {
                    DvStatus::Signed
                } else if is_linker_signed(cd_line) {
                    DvStatus::AdHocLinkerSigned
                } else {
                    DvStatus::AdHocManual
                }
            }
        });
    }
    // `codesign -dv` exits non-zero for unsigned binaries *and* for genuine
    // errors, so match the specific "not signed" message, not the exit code.
    let is_unsigned = stderr.lines().any(|line| {
        let line = line.trim();
        line == "code object is not signed at all"
            || line.ends_with(": code object is not signed at all")
    });
    if is_unsigned {
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
        if ctx.content.is_none() {
            return Err(RuleOutcome::NotApplicable);
        }

        // `codesign -dv` says "not signed at all" for anything it doesn't
        // recognize (text, tarball, `.pkg` — whose xar signature it can't
        // read), so gate on `ctx.macho()` first or the rule calls a README
        // an unsigned binary (§10/§11.8).
        if !ctx.macho().is_macho {
            return Ok(None);
        }

        if run_codesign_dv(ctx)? == DvStatus::Unsigned {
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

    /// `ctx.macho()` is only consulted for the Mach-O gate; the verdict
    /// itself comes from `codesign` run on the whole file.
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        true
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
        if ctx.content.is_none() {
            return Err(RuleOutcome::NotApplicable);
        }
        if !ctx.macho().is_macho {
            return Ok(None);
        }

        if run_codesign_dv(ctx)? == DvStatus::AdHocManual {
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

    /// Same as `UnsignedBinaryRule`: `ctx.macho()` only gates.
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        true
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
///
/// Chain revocation (OCSP) is primarily Gatekeeper/`spctl`'s job; `codesign
/// --verify`'s revocation reporting is best-effort and depends on
/// cached/online revocation state. This rule only reports a revocation
/// `codesign` actually surfaces — a clean verify is not proof the cert is
/// un-revoked (§10/§11.8).
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
        if ctx.content.is_none() {
            return Err(RuleOutcome::NotApplicable);
        }
        if !ctx.macho().is_macho {
            return Ok(None);
        }

        // Revocation is a property of a real certificate; unsigned/ad-hoc
        // binaries have none, so don't spend a `codesign --verify` call on them.
        if run_codesign_dv(ctx)? != DvStatus::Signed {
            return Ok(None);
        }

        if run_codesign_verify(ctx)? {
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

    /// Same as `UnsignedBinaryRule`: `ctx.macho()` only gates.
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        true
    }
}

/// Runs `codesign --verify` and reports whether the failure was specifically
/// a revoked certificate, as opposed to any other reason verification failed
/// (modified resource, broken seal, …) — those aren't this rule's claim to
/// make. Best-effort: depends on `codesign`'s own cached/online revocation
/// state, so `false` means "not reported," not "confirmed un-revoked."
///
/// Bound to the scanned object's identity like the memoized `codesign -dv` /
/// `spctl` checks (§11.7): a path swapped between the content read and this
/// call drops the result to `NotApplicable` rather than reporting a different
/// object's revocation state.
fn run_codesign_verify(ctx: &ScanContext) -> Result<bool, RuleOutcome> {
    if !path_is_line_safe(&ctx.path) {
        return Err(RuleOutcome::NotApplicable);
    }
    let stderr = ctx
        .run_object_bound(|| spawn_codesign_verify(&ctx.path).ok())
        .ok_or(RuleOutcome::NotApplicable)?;
    Ok(indicates_revocation(&stderr))
}

fn indicates_revocation(stderr: &str) -> bool {
    // Match only the literal error constant as the trailing diagnostic on a
    // line — `codesign` prefixes every line with the scanned path (and, with
    // `--deep`, nested code paths), so a substring match on "revoked" fires
    // on any path containing that word (#30).
    stderr.lines().any(|line| {
        let line = line.trim_end();
        // `--deep --strict -v` also emits `--prepared:<path>`/`--validated:
        // <path>` progress lines as it walks nested code; a component named
        // to end in the error constant (colons are legal on APFS) would
        // otherwise forge a match on a validly signed bundle (#30 follow-up).
        let trimmed_start = line.trim_start();
        if trimmed_start.starts_with("--prepared:") || trimmed_start.starts_with("--validated:") {
            return false;
        }
        line == "CSSMERR_TP_CERT_REVOKED" || line.ends_with(": CSSMERR_TP_CERT_REVOKED")
    })
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
        if ctx.content.is_none() {
            return Err(RuleOutcome::NotApplicable);
        }
        if !ctx.macho().is_macho {
            return Ok(None);
        }
        // Notarization presupposes a real identity to submit for notarization.
        if run_codesign_dv(ctx)? != DvStatus::Signed {
            return Ok(None);
        }

        match run_spctl_source(ctx)?.as_deref() {
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

    /// Same as `UnsignedBinaryRule`: `ctx.macho()` only gates.
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        true
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
        if ctx.content.is_none() {
            return Err(RuleOutcome::NotApplicable);
        }
        if !ctx.macho().is_macho {
            return Ok(None);
        }
        if run_codesign_dv(ctx)? != DvStatus::Signed {
            return Ok(None);
        }

        match run_spctl_source(ctx)?.as_deref() {
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

    /// Same as `UnsignedBinaryRule`: `ctx.macho()` only gates.
    fn covers_truncation(&self, _ctx: &ScanContext) -> bool {
        true
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

/// Runs `spctl -a -t exec` and pulls out its `source=` line, if any. The
/// spawn is cached on `ctx` (§5.2) so notarization rules sharing a scan
/// don't each spawn their own `spctl`.
fn run_spctl_source(ctx: &ScanContext) -> Result<Option<String>, RuleOutcome> {
    if !path_is_line_safe(&ctx.path) {
        return Err(RuleOutcome::NotApplicable);
    }
    let output = ctx
        .spctl_assessment(|| spawn_spctl_assess(&ctx.path).ok())
        .ok_or(RuleOutcome::NotApplicable)?;
    Ok(parse_spctl_source(&output).map(str::to_string))
}

fn parse_spctl_source(output: &str) -> Option<&str> {
    // Skip line 0: spctl's own `<path>: accepted|rejected` verdict, which
    // echoes the scanned path and could itself start with "source=" (#31).
    output
        .lines()
        .skip(1)
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
/// process spawn is behind the platform gate. The spawn itself is cached on
/// `ctx` (§5.2) so the five rules sharing a scan spawn `codesign` once, not
/// once each.
fn run_codesign_dv(ctx: &ScanContext) -> Result<DvStatus, RuleOutcome> {
    if !path_is_line_safe(&ctx.path) {
        return Err(RuleOutcome::NotApplicable);
    }
    let (success, stderr) = ctx
        .codesign_dv(|| spawn_codesign_dv(&ctx.path).ok())
        .ok_or(RuleOutcome::NotApplicable)?;
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
            identity: None,
            source: ContentSource::File,
            file: None,
            codesign_dv_cache: std::sync::OnceLock::new(),
            spctl_cache: std::sync::OnceLock::new(),
            macho_cache: std::sync::OnceLock::new(),
            stream_failures: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn truncated_ctx(name: &str, body: &[u8]) -> ScanContext {
        ScanContext {
            truncated: true,
            ..ctx(name, body)
        }
    }

    /// All five rules' verdicts come from `codesign`/`spctl` on the whole
    /// file, not the truncated prefix — see the module-level doc comments.
    #[test]
    fn all_codesign_rules_cover_truncation_on_a_truncated_macho_context() {
        let c = truncated_ctx("app", b"\xfe\xed\xfa\xcf");
        assert!(UnsignedBinaryRule.covers_truncation(&c));
        assert!(AdHocSignedRule.covers_truncation(&c));
        assert!(RevokedSignatureRule.covers_truncation(&c));
        assert!(UnnotarizedSignedRule.covers_truncation(&c));
        assert!(NotarizedRule.covers_truncation(&c));
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

    /// A >8 MiB file with a `CAFEBABE` header whose sole arch-table entry
    /// points past the 8 MiB prefix at bytes that aren't a thin Mach-O
    /// magic: `ctx.macho()` reads the real offset and correctly says this
    /// isn't Mach-O, so none of the five rules should even ask `codesign`
    /// (§5.2, #45).
    #[test]
    fn codesign_rules_do_not_treat_an_out_of_bounds_fat_offset_as_macho() {
        use crate::context::MAX_CONTENT_BYTES;
        use crate::test_support::{sparse_temp_file, write_at};

        let total_len = MAX_CONTENT_BYTES as u64 + 4096;
        let path = sparse_temp_file("codesign-oob-fat-offset", total_len);

        let bogus_offset = (MAX_CONTENT_BYTES + 2048) as u32;
        let mut header = Vec::new();
        header.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
        header.extend_from_slice(&1u32.to_be_bytes()); // nfat_arch = 1
        header.extend_from_slice(&0x0100_0007u32.to_be_bytes()); // cputype
        header.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        header.extend_from_slice(&bogus_offset.to_be_bytes()); // offset
        header.extend_from_slice(&4096u32.to_be_bytes()); // size
        header.extend_from_slice(&0u32.to_be_bytes()); // align
        write_at(&path, 0, &header);
        write_at(&path, bogus_offset as u64, b"not a mach-o slice at all");

        let ctx = ScanContext::load(&path);
        assert!(ctx.truncated);
        assert!(
            !ctx.macho().is_macho,
            "the arch table's offset, read for real, doesn't point at a thin magic"
        );

        assert!(matches!(UnsignedBinaryRule.evaluate(&ctx), Ok(None)));
        assert!(matches!(AdHocSignedRule.evaluate(&ctx), Ok(None)));
        assert!(matches!(RevokedSignatureRule.evaluate(&ctx), Ok(None)));
        assert!(matches!(UnnotarizedSignedRule.evaluate(&ctx), Ok(None)));
        assert!(matches!(NotarizedRule.evaluate(&ctx), Ok(None)));

        let _ = std::fs::remove_file(&path);
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
             CodeDirectory v=20400 size=... flags=0x10000(runtime) hashes=...\n\
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

    /// Regression for #30: `codesign` prefixes every line with the scanned
    /// path, so a path containing "revoked" must not itself trigger a match.
    #[test]
    fn indicates_revocation_is_false_for_a_path_containing_the_word() {
        assert!(!indicates_revocation(
            "/Users/x/unrevoked-tools/tool: valid on disk\n\
             /Users/x/unrevoked-tools/tool: satisfies its Designated Requirement\n"
        ));
    }

    /// A `--deep` nested path can also contain the word without the binary
    /// actually being revoked.
    #[test]
    fn indicates_revocation_is_false_for_a_deep_nested_path_containing_the_word() {
        assert!(!indicates_revocation(
            "/Applications/App.app/Contents/Frameworks/Revoked.framework: \
             a sealed resource is missing or invalid\n"
        ));
    }

    /// Regression for #30's follow-up: `--deep --strict -v` emits
    /// `--prepared:`/`--validated:` progress lines for each nested code path
    /// it walks. Colons are legal on APFS, so a component literally named
    /// `helper: CSSMERR_TP_CERT_REVOKED` makes such a line end with the exact
    /// error constant on a validly signed bundle — those lines must be
    /// ignored, not just path-prefix lines in general.
    #[test]
    fn indicates_revocation_is_false_for_deep_progress_lines_ending_in_the_constant() {
        assert!(!indicates_revocation(
            "--prepared:/A.app/Contents/MacOS/helper: CSSMERR_TP_CERT_REVOKED\n\
             --validated:/A.app/Contents/MacOS/helper: CSSMERR_TP_CERT_REVOKED\n\
             /A.app: valid on disk\n"
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

    #[test]
    fn is_linker_signed_matches_the_named_form() {
        assert!(is_linker_signed(
            "CodeDirectory v=20400 size=... flags=0x20002(adhoc,linker-signed) hashes=877+0"
        ));
    }

    /// A `codesign` that renders flags numerically, without the
    /// `(...,linker-signed)` text suffix, must still be recognized — this is
    /// the case the old text-only `.contains("linker-signed")` check missed.
    #[test]
    fn classify_dv_linker_signed_from_numeric_flags_only() {
        let stderr = "Executable=/tmp/x\n\
             CodeDirectory v=20400 size=... flags=0x20002 hashes=...\n\
             Signature=adhoc\n";
        assert_eq!(classify_dv(true, stderr), Ok(DvStatus::AdHocLinkerSigned));
    }

    #[test]
    fn classify_dv_manual_adhoc_from_numeric_flags_only() {
        let stderr = "Executable=/tmp/x\n\
             CodeDirectory v=20400 size=... flags=0x2 hashes=...\n\
             Signature=adhoc\n";
        assert_eq!(classify_dv(true, stderr), Ok(DvStatus::AdHocManual));
    }

    #[test]
    fn is_linker_signed_is_false_without_the_bit_or_the_text() {
        assert!(!is_linker_signed(
            "CodeDirectory v=20400 size=... flags=0x2(adhoc) hashes=877+0"
        ));
        assert!(!is_linker_signed(
            "CodeDirectory v=20400 size=... flags=0x2 hashes=877+0"
        ));
    }

    #[test]
    fn is_linker_signed_falls_back_to_text_when_flags_token_is_malformed() {
        assert!(is_linker_signed(
            "CodeDirectory v=20400 size=... flags=0xZZ(adhoc,linker-signed)"
        ));
    }

    #[test]
    fn is_linker_signed_is_false_when_flags_token_is_absent() {
        assert!(!is_linker_signed("CodeDirectory v=20400 size=1 hashes=0+0"));
    }

    /// Regression for #31: a signer-chosen field that embeds a newline (e.g.
    /// `codesign -i`'s identifier) can echo a second line shaped like the real
    /// `CodeDirectory` line — the point of the exactly-one check, not just its
    /// presence.
    #[test]
    fn single_code_directory_line_is_none_when_there_are_two() {
        let stderr = "Executable=/path/bin\n\
             Identifier=x\n\
             CodeDirectory v=20400 size=1 flags=0x20002(adhoc,linker-signed) hashes=1+1\n\
             Format=Mach-O thin (arm64)\n\
             CodeDirectory v=20400 size=293 flags=0x2(adhoc) hashes=2+2 location=embedded\n\
             Signature=adhoc\n";
        assert_eq!(single_code_directory_line(stderr), None);
    }

    /// No `CodeDirectory` line at all (e.g. a truncated/odd `codesign`
    /// output, or forged text that never actually starts a line with the
    /// literal prefix) must not fall back to scanning the whole blob for it.
    #[test]
    fn single_code_directory_line_is_none_without_a_codedirectory_line() {
        assert_eq!(
            single_code_directory_line(
                "Executable=/tmp/flags=0x20002(adhoc,linker-signed)\nSignature=adhoc\n"
            ),
            None
        );
    }

    /// The exact identifier-injection repro from #31's follow-up review: a
    /// crafted `-i` value forges a second `CodeDirectory `-prefixed line
    /// ahead of the real one, so the count is 2, not 1 — `classify_dv` must
    /// refuse to guess which one is real rather than trusting the first.
    #[test]
    fn classify_dv_is_not_applicable_when_a_codedirectory_line_is_forged() {
        let stderr = "Executable=/path/bin\n\
             Identifier=x\n\
             CodeDirectory v=20400 size=1 flags=0x20002(adhoc,linker-signed) hashes=1+1\n\
             Format=Mach-O thin (arm64)\n\
             CodeDirectory v=20400 size=293 flags=0x2(adhoc) hashes=2+2 location=embedded\n\
             Signature=adhoc\n";
        assert_eq!(classify_dv(true, stderr), Err(RuleOutcome::NotApplicable));
    }

    /// An injected bare `Signature=adhoc` line must not override a real,
    /// single `CodeDirectory` line's flags — once those parse, the
    /// `Signature=` line is never consulted (#31).
    #[test]
    fn classify_dv_ignores_an_injected_signature_adhoc_line_when_flags_parse() {
        let stderr = "Executable=/tmp/x\n\
             Identifier=x\n\
             Signature=adhoc\n\
             CodeDirectory v=20400 size=... flags=0x10000(runtime) hashes=...\n\
             Authority=Developer ID Application: Example Corp (TEAMID1234)\n\
             Authority=Developer ID Certification Authority\n\
             Authority=Apple Root CA\n";
        assert_eq!(classify_dv(true, stderr), Ok(DvStatus::Signed));
    }

    #[test]
    fn path_is_line_safe_true_for_a_normal_path() {
        assert!(path_is_line_safe(std::path::Path::new("/tmp/normal/tool")));
    }

    #[test]
    fn path_is_line_safe_false_for_paths_with_line_breaks() {
        assert!(!path_is_line_safe(std::path::Path::new(
            "/tmp/flags=0x20000\nCodeDirectory v=20400 flags=0x2(adhoc)"
        )));
        assert!(!path_is_line_safe(std::path::Path::new(
            "/tmp/flags=0x20000\rmore"
        )));
    }

    /// Regression for #31: a manually ad-hoc-signed binary named to embed a
    /// bogus `flags=0x...` token before the real `CodeDirectory` line must
    /// not be misread as linker-signed just because that text appears first
    /// in the stream.
    #[test]
    fn classify_dv_ignores_flags_token_in_the_executable_path() {
        let stderr = "Executable=/tmp/flags=0x20000\n\
             Identifier=flags=0x20000\n\
             CodeDirectory v=20400 size=... flags=0x2(adhoc) hashes=877+0\n\
             Signature=adhoc\n";
        assert_eq!(classify_dv(true, stderr), Ok(DvStatus::AdHocManual));
    }

    /// Same forgery attempt via the literal text `linker-signed` embedded in
    /// the path, ahead of a `CodeDirectory` line with no such flag.
    #[test]
    fn classify_dv_ignores_linker_signed_text_in_the_executable_path() {
        let stderr = "Executable=/tmp/linker-signed/x\n\
             CodeDirectory v=20400 size=... flags=0x2(adhoc) hashes=877+0\n\
             Signature=adhoc\n";
        assert_eq!(classify_dv(true, stderr), Ok(DvStatus::AdHocManual));
    }

    /// A filename containing the literal text `Signature=adhoc` must not
    /// forge an ad-hoc verdict on a genuinely Developer-ID-signed binary.
    #[test]
    fn classify_dv_ignores_signature_adhoc_text_in_the_executable_path() {
        let stderr = "Executable=/tmp/Signature=adhoc/x\n\
             CodeDirectory v=20400 size=... flags=0x10000(runtime) hashes=...\n\
             Authority=Developer ID Application: Example Corp (TEAMID1234)\n\
             Authority=Developer ID Certification Authority\n\
             Authority=Apple Root CA\n";
        assert_eq!(classify_dv(true, stderr), Ok(DvStatus::Signed));
    }

    /// Regression for #31: spctl's first line is the `<path>: accepted`
    /// verdict, which echoes the scanned path — a path forging a `source=`
    /// line there must not shadow the real `source=` line that follows.
    #[test]
    fn parse_spctl_source_ignores_a_forged_source_on_the_verdict_line() {
        let out = "source=Notarized Developer ID: rejected\n\
             source=Unnotarized Developer ID\n";
        assert_eq!(parse_spctl_source(out), Some("Unnotarized Developer ID"));
    }
}
