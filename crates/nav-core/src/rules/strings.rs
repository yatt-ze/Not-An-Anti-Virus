//! Suspicious string/import scanning (§5.2): `dlopen`, `NSAppleScript`/
//! `osascript`, TCC database paths, Keychain APIs, curl-pipe-to-shell. A cheap
//! cross-platform substring scan over the content window.

use super::{Rule, RuleOutcome};
use crate::context::ScanContext;
use crate::model::{MatchedSignal, SignalCategory};

struct Marker {
    needle: &'static str,
    weight: i32,
    note: &'static str,
    /// Require a non-word byte (or end of input) after the needle — see
    /// `contains_token`. Used for markers that would otherwise match as a
    /// prefix of an unrelated word (`| sh` inside `| shasum`).
    bounded: bool,
}

const MARKERS: &[Marker] = &[
    Marker {
        needle: "NSAppleScript",
        weight: 6,
        note: "references NSAppleScript (AppleScript execution API)",
        bounded: false,
    },
    Marker {
        needle: "osascript",
        weight: 6,
        note: "references osascript (AppleScript/JXA interpreter)",
        bounded: false,
    },
    Marker {
        needle: "dlopen",
        weight: 4,
        note: "references dlopen (dynamic library loading)",
        bounded: false,
    },
    Marker {
        needle: "TCC.db",
        weight: 10,
        note: "references the TCC permissions database directly",
        bounded: false,
    },
    Marker {
        needle: "SecKeychain",
        weight: 8,
        note: "references Keychain Services APIs",
        bounded: false,
    },
    Marker {
        needle: "curl ",
        weight: 3,
        note: "references curl invocation",
        bounded: false,
    },
    Marker {
        needle: "| sh",
        weight: 10,
        note: "curl/download-pipe-to-shell pattern",
        bounded: true,
    },
    Marker {
        needle: "| bash",
        weight: 10,
        note: "curl/download-pipe-to-shell pattern",
        bounded: true,
    },
];

/// Whether `needle` occurs in `haystack` as a token, not as a prefix of a
/// longer word (`| sh` in `| shasum`). A match counts only when the byte
/// after it is absent or not ASCII alphanumeric/`_`/`-`/`.` — a negative
/// class, since content is lossy-decoded binary too (bplist/Mach-O bytes).
fn contains_token(haystack: &str, needle: &str) -> bool {
    haystack.match_indices(needle).any(|(start, _)| {
        match haystack.as_bytes().get(start + needle.len()) {
            None => true,
            Some(b) => !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')),
        }
    })
}

pub struct SuspiciousStringsRule;

impl Default for SuspiciousStringsRule {
    fn default() -> Self {
        SuspiciousStringsRule
    }
}

impl Rule for SuspiciousStringsRule {
    fn id(&self) -> &'static str {
        "suspicious-strings"
    }

    fn category(&self) -> SignalCategory {
        SignalCategory::StaticSuspicion
    }

    fn evaluate(&self, ctx: &ScanContext) -> Result<Option<MatchedSignal>, RuleOutcome> {
        let content = ctx.content.as_ref().ok_or(RuleOutcome::NotApplicable)?;

        // Lossy-decoded: ASCII markers still match, no panic on non-UTF-8.
        let text = String::from_utf8_lossy(content);

        let hits: Vec<&Marker> = MARKERS
            .iter()
            .filter(|m| {
                if m.bounded {
                    contains_token(&text, m.needle)
                } else {
                    text.contains(m.needle)
                }
            })
            .collect();
        if hits.is_empty() {
            return Ok(None);
        }

        let weight = hits.iter().map(|m| m.weight).sum();
        let description = format!(
            "matched {} marker(s): {}",
            hits.len(),
            hits.iter().map(|m| m.note).collect::<Vec<_>>().join("; ")
        );

        Ok(Some(MatchedSignal {
            id: self.id().to_string(),
            weight,
            description,
            category: self.category(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::contains_token;

    #[test]
    fn rejects_word_extensions() {
        assert!(!contains_token("cat f | shasum -a 256", "| sh"));
        assert!(!contains_token("cat f | sha256sum", "| sh"));
        assert!(!contains_token("shuf -n1 list.txt | shuf", "| sh"));
        assert!(!contains_token(
            "eval \"$(bashcompinit)\" | bashcompinit",
            "| bash"
        ));
    }

    #[test]
    fn accepts_token_boundaries() {
        assert!(contains_token("curl x | sh", "| sh"));
        assert!(contains_token("curl x | sh -s", "| sh"));
        assert!(contains_token("curl x | sh\n", "| sh"));
        assert!(contains_token("curl x | sh;", "| sh"));
        assert!(contains_token("curl x | sh)", "| sh"));
        assert!(contains_token("curl x | sh\"", "| sh"));
        assert!(contains_token("curl x | sh\0", "| sh"));
        assert!(contains_token("curl x | sh\t", "| sh"));
        assert!(contains_token("curl x | bash", "| bash"));
    }
}
