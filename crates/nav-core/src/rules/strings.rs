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
}

const MARKERS: &[Marker] = &[
    Marker {
        needle: "NSAppleScript",
        weight: 6,
        note: "references NSAppleScript (AppleScript execution API)",
    },
    Marker {
        needle: "osascript",
        weight: 6,
        note: "references osascript (AppleScript/JXA interpreter)",
    },
    Marker {
        needle: "dlopen",
        weight: 4,
        note: "references dlopen (dynamic library loading)",
    },
    Marker {
        needle: "TCC.db",
        weight: 10,
        note: "references the TCC permissions database directly",
    },
    Marker {
        needle: "SecKeychain",
        weight: 8,
        note: "references Keychain Services APIs",
    },
    Marker {
        needle: "curl ",
        weight: 3,
        note: "references curl invocation",
    },
    Marker {
        needle: "| sh",
        weight: 10,
        note: "curl/download-pipe-to-shell pattern",
    },
    Marker {
        needle: "| bash",
        weight: 10,
        note: "curl/download-pipe-to-shell pattern",
    },
];

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

        let hits: Vec<&Marker> = MARKERS.iter().filter(|m| text.contains(m.needle)).collect();
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
