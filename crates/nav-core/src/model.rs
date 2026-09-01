//! Output model for a scan: the score/confidence/completeness split (§5.5).
//! Every `ScanResult` carries enough context to explain itself and to tell
//! "clean" from "we couldn't tell".

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;

/// How much to trust the score, independent of the score's magnitude.
/// A high score built on ambiguous/low-confidence evidence is not the same
/// finding as the same score built on high-confidence evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceConfidence {
    Low,
    Medium,
    High,
}

/// Whether the scan actually finished examining what it set out to examine.
/// A `Partial`/`Indeterminate` scan must never be presented the same way as
/// a `Complete` clean scan — see design doc §6.2 and §8 (exit codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanCompleteness {
    Complete,
    Partial,
    Indeterminate,
}

/// A single rule that fired during the scan, with its own weight and a
/// human-readable explanation. Signals are never collapsed into the score
/// silently — `navctl rules test` surfaces this list verbatim (§5.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedSignal {
    /// Stable rule id — scripts and the false-positive harness key off it.
    pub id: String,
    pub weight: i32,
    pub description: String,
    pub category: SignalCategory,
}

/// Signal categories, grouped per §5.4 rather than one flat additive list —
/// keeps any single category from dominating a verdict on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignalCategory {
    StaticSuspicion,
    ProvenanceConcern,
    BehavioralConcern,
    TemporalCorrelation,
    TrustReduction,
    Informational,
}

/// What the tool suggests doing, never phrased as an automatic action —
/// per §7, no default action above "alert" without explicit user opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Recommendation {
    NoAction,
    Notify,
    NotifyAndSuggestQuarantine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: PathBuf,
    pub score: i32,
    pub confidence: EvidenceConfidence,
    pub completeness: ScanCompleteness,
    pub signals: Vec<MatchedSignal>,
    pub recommendation: Recommendation,
    /// Engine version this verdict was produced under, retained so rollback
    /// (§11.2) and later explanation stay reliable even as rules change.
    pub engine_version: String,
    #[serde(with = "system_time_secs")]
    pub evaluated_at: SystemTime,
}

impl ScanResult {
    pub fn is_significant(&self) -> bool {
        !matches!(self.recommendation, Recommendation::NoAction)
    }
}

mod system_time_secs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        let secs = t
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        secs.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(UNIX_EPOCH + std::time::Duration::from_secs(secs))
    }
}
