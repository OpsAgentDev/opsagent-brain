use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn weight(self) -> f32 {
        match self {
            Self::Critical => 10.0,
            Self::High => 5.0,
            Self::Medium => 2.0,
            Self::Low => 0.5,
            Self::Info => 0.0,
        }
    }
}

/// Dedup identity of a finding across runs (PRD 7.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingKey {
    pub connection_id: Uuid,
    pub check_id: String,
    pub resource_identity: String,
    pub variant: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingDraft {
    pub key: FindingKey,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    pub next_step: String,
    pub cost_monthly_usd: Option<f64>,
    pub evidence: Vec<Evidence>,
}
