//! Finding wire views, shared by REST controllers and MCP tools.
use chrono::{DateTime, FixedOffset};
use opsagent_core::finding::{self as core, StoredEvidence};
use sea_orm::prelude::Decimal;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::models::enum_str;

#[derive(Serialize, ToSchema)]
pub struct FindingSummary {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub check_id: String,
    pub resource_identity: String,
    pub variant: String,
    /// `critical`, `high`, `medium`, `low` or `info`.
    pub severity: String,
    /// `open`, `resolved`, `accepted`, `snoozed` or `flapping`.
    pub status: String,
    pub title: String,
    pub cost_monthly_usd: Option<Decimal>,
    pub created_at: DateTime<FixedOffset>,
    pub updated_at: DateTime<FixedOffset>,
}

#[derive(Serialize, ToSchema)]
pub struct Finding {
    #[serde(flatten)]
    pub finding: FindingSummary,
    pub summary: Option<String>,
    pub next_step: Option<String>,
    pub accepted_reason: Option<String>,
    pub accepted_until: Option<DateTime<FixedOffset>>,
    pub snoozed_until: Option<DateTime<FixedOffset>>,
    pub resolved_at: Option<DateTime<FixedOffset>>,
    pub resolved_reason: Option<String>,
    pub first_seen_run_id: Option<Uuid>,
    pub last_seen_run_id: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct EvidenceItem {
    pub source: String,
    /// Redacted before storage.
    pub excerpt: String,
    pub redacted: bool,
    pub run_id: Uuid,
    pub created_at: DateTime<FixedOffset>,
}

#[derive(Serialize, ToSchema)]
pub struct FindingEvent {
    pub event_type: String,
    pub from_severity: Option<String>,
    pub to_severity: Option<String>,
    /// Null for customer actions.
    pub run_id: Option<Uuid>,
    pub created_at: DateTime<FixedOffset>,
}

#[derive(Serialize, ToSchema)]
pub struct FindingDetail {
    #[serde(flatten)]
    pub finding: Finding,
    pub evidence: Vec<EvidenceItem>,
    /// Newest first, at most 20.
    pub events: Vec<FindingEvent>,
    /// Model explanation; null until explanations exist.
    #[schema(value_type = Option<Object>)]
    pub explanation: Option<Value>,
}

pub fn summary(f: core::Finding) -> FindingSummary {
    FindingSummary {
        id: f.id,
        connection_id: f.connection_id,
        check_id: f.key.check_id,
        resource_identity: f.key.resource_identity,
        variant: f.key.variant,
        severity: enum_str(f.severity),
        status: f.status,
        title: f.title,
        cost_monthly_usd: f.cost_monthly_usd,
        created_at: f.created_at.fixed_offset(),
        updated_at: f.updated_at.fixed_offset(),
    }
}

pub fn full(f: core::Finding) -> Finding {
    Finding {
        summary: f.summary.clone(),
        next_step: f.next_step.clone(),
        accepted_reason: f.accepted_reason.clone(),
        accepted_until: f.accepted_until.map(|t| t.fixed_offset()),
        snoozed_until: f.snoozed_until.map(|t| t.fixed_offset()),
        resolved_at: f.resolved_at.map(|t| t.fixed_offset()),
        resolved_reason: f.resolved_reason.clone(),
        first_seen_run_id: f.first_seen_run_id,
        last_seen_run_id: f.last_seen_run_id,
        finding: summary(f),
    }
}

fn evidence_item(e: StoredEvidence) -> EvidenceItem {
    EvidenceItem {
        source: e.source,
        excerpt: e.excerpt,
        redacted: e.redacted,
        run_id: e.run_id,
        created_at: e.created_at.fixed_offset(),
    }
}

fn event(e: core::FindingEvent) -> FindingEvent {
    FindingEvent {
        event_type: e.kind,
        from_severity: e.from_severity.map(enum_str),
        to_severity: e.to_severity.map(enum_str),
        run_id: e.run_id,
        created_at: e.at.fixed_offset(),
    }
}

/// The wire view of one finding with its evidence and events.
pub fn detail(d: crate::actions::findings::FindingDetail) -> FindingDetail {
    FindingDetail {
        finding: full(d.finding),
        evidence: d.evidence.into_iter().map(evidence_item).collect(),
        events: d.events.into_iter().map(event).collect(),
        explanation: None,
    }
}
