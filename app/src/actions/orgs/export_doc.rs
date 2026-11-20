//! The data export document. Every field is named here, so nothing reaches the document by
//! accident: no Stripe ids, ExternalIds, sealed credentials, tokens or key material.
use chrono::{DateTime, NaiveTime, Utc};
use opsagent_core::{
    connection::{Connection, ConnectionStatus},
    finding::{Finding, Severity, StoredEvidence},
    org::Member,
};
use opsagent_deliver::repo::{DeliveryRow, Integration, RecipientRow};
use serde::Serialize;
use uuid::Uuid;

use super::audit_view::AuditItem;

#[derive(Serialize)]
pub struct ExportDoc {
    pub exported_at: DateTime<Utc>,
    pub organisation: OrgOut,
    pub members: Vec<MemberOut>,
    pub connections: Vec<ConnectionOut>,
    pub findings: Vec<FindingOut>,
    pub delivery_settings: DeliverySettingsOut,
    pub recipients: Vec<RecipientOut>,
    pub deliveries: Vec<DeliveryOut>,
    pub audit_log: Vec<AuditItem>,
}

#[derive(Serialize)]
pub struct OrgOut {
    pub name: String,
    pub slug: String,
    pub timezone: String,
    pub created_at: DateTime<Utc>,
    /// `starter`, `team` or `scale`; null without a subscription.
    pub plan: Option<&'static str>,
    pub billing_status: &'static str,
}

#[derive(Serialize)]
pub struct MemberOut {
    pub name: Option<String>,
    pub email: String,
    pub role: &'static str,
    pub joined_at: DateTime<Utc>,
}

impl From<Member> for MemberOut {
    fn from(m: Member) -> Self {
        Self {
            name: m.name,
            email: m.email.as_str().into(),
            role: m.role.as_str(),
            joined_at: m.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct ConnectionOut {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub provider: String,
    /// The cloud account's own id (an AWS account number).
    pub account_id: Option<String>,
    pub status: ConnectionStatus,
    pub created_at: DateTime<Utc>,
}

impl From<&Connection> for ConnectionOut {
    fn from(c: &Connection) -> Self {
        Self {
            id: c.id,
            display_name: c.display_name.clone(),
            provider: c.provider.clone(),
            account_id: c.external_account_id.clone(),
            status: c.status,
            created_at: c.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct EvidenceOut {
    pub source: String,
    /// As stored: redacted before storage.
    pub excerpt: String,
    pub redacted: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct FindingOut {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub check_id: String,
    pub resource: String,
    pub severity: Severity,
    pub status: String,
    pub title: String,
    pub summary: Option<String>,
    pub next_step: Option<String>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub evidence: Vec<EvidenceOut>,
}

impl FindingOut {
    pub fn new(f: Finding, evidence: Vec<StoredEvidence>) -> Self {
        let evidence = evidence.into_iter().map(|e| EvidenceOut {
            source: e.source,
            excerpt: e.excerpt,
            redacted: e.redacted,
            created_at: e.created_at,
        });
        Self {
            id: f.id,
            connection_id: f.connection_id,
            check_id: f.key.check_id,
            resource: f.key.resource_identity,
            severity: f.severity,
            status: f.status,
            title: f.title,
            summary: f.summary,
            next_step: f.next_step,
            created_at: f.created_at,
            resolved_at: f.resolved_at,
            evidence: evidence.collect(),
        }
    }
}

#[derive(Serialize)]
pub struct DeliverySettingsOut {
    pub connections: Vec<ConnectionDeliveryOut>,
    pub integrations: Vec<IntegrationOut>,
}

/// When one connection is scanned and briefed, and where its briefing goes.
#[derive(Serialize)]
pub struct ConnectionDeliveryOut {
    pub connection_id: Uuid,
    pub scan_time_local: Option<NaiveTime>,
    pub briefing_time_local: Option<NaiveTime>,
    pub slack_channel_id: Option<String>,
    pub urgent_alerts: bool,
}

impl From<&Connection> for ConnectionDeliveryOut {
    fn from(c: &Connection) -> Self {
        Self {
            connection_id: c.id,
            scan_time_local: c.scan_time_local,
            briefing_time_local: c.briefing_time_local,
            slack_channel_id: c.slack_channel_id.clone(),
            urgent_alerts: c.urgent_alerts,
        }
    }
}

#[derive(Serialize)]
pub struct IntegrationOut {
    pub kind: String,
    pub status: String,
    /// Slack: the workspace's name.
    pub workspace: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<Integration> for IntegrationOut {
    fn from(i: Integration) -> Self {
        Self {
            workspace: i.config["team_name"].as_str().map(str::to_owned),
            kind: i.kind,
            status: i.status,
            created_at: i.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct RecipientOut {
    pub email: String,
    /// Null: organisation-wide.
    pub connection_id: Option<Uuid>,
    pub status: String,
    pub unsubscribed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<RecipientRow> for RecipientOut {
    fn from(r: RecipientRow) -> Self {
        Self {
            email: r.email,
            connection_id: r.connection_id,
            status: r.status,
            unsubscribed_at: r.unsubscribed_at,
            created_at: r.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct DeliveryOut {
    pub at: DateTime<Utc>,
    pub kind: String,
    pub channel: String,
    pub status: String,
    pub connection_id: Option<Uuid>,
}

impl From<DeliveryRow> for DeliveryOut {
    fn from(d: DeliveryRow) -> Self {
        Self {
            at: d.sent_at.unwrap_or(d.created_at),
            kind: d.kind,
            channel: d.channel,
            status: d.status,
            connection_id: d.connection_id,
        }
    }
}
