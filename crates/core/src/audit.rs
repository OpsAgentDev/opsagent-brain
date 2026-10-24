//! The audit trail: one entry per state change, by a member or by the system.
use async_trait::async_trait;
use uuid::Uuid;

use crate::repo::RepoResult;

/// Who acted: `audit_events.actor_type` and `actor_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// A user, by user id.
    Member(Uuid),
    /// Work done by the system (workers).
    System,
    /// An MCP client, by OAuth grant id.
    McpClient(Uuid),
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    pub organisation_id: Option<Uuid>,
    pub actor: Actor,
    pub action: String,
    /// `(kind, id)`, e.g. `("connection", <uuid>)`; ids are not always uuids (`integration`).
    pub target: Option<(&'static str, String)>,
    pub outcome: String,
    pub meta: serde_json::Value,
}

impl AuditEntry {
    /// A successful action by member `actor`, no metadata.
    pub fn member(
        organisation_id: Option<Uuid>,
        actor: Uuid,
        action: impl Into<String>,
        target: Option<(&'static str, String)>,
    ) -> Self {
        Self {
            organisation_id,
            actor: Actor::Member(actor),
            action: action.into(),
            target,
            outcome: "success".into(),
            meta: serde_json::json!({}),
        }
    }

    /// Work done by the system, with an explicit outcome.
    pub fn system(
        organisation_id: Uuid,
        action: impl Into<String>,
        target: (&'static str, String),
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            organisation_id: Some(organisation_id),
            actor: Actor::System,
            action: action.into(),
            target: Some(target),
            outcome: outcome.into(),
            meta: serde_json::json!({}),
        }
    }

    /// A tool call by the MCP client holding grant `grant_id`.
    pub fn mcp_client(
        organisation_id: Uuid,
        grant_id: Uuid,
        action: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            organisation_id: Some(organisation_id),
            actor: Actor::McpClient(grant_id),
            action: action.into(),
            target: None,
            outcome: outcome.into(),
            meta: serde_json::json!({}),
        }
    }

    pub fn with_meta(self, meta: serde_json::Value) -> Self {
        Self { meta, ..self }
    }
}

#[async_trait]
pub trait AuditLog: Send + Sync {
    async fn record(&self, e: AuditEntry) -> RepoResult<()>;
    /// Whether the organisation already has an `action` entry whose metadata names `run_id`.
    async fn recorded_for_run(
        &self,
        organisation_id: Uuid,
        action: &str,
        run_id: Uuid,
    ) -> RepoResult<bool>;
}
