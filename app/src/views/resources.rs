//! Resource wire views, shared by REST controllers and MCP tools.
use chrono::{DateTime, FixedOffset};
use opsagent_core::resource::ResourceRow;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::models::enum_str;

#[derive(Serialize, ToSchema)]
pub struct ResourceSummary {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub kind: String,
    pub identity: String,
    pub name: Option<String>,
    pub region: Option<String>,
    #[schema(value_type = Object)]
    pub tags: Value,
    pub first_seen_at: DateTime<FixedOffset>,
    pub last_seen_at: DateTime<FixedOffset>,
    /// Set when the resource was missing from a complete inventory.
    pub gone_at: Option<DateTime<FixedOffset>>,
}

pub fn summary(r: ResourceRow) -> ResourceSummary {
    ResourceSummary {
        id: r.id,
        connection_id: r.connection_id,
        kind: enum_str(r.kind),
        identity: r.identity,
        name: r.name,
        region: r.region,
        tags: serde_json::json!(r.tags),
        first_seen_at: r.first_seen_at.fixed_offset(),
        last_seen_at: r.last_seen_at.fixed_offset(),
        gone_at: r.gone_at.map(|t| t.fixed_offset()),
    }
}
