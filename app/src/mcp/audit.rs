//! One `audit_events` row per tool call; never the arguments or the result.
use opsagent_core::{
    audit::{AuditEntry, AuditLog},
    repo::RepoResult,
};
use serde_json::json;

use crate::tools::{Caller, Via};

pub async fn record(
    audit: &dyn AuditLog,
    caller: &Caller,
    tool: &str,
    outcome: &str,
) -> RepoResult<()> {
    let Via::Mcp {
        grant_id,
        client_id,
        ..
    } = &caller.via;
    let org = caller.scope.organisation.id;
    let entry = AuditEntry::mcp_client(org, *grant_id, "mcp.tool.call", outcome)
        .with_meta(json!({ "client_id": client_id, "tool": tool, "outcome": outcome }));
    audit.record(entry).await
}
