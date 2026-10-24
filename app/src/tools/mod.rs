//! Transport-neutral tools: each a struct over the Actions it needs, registered once in
//! `boot.rs`. No transport types here; MCP (`crate::mcp`) and Plan 5's model harness are
//! adapters over the `ToolRegistry`.
pub mod get_cost_anomalies;
pub mod get_finding;
pub mod get_scan;
pub mod list_connections;
pub mod list_findings;
pub mod list_resources;
pub mod prompts;
pub mod resources;
pub mod run_check;

use std::{sync::Arc, time::Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    audit::AuditEntry,
    repo::{PageOf, PageRequest, RepoError},
};
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    actions::{orgs::OrgScope, uow::UnitOfWork},
    controllers::page::{decode, Page, DEFAULT_LIMIT, MAX_LIMIT},
    error::AppError,
    models::enum_of,
};

pub use get_cost_anomalies::GetCostAnomaliesTool;
pub use get_finding::GetFindingTool;
pub use get_scan::GetScanTool;
pub use list_connections::ListConnectionsTool;
pub use list_findings::ListFindingsTool;
pub use list_resources::ListResourcesTool;
pub use prompts::{Prompt, PromptRegistry};
pub use resources::{ResourceRegistry, ResourceSource};
pub use run_check::RunCheckTool;

/// Who is calling a tool: the organisation scope and the door they came through.
#[derive(Debug, Clone)]
pub struct Caller {
    pub scope: OrgScope,
    pub via: Via,
}

#[derive(Debug, Clone)]
pub enum Via {
    Mcp {
        grant_id: Uuid,
        client_id: String,
        token_id: Uuid,
    },
}

/// What a tool may do. Read only in this release: a write tool needs a new variant and an
/// approval path, which nothing here provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
}

#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    /// JSON Schema of the arguments object (`schema_of`).
    pub input_schema: Value,
    pub access: Access,
    pub idempotent: bool,
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn spec(&self) -> ToolSpec;
    /// The result is a JSON object.
    async fn call(&self, caller: &Caller, args: Value) -> Result<Value, ToolError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("Not found.")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    /// No tool of that name; a protocol error for the adapter, not a tool outcome.
    #[error("Unknown tool: {0}")]
    Unknown(String),
    #[error("A scan ran less than an hour ago (last at {last_scan_at}).")]
    ScanTooSoon { last_scan_at: DateTime<Utc> },
    #[error("The connection is blocked.")]
    ConnectionBlocked,
    /// The detail is logged, never shown to the caller.
    #[error("internal: {0}")]
    Internal(String),
}

impl ToolError {
    /// The API error catalogue code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Invalid(_) => "invalid",
            Self::Unknown(_) => "unknown_tool",
            Self::ScanTooSoon { .. } => "scan_too_soon",
            Self::ConnectionBlocked => "connection_blocked",
            Self::Internal(_) => "internal",
        }
    }
}

impl From<AppError> for ToolError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::NotFound | AppError::Repo(RepoError::NotFound) => Self::NotFound,
            AppError::Invalid(detail) => Self::Invalid(detail),
            e => Self::Internal(e.to_string()),
        }
    }
}

/// The input schema of the args struct `T`.
pub fn schema_of<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).unwrap_or_default()
}

/// `args` as `T` (declare it `deny_unknown_fields`); a mismatch is `Invalid`.
pub fn parse_args<T: DeserializeOwned>(args: Value) -> Result<T, ToolError> {
    serde_json::from_value(args).map_err(|e| ToolError::Invalid(e.to_string()))
}

/// The tool result as JSON.
pub fn to_json<T: Serialize>(v: &T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::Internal(e.to_string()))
}

/// The page request for `cursor` and `limit` (default 50, clamped to 1..=200 like REST).
pub fn page_request(cursor: Option<&str>, limit: Option<u64>) -> Result<PageRequest, ToolError> {
    let after = cursor
        .map(decode)
        .transpose()
        .map_err(|_| ToolError::Invalid("cursor is not valid".into()))?;
    Ok(PageRequest {
        after,
        limit: limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT),
    })
}

/// `{items, next_cursor}` with each row through `view`.
pub fn page_json<T, U: Serialize>(
    got: PageOf<T>,
    view: impl FnMut(T) -> U,
) -> Result<Value, ToolError> {
    to_json(&Page::of(got).map(view))
}

/// An id naming a record: a malformed one is `NotFound`, as in REST.
pub fn record_id(s: &str) -> Result<Uuid, ToolError> {
    s.parse().map_err(|_| ToolError::NotFound)
}

/// An id used as a filter: a malformed one is `Invalid`.
pub fn filter_id(s: &str) -> Result<Uuid, ToolError> {
    s.parse()
        .map_err(|_| ToolError::Invalid(format!("{s:?} is not a valid id")))
}

/// The enum value named `s` (`what` names the argument in the error).
pub fn enum_arg<T: DeserializeOwned>(what: &str, s: &str) -> Result<T, ToolError> {
    enum_of(s).ok_or_else(|| ToolError::Invalid(format!("unknown {what} {s:?}")))
}

/// Every tool, by unique name, and the one place a call is audited and logged.
pub struct ToolRegistry {
    tools: Vec<Arc<dyn Tool>>,
    uow: Arc<dyn UnitOfWork>,
}

impl ToolRegistry {
    /// Panics on a duplicate name: a startup bug.
    pub fn new(tools: Vec<Arc<dyn Tool>>, uow: Arc<dyn UnitOfWork>) -> Self {
        let mut names: Vec<_> = tools.iter().map(|t| t.spec().name).collect();
        names.sort_unstable();
        if let Some(w) = names.windows(2).find(|w| w[0] == w[1]) {
            panic!("tool registered twice: {}", w[0]);
        }
        Self { tools, uow }
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|t| t.spec()).collect()
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        self.tools.iter().find(|t| t.spec().name == name)
    }

    /// Runs the tool, writes its `audit_events` row (tool and outcome, never arguments or
    /// results) and logs outcome and latency. An unknown name is `Unknown`, not audited; a
    /// failed audit write fails the call (no unaudited access).
    pub async fn invoke(
        &self,
        caller: &Caller,
        name: &str,
        args: Value,
    ) -> Result<Value, ToolError> {
        let Some(tool) = self.get(name) else {
            tracing::warn!(tool = name, "unknown tool");
            return Err(ToolError::Unknown(name.to_owned()));
        };
        let started = Instant::now();
        let result = tool.call(caller, args).await;
        let outcome = result.as_ref().map_or_else(ToolError::code, |_| "success");
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        tracing::info!(tool = name, outcome, latency_ms, "tool call");
        let Via::Mcp {
            grant_id,
            client_id,
            ..
        } = &caller.via;
        let org = caller.scope.organisation.id;
        let entry = AuditEntry::mcp_client(org, *grant_id, "mcp.tool.call", outcome)
            .with_meta(json!({ "client_id": client_id, "tool": name, "outcome": outcome }));
        if let Err(e) = self.uow.audit().record(entry).await {
            tracing::error!(error = %e, tool = name, "tool call audit failed");
            return Err(ToolError::Internal("audit failed".into()));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::memory::MemStore;

    struct Named(&'static str);

    #[async_trait]
    impl Tool for Named {
        fn spec(&self) -> ToolSpec {
            ToolSpec {
                name: self.0,
                title: "t",
                description: "d",
                input_schema: serde_json::json!({"type": "object"}),
                access: Access::Read,
                idempotent: true,
            }
        }
        async fn call(&self, _: &Caller, _: Value) -> Result<Value, ToolError> {
            Ok(Value::Null)
        }
    }

    #[test]
    #[should_panic(expected = "tool registered twice: a")]
    fn registry_rejects_duplicate_names() {
        ToolRegistry::new(
            vec![
                Arc::new(Named("a")),
                Arc::new(Named("b")),
                Arc::new(Named("a")),
            ],
            Arc::new(MemStore::default()),
        );
    }

    #[test]
    fn registry_finds_by_name() {
        let r = ToolRegistry::new(
            vec![Arc::new(Named("a")), Arc::new(Named("b"))],
            Arc::new(MemStore::default()),
        );
        assert_eq!(r.get("b").map(|t| t.spec().name), Some("b"));
        assert!(r.get("c").is_none());
        assert_eq!(r.specs().len(), 2);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use chrono::Utc;
    use opsagent_core::{
        org::{Member, Organisation, Role},
        user::Email,
    };

    use super::*;

    /// An MCP caller for organisation `org`.
    pub fn caller(org: Uuid) -> Caller {
        let organisation = Organisation {
            id: org,
            slug: "o".into(),
            name: "O".into(),
            timezone: "UTC".into(),
            kek_version: None,
            wrapped_dek: None,
            created_at: Utc::now(),
            deleted_at: None,
        };
        let member = Member {
            id: Uuid::new_v4(),
            organisation_id: org,
            user_id: Uuid::new_v4(),
            email: Email::parse("a@example.com").unwrap(),
            name: None,
            role: Role::Owner,
            created_at: Utc::now(),
        };
        Caller {
            scope: OrgScope::new(organisation, member),
            via: Via::Mcp {
                grant_id: Uuid::new_v4(),
                client_id: "test".into(),
                token_id: Uuid::new_v4(),
            },
        }
    }
}
