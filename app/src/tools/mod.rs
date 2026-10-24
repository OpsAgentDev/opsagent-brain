//! Transport-neutral tools: each a struct over the Actions it needs, registered once in
//! `boot.rs`. No transport types here; MCP (`crate::mcp`) and Plan 5's model harness are
//! adapters over the `ToolRegistry`.
pub mod list_connections;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::repo::RepoError;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::Value;
use uuid::Uuid;

use crate::{actions::orgs::OrgScope, error::AppError};

pub use list_connections::ListConnectionsTool;

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

/// Every tool, by unique name.
pub struct ToolRegistry {
    tools: Vec<Arc<dyn Tool>>,
}

impl ToolRegistry {
    /// Panics on a duplicate name: a startup bug.
    pub fn new(tools: Vec<Arc<dyn Tool>>) -> Self {
        let mut names: Vec<_> = tools.iter().map(|t| t.spec().name).collect();
        names.sort_unstable();
        if let Some(w) = names.windows(2).find(|w| w[0] == w[1]) {
            panic!("tool registered twice: {}", w[0]);
        }
        Self { tools }
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|t| t.spec()).collect()
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        self.tools.iter().find(|t| t.spec().name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        ToolRegistry::new(vec![
            Arc::new(Named("a")),
            Arc::new(Named("b")),
            Arc::new(Named("a")),
        ]);
    }

    #[test]
    fn registry_finds_by_name() {
        let r = ToolRegistry::new(vec![Arc::new(Named("a")), Arc::new(Named("b"))]);
        assert_eq!(r.get("b").map(|t| t.spec().name), Some("b"));
        assert!(r.get("c").is_none());
        assert_eq!(r.specs().len(), 2);
    }
}
