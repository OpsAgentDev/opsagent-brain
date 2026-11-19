//! Transport-neutral tools: each a struct over the Actions it needs, registered once in
//! `boot.rs`. No transport types here; MCP (`crate::mcp`) and Plan 5's model harness are
//! adapters over the `ToolRegistry`.
pub mod connect_cloud_account;
pub mod get_cost_anomalies;
pub mod get_finding;
pub mod get_scan;
pub mod list_connections;
pub mod list_findings;
pub mod list_resources;
pub mod prompts;
pub mod resources;
pub mod run_check;
pub mod triage_finding;
pub mod verify_connection;

use std::{sync::Arc, time::Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    audit::AuditEntry,
    org::org_web_base,
    repo::{PageOf, PageRequest, RepoError},
};
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    actions::{orgs::OrgScope, uow::UnitOfWork},
    error::AppError,
    models::enum_of,
    views::page::{Page, WireCursor, DEFAULT_LIMIT, MAX_LIMIT},
};

pub use connect_cloud_account::ConnectCloudAccountTool;
pub use get_cost_anomalies::GetCostAnomaliesTool;
pub use get_finding::GetFindingTool;
pub use get_scan::GetScanTool;
pub use list_connections::ListConnectionsTool;
pub use list_findings::ListFindingsTool;
pub use list_resources::ListResourcesTool;
pub use prompts::{Prompt, PromptRegistry};
pub use resources::{ResourceRegistry, ResourceSource};
pub use run_check::RunCheckTool;
pub use triage_finding::{Triage, TriageFindingTool};
pub use verify_connection::VerifyConnectionTool;

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
        /// The grant carries `opsagent.write`: the member approved changes.
        write: bool,
    },
    /// The dashboard chat, for the member who owns the session.
    Chat { session_id: Uuid, member_id: Uuid },
}

impl Via {
    /// Audit action prefix and log label for this door.
    pub fn channel(&self) -> &'static str {
        match self {
            Via::Mcp { .. } => "mcp",
            Via::Chat { .. } => "chat",
        }
    }

    /// Only an MCP grant approved for changes may run a write tool; the chat never does.
    fn may_write(&self) -> bool {
        matches!(self, Via::Mcp { write: true, .. })
    }
}

/// What a tool may do. `Write` changes OpsAgent's own state for the organisation (never the
/// customer's cloud) and runs only for a caller that `may_write`; the registry enforces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
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
    #[error("This organisation is read-only until billing is set up.")]
    BillingRequired,
    #[error("This connection is read-only. Revoke it under Settings > Connected agents, connect the agent again and tick 'Let this agent make changes'.")]
    InsufficientScope,
    #[error("{0}")]
    Forbidden(&'static str),
    /// An Action's own refusal, with the code and wording REST gives.
    #[error("{detail}")]
    Refused { code: &'static str, detail: String },
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
            Self::BillingRequired => "billing_required",
            Self::InsufficientScope => "insufficient_scope",
            Self::Forbidden(_) => "forbidden",
            Self::Refused { code, .. } => code,
            Self::Internal(_) => "internal",
        }
    }
}

impl From<AppError> for ToolError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::NotFound | AppError::Repo(RepoError::NotFound) => Self::NotFound,
            AppError::Invalid(detail) => Self::Invalid(detail),
            AppError::Refused {
                code: "billing_required",
                ..
            } => Self::BillingRequired,
            AppError::Forbidden => Self::Forbidden("Owner role required."),
            AppError::Refused { code, detail, .. } => Self::Refused { code, detail },
            e => Self::Internal(e.to_string()),
        }
    }
}

/// An Action's error for the connect tools, where a member's refusal names what owners do.
pub fn owner_only(e: AppError) -> ToolError {
    match e {
        AppError::Forbidden => ToolError::Forbidden("Only an owner can connect a cloud account."),
        e => e.into(),
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
pub fn page_request<K: WireCursor>(
    cursor: Option<&str>,
    limit: Option<u64>,
) -> Result<PageRequest<K>, ToolError> {
    let after = cursor
        .map(K::decode)
        .transpose()
        .map_err(|_| ToolError::Invalid("cursor is not valid".into()))?;
    Ok(PageRequest {
        after,
        limit: limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT),
    })
}

/// `{items, next_cursor}` with each row through `view`.
pub fn page_json<T, K: WireCursor, U: Serialize>(
    got: PageOf<T, K>,
    view: impl FnMut(T) -> U,
) -> Result<Value, ToolError> {
    to_json(&Page::of(got).map(view))
}

/// The caller's organisation's dashboard address, for each finding's `url`.
pub fn link_base(web_base_url: &str, caller: &Caller) -> String {
    org_web_base(web_base_url, &caller.scope.organisation.slug)
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

    /// Runs the tool and audits it (`audited`). An unknown name is `Unknown`, not audited;
    /// failed audit write fails the call. A write tool never runs for a caller that may not
    /// write: that is `InsufficientScope`, audited like any outcome.
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
        let result = if tool.spec().access == Access::Write && !caller.via.may_write() {
            Err(ToolError::InsufficientScope)
        } else {
            tool.call(caller, args).await
        };
        audited(
            &*self.uow,
            caller,
            &format!("{}.tool.call", caller.via.channel()),
            ("tool", name),
            started,
            result,
        )
        .await
    }
}

/// Logs outcome and latency of one tool, resource or prompt request and writes its
/// `audit_events` row (the subject and outcome, never arguments or content), with the door's
/// actor: the MCP grant, or the chatting member. A failed audit write fails the request (no
/// unaudited access).
pub(crate) async fn audited<T>(
    uow: &dyn UnitOfWork,
    caller: &Caller,
    action: &str,
    (key, subject): (&'static str, &str),
    started: Instant,
    result: Result<T, ToolError>,
) -> Result<T, ToolError> {
    let outcome = result.as_ref().map_or_else(ToolError::code, |_| "success");
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let channel = caller.via.channel();
    tracing::info!(
        channel,
        action,
        subject,
        outcome,
        latency_ms,
        "tool request"
    );
    let org = caller.scope.organisation.id;
    let entry = match &caller.via {
        Via::Mcp {
            grant_id,
            client_id,
            ..
        } => AuditEntry::mcp_client(org, *grant_id, action, outcome)
            .with_meta(json!({ "client_id": client_id, key: subject, "outcome": outcome })),
        Via::Chat { session_id, .. } => {
            let user = caller.scope.member.user_id;
            AuditEntry {
                outcome: outcome.into(),
                ..AuditEntry::member(Some(org), user, action, None)
            }
            .with_meta(json!({ "session_id": session_id, key: subject, "outcome": outcome }))
        }
    };
    if let Err(e) = uow.audit().record(entry).await {
        tracing::error!(error = %e, action, "tool audit write failed");
        return Err(ToolError::Internal("audit failed".into()));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::memory::MemStore;

    struct Named(&'static str);

    /// A write tool that records whether it ran.
    struct Writes(Arc<std::sync::atomic::AtomicBool>);

    #[async_trait]
    impl Tool for Writes {
        fn spec(&self) -> ToolSpec {
            ToolSpec {
                name: "w",
                access: Access::Write,
                ..Named("w").spec()
            }
        }
        async fn call(&self, _: &Caller, _: Value) -> Result<Value, ToolError> {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(Value::Null)
        }
    }

    #[tokio::test]
    async fn write_tool_runs_only_for_a_write_grant() {
        use std::sync::atomic::Ordering::SeqCst;
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let store = MemStore::default();
        let r = ToolRegistry::new(vec![Arc::new(Writes(ran.clone()))], Arc::new(store.clone()));
        let write = test_support::caller(Uuid::new_v4());
        let mut read = write.clone();
        if let Via::Mcp { write, .. } = &mut read.via {
            *write = false;
        }
        let chat = Caller {
            via: Via::Chat {
                session_id: Uuid::new_v4(),
                member_id: write.scope.member.id,
            },
            ..write.clone()
        };
        for refused in [&read, &chat] {
            let e = r.invoke(refused, "w", Value::Null).await.unwrap_err();
            assert_eq!(e.code(), "insufficient_scope");
            assert_eq!(
                e.to_string(),
                "This connection is read-only. Revoke it under Settings > Connected agents, connect the agent again and tick 'Let this agent make changes'."
            );
            assert!(!ran.load(SeqCst), "the tool ran");
        }
        r.invoke(&write, "w", Value::Null).await.unwrap();
        assert!(ran.load(SeqCst));
        let outcomes: Vec<_> = store
            .audit_entries()
            .into_iter()
            .map(|a| a.outcome)
            .collect();
        assert_eq!(
            outcomes,
            ["insufficient_scope", "insufficient_scope", "success"]
        );
    }

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

    #[tokio::test]
    async fn audit_actor_follows_the_door() {
        use opsagent_core::audit::Actor;
        let store = MemStore::default();
        let r = ToolRegistry::new(vec![Arc::new(Named("a"))], Arc::new(store.clone()));
        let mcp = test_support::caller(Uuid::new_v4());
        let Via::Mcp { grant_id, .. } = mcp.via else {
            unreachable!()
        };
        let session_id = Uuid::new_v4();
        let chat = Caller {
            via: Via::Chat {
                session_id,
                member_id: mcp.scope.member.id,
            },
            ..mcp.clone()
        };
        r.invoke(&mcp, "a", Value::Null).await.unwrap();
        r.invoke(&chat, "a", Value::Null).await.unwrap();
        let audit = store.audit_entries();
        assert_eq!(audit[0].actor, Actor::McpClient(grant_id));
        assert_eq!(audit[0].action, "mcp.tool.call");
        assert_eq!(audit[1].actor, Actor::Member(mcp.scope.member.user_id));
        assert_eq!(audit[1].action, "chat.tool.call");
        assert_eq!(audit[1].meta["session_id"], session_id.to_string());
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

    /// An MCP caller for organisation `org`: an owner whose grant allows changes.
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
                write: true,
            },
        }
    }
}
