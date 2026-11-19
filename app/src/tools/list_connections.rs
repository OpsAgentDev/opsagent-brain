use async_trait::async_trait;
use opsagent_core::{connection::ConnectionStatus, repo::PageRequest, run::RunFilter};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{parse_args, schema_of, Access, Caller, Tool, ToolError, ToolSpec};
use crate::actions::{connections::ListConnections, runs::ListRuns};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Args {}

/// The organisation's connections, each with its latest full scan.
pub struct ListConnectionsTool {
    list: ListConnections,
    runs: ListRuns,
}

impl ListConnectionsTool {
    pub fn new(list: ListConnections, runs: ListRuns) -> Self {
        Self { list, runs }
    }
}

#[async_trait]
impl Tool for ListConnectionsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "list_connections",
            title: "List connections",
            description: "Lists the organisation's cloud connections: id, provider, name, \
                          cloud account id, status, status_reason and the latest scan. Only \
                          `connected` ones are scanned; a `disconnected` one keeps its old \
                          findings. `status_reason` says why a connection is not connected, \
                          for example `access_denied` on a `pending` one: the cloud refused \
                          the role, so correct it and verify again. Use a connection id to \
                          filter the other tools.",
            input_schema: schema_of::<Args>(),
            access: Access::Read,
            idempotent: true,
        }
    }

    async fn call(&self, caller: &Caller, args: Value) -> Result<Value, ToolError> {
        let Args {} = parse_args(args)?;
        let org = caller.scope.organisation.id;
        let mut out = Vec::new();
        for c in self.list.run(org).await? {
            // An abandoned connect attempt is not a cloud account: the dashboard hides it too.
            if c.status == ConnectionStatus::Disconnected && c.first_connected_at.is_none() {
                continue;
            }
            // shortcut: one runs query per connection, batch when connections per org grow past ~50
            let filter = RunFilter {
                connection_id: Some(c.id),
                job_type: Some("full_scan".into()),
            };
            let page = PageRequest {
                after: None,
                limit: 1,
            };
            let last = self.runs.run(org, filter, page).await?.items.pop();
            out.push(json!({
                "id": c.id,
                "provider": c.provider,
                "name": c.display_name,
                "account_id": c.external_account_id,
                "status": c.status,
                "status_reason": c.status_reason,
                "last_scan": last.map(|r| json!({
                    "run_id": r.id,
                    "status": r.status,
                    "scheduled_at": r.scheduled_at,
                    "finished_at": r.finished_at,
                })),
            }));
        }
        Ok(json!({ "connections": out }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use opsagent_core::connection::{NewConnection, SealedCreds};

    use super::*;
    use crate::{actions::uow::Repos, adapters::memory::MemStore, tools::test_support::caller};

    #[tokio::test]
    async fn items_carry_the_status_reason() {
        let store = MemStore::default();
        let me = caller(uuid::Uuid::new_v4());
        let org = me.scope.organisation.id;
        let new = NewConnection {
            organisation_id: org,
            provider: "aws".into(),
            display_name: "Prod".into(),
            template_version: None,
            credential_kind: "aws_role".into(),
        };
        let creds = SealedCreds {
            ciphertext: vec![],
            nonce: vec![],
            kek_version: 1,
        };
        let repo = store.connections();
        let c = repo.insert(new, creds).await.unwrap();
        let pending = ConnectionStatus::Pending;
        let reason = Some("access_denied");
        assert!(repo
            .cas_status(org, c.id, pending, pending, reason)
            .await
            .unwrap());
        let uow = Arc::new(store.clone());
        let tool = ListConnectionsTool::new(ListConnections::new(uow.clone()), ListRuns::new(uow));
        let got = tool.call(&me, json!({})).await.unwrap();
        let item = &got["connections"][0];
        assert_eq!(item["status"], "pending");
        assert_eq!(item["status_reason"], "access_denied");
        assert_eq!(item["last_scan"], Value::Null);
    }
}
