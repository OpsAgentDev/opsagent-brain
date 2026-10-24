use async_trait::async_trait;
use opsagent_core::{repo::PageRequest, run::RunFilter};
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
                          status and the latest scan. Use a connection id to filter the other tools.",
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
                "status": c.status,
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
