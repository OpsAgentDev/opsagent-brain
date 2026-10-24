use async_trait::async_trait;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use super::{parse_args, record_id, schema_of, to_json, Access, Caller, Tool, ToolError, ToolSpec};
use crate::{actions::runs::GetRun, views::runs::run_view};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Args {
    /// Run id, from `list_connections` (last scan) or `run_check`.
    run_id: String,
}

/// One run: status, timings and its statistics (score, counts).
pub struct GetScanTool {
    get: GetRun,
}

impl GetScanTool {
    pub fn new(get: GetRun) -> Self {
        Self { get }
    }
}

#[async_trait]
impl Tool for GetScanTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "get_scan",
            title: "Get scan",
            description: "One scan run: status, timings and statistics such as score and counts.",
            input_schema: schema_of::<Args>(),
            access: Access::Read,
            idempotent: true,
        }
    }

    async fn call(&self, caller: &Caller, args: Value) -> Result<Value, ToolError> {
        let a: Args = parse_args(args)?;
        let r = self
            .get
            .run(caller.scope.organisation.id, record_id(&a.run_id)?)
            .await?;
        to_json(&run_view(r))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::{adapters::memory::MemStore, tools::test_support::caller};

    #[tokio::test]
    async fn unknown_run_is_not_found() {
        let tool = GetScanTool::new(GetRun::new(Arc::new(MemStore::default())));
        let org = Uuid::new_v4();
        for id in [Uuid::new_v4().to_string(), "x".into()] {
            let e = tool
                .call(&caller(org), json!({"run_id": id}))
                .await
                .unwrap_err();
            assert_eq!(e.code(), "not_found");
        }
    }
}
