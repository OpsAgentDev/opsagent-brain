use std::sync::Arc;

use async_trait::async_trait;
use chrono::Duration;
use opsagent_core::repo::Clock;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{parse_args, record_id, schema_of, Access, Caller, Tool, ToolError, ToolSpec};
use crate::{
    actions::runs::{RequestManualScan, SCAN_WINDOW},
    error::AppError,
};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Args {
    /// Connection id, from `list_connections`.
    connection: String,
}

/// Queues a scan of a connection: the same once-an-hour rule as REST.
pub struct RunCheckTool {
    scan: RequestManualScan,
    clock: Arc<dyn Clock>,
}

impl RunCheckTool {
    pub fn new(scan: RequestManualScan, clock: Arc<dyn Clock>) -> Self {
        Self { scan, clock }
    }

    /// `scan_too_soon` carries the last scan's time; `connection_blocked` is an unscannable one.
    fn map(&self, e: AppError) -> ToolError {
        match e {
            AppError::RateLimited {
                retry_after_secs, ..
            } => {
                let left = Duration::seconds(i64::try_from(retry_after_secs).unwrap_or(i64::MAX));
                ToolError::ScanTooSoon {
                    last_scan_at: self.clock.now() + left - SCAN_WINDOW,
                }
            }
            e if e.is_not_scannable() => ToolError::ConnectionBlocked,
            e => e.into(),
        }
    }
}

#[async_trait]
impl Tool for RunCheckTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "run_check",
            title: "Run a scan now",
            description: "Queues a scan of one connection and returns its run id; poll get_scan. \
                          It only reads the customer's cloud. At most one scan per connection per \
                          hour: otherwise the error scan_too_soon carries the last scan's time.",
            input_schema: schema_of::<Args>(),
            access: Access::Read,
            idempotent: false,
        }
    }

    async fn call(&self, caller: &Caller, args: Value) -> Result<Value, ToolError> {
        let a: Args = parse_args(args)?;
        let out = self
            .scan
            .run(
                caller.scope.organisation.id,
                caller.scope.member.user_id,
                record_id(&a.connection)?,
            )
            .await
            .map_err(|e| self.map(e))?;
        Ok(json!({ "run_id": out.run.id }))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use opsagent_core::repo::FixedClock;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::{
        actions::runs::{test_support::connected, RunDispatcher},
        adapters::memory::MemStore,
        tools::test_support::caller,
    };

    #[tokio::test]
    async fn second_scan_is_too_soon_with_the_first_scans_time() {
        let store = MemStore::default();
        let org = Uuid::new_v4();
        let c = connected(&store, org).await;
        let first: DateTime<Utc> = "2026-10-22T12:00:00Z".parse().unwrap();
        let tool = |t| {
            let clock = Arc::new(FixedClock(t));
            let d = Arc::new(RunDispatcher::new(Arc::new(store.clone())));
            let scan = RequestManualScan::new(Arc::new(store.clone()), d, clock.clone());
            RunCheckTool::new(scan, clock)
        };
        let args = json!({"connection": c.id.to_string()});
        let ok = tool(first).call(&caller(org), args.clone()).await.unwrap();
        assert!(ok["run_id"].is_string());
        let e = tool(first + Duration::minutes(10))
            .call(&caller(org), args)
            .await
            .unwrap_err();
        assert!(
            matches!(e, ToolError::ScanTooSoon { last_scan_at } if last_scan_at == first),
            "{e:?}"
        );
        let e = tool(first)
            .call(
                &caller(Uuid::new_v4()),
                json!({"connection": c.id.to_string()}),
            )
            .await
            .unwrap_err();
        assert_eq!(e.code(), "not_found");
    }
}
