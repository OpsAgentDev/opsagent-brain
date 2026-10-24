use std::sync::Arc;

use async_trait::async_trait;
use chrono::Duration;
use opsagent_core::{finding::FindingFilter, repo::Clock};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{
    filter_id, page_request, parse_args, schema_of, to_json, Access, Caller, Tool, ToolError,
    ToolSpec,
};
use crate::{
    actions::findings::ListFindings,
    views::{findings::full, page::MAX_LIMIT},
};

/// Check 01 (cost) as stored in `findings.check_id`.
const COST_CHECK: &str = "01";
const MAX_DAYS: u64 = 30;
const DEFAULT_DAYS: u64 = 7;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Args {
    /// Connection id, from `list_connections`.
    connection: Option<String>,
    /// Look back this many days: 1 to 30, default 7.
    days: Option<u64>,
}

/// Open cost anomalies seen lately.
pub struct GetCostAnomaliesTool {
    list: ListFindings,
    clock: Arc<dyn Clock>,
}

impl GetCostAnomaliesTool {
    pub fn new(list: ListFindings, clock: Arc<dyn Clock>) -> Self {
        Self { list, clock }
    }
}

#[async_trait]
impl Tool for GetCostAnomaliesTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "get_cost_anomalies",
            title: "Get cost anomalies",
            description:
                "Open cost anomalies (check 01 findings) seen within the last N days. Each \
                          summary carries the spend and its baseline.",
            input_schema: schema_of::<Args>(),
            access: Access::Read,
            idempotent: true,
        }
    }

    async fn call(&self, caller: &Caller, args: Value) -> Result<Value, ToolError> {
        let a: Args = parse_args(args)?;
        let days = a.days.unwrap_or(DEFAULT_DAYS);
        if !(1..=MAX_DAYS).contains(&days) {
            return Err(ToolError::Invalid(format!("days must be 1 to {MAX_DAYS}")));
        }
        let since = self.clock.now() - Duration::days(i64::try_from(days).unwrap_or(0));
        let filter = FindingFilter {
            connection_id: a.connection.as_deref().map(filter_id).transpose()?,
            // Open only: a resolved finding's `updated_at` moves when it resolves.
            status: Some("open".into()),
            check_id: Some(COST_CHECK.into()),
            variant: Some("cost_anomaly".into()),
            last_seen_since: Some(since),
            ..Default::default()
        };
        // shortcut: first page only; more than 200 anomalies in 30 days is not expected.
        let page = page_request(None, Some(MAX_LIMIT))?;
        let got = self
            .list
            .run(caller.scope.organisation.id, filter, page)
            .await?;
        let items: Vec<_> = got.items.into_iter().map(full).collect();
        Ok(json!({ "findings": to_json(&items)? }))
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::{
        finding::{FindingDraft, FindingKey, FindingsRepo, Severity},
        repo::FixedClock,
    };
    use uuid::Uuid;

    use super::*;
    use crate::{adapters::memory::MemStore, tools::test_support::caller};

    fn draft(conn: Uuid, check: &str, variant: &str) -> FindingDraft {
        FindingDraft {
            key: FindingKey {
                connection_id: conn,
                check_id: check.into(),
                resource_identity: format!("{check}/{variant}"),
                variant: variant.into(),
            },
            severity: Severity::High,
            title: "t".into(),
            summary: "spend 10 vs baseline 2".into(),
            next_step: "n".into(),
            cost_monthly_usd: None,
            evidence: vec![],
        }
    }

    #[tokio::test]
    async fn only_the_cost_anomaly_variant_within_the_window() {
        let store = MemStore::default();
        let (org, conn, run) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let now = chrono::Utc::now();
        let drafts = [
            draft(conn, "01", "cost_anomaly"),
            draft(conn, "01", "cost_other"),
            draft(conn, "no_mfa", "cost_anomaly"),
        ];
        store
            .upsert_seen(org, conn, run, &drafts, now)
            .await
            .unwrap();
        let tool = |t| {
            GetCostAnomaliesTool::new(
                ListFindings::new(Arc::new(store.clone())),
                Arc::new(FixedClock(t)),
            )
        };
        let got = tool(now).call(&caller(org), json!({})).await.unwrap();
        let f = got["findings"].as_array().unwrap();
        assert_eq!(f.len(), 1, "{got}");
        assert_eq!(f[0]["variant"], "cost_anomaly");
        assert_eq!(f[0]["check_id"], "01");
        // Eight days on, the default window of seven no longer reaches it; 30 does.
        let later = now + Duration::days(8);
        let got = tool(later).call(&caller(org), json!({})).await.unwrap();
        assert_eq!(got["findings"], json!([]));
        let got = tool(later)
            .call(&caller(org), json!({"days": 30}))
            .await
            .unwrap();
        assert_eq!(got["findings"].as_array().unwrap().len(), 1);
        for days in [31, 0] {
            let e = tool(now)
                .call(&caller(org), json!({"days": days}))
                .await
                .unwrap_err();
            assert_eq!(e.code(), "invalid");
        }
    }
}
