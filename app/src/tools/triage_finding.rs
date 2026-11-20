//! `accept_finding`, `snooze_finding` and `reopen_finding`: the customer's actions on a finding,
//! through the same Action as REST. They change OpsAgent's record only, never the cloud account.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use super::{
    link_base, parse_args, record_id, schema_of, to_json, Access, Caller, Tool, ToolError, ToolSpec,
};
use crate::{
    actions::findings::{ChangeFindingStatus, FindingAction, GetFinding},
    views::findings::detail,
};

const REASON_MAX: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Triage {
    Accept,
    Snooze,
    Reopen,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AcceptArgs {
    /// Finding id, from `list_findings`.
    id: String,
    /// Why the risk is accepted, in the person's words: 1 to 500 characters.
    reason: String,
    /// RFC 3339 time the acceptance ends; default 90 days from now, at most 365.
    until: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SnoozeArgs {
    /// Finding id, from `list_findings`.
    id: String,
    /// RFC 3339 time the finding comes back; in the future, at most 30 days ahead.
    until: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReopenArgs {
    /// Finding id, from `list_findings`.
    id: String,
}

fn time(raw: &str) -> Result<DateTime<Utc>, ToolError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.to_utc())
        .map_err(|_| ToolError::Invalid("until must be an RFC 3339 time".into()))
}

/// One of the three triage tools (`kind`); the result is the finding detail after the change.
pub struct TriageFindingTool {
    kind: Triage,
    change: ChangeFindingStatus,
    get: GetFinding,
    web_base_url: String,
}

impl TriageFindingTool {
    pub fn new(
        kind: Triage,
        change: ChangeFindingStatus,
        get: GetFinding,
        web_base_url: String,
    ) -> Self {
        Self {
            kind,
            change,
            get,
            web_base_url,
        }
    }

    /// The finding id and the action the arguments ask for.
    fn parse(&self, args: Value) -> Result<(String, FindingAction), ToolError> {
        Ok(match self.kind {
            Triage::Accept => {
                let a: AcceptArgs = parse_args(args)?;
                let chars = a.reason.trim().chars().count();
                if chars == 0 || chars > REASON_MAX {
                    return Err(ToolError::Invalid(format!(
                        "reason is required (at most {REASON_MAX} characters)"
                    )));
                }
                let action = FindingAction::Accept {
                    reason: Some(a.reason),
                    until: a.until.as_deref().map(time).transpose()?,
                };
                (a.id, action)
            }
            Triage::Snooze => {
                let a: SnoozeArgs = parse_args(args)?;
                let until = time(&a.until)?;
                (a.id, FindingAction::Snooze { until })
            }
            Triage::Reopen => {
                let a: ReopenArgs = parse_args(args)?;
                (a.id, FindingAction::Reopen)
            }
        })
    }
}

#[async_trait]
impl Tool for TriageFindingTool {
    fn spec(&self) -> ToolSpec {
        let (name, title, description, input_schema) = match self.kind {
            Triage::Accept => (
                "accept_finding",
                "Accept a finding",
                "Marks a finding as an accepted risk, with the reason, until a date (default 90 \
                 days). It changes OpsAgent's record only, not the cloud account. Use it when \
                 the person says the risk is acceptable. Returns the finding.",
                schema_of::<AcceptArgs>(),
            ),
            Triage::Snooze => (
                "snooze_finding",
                "Snooze a finding",
                "Hides a finding until a time at most 30 days ahead, then it is open again. It \
                 changes OpsAgent's record only, not the cloud account. Returns the finding.",
                schema_of::<SnoozeArgs>(),
            ),
            Triage::Reopen => (
                "reopen_finding",
                "Reopen a finding",
                "Makes an accepted or snoozed finding open again. It changes OpsAgent's record \
                 only, not the cloud account. Returns the finding.",
                schema_of::<ReopenArgs>(),
            ),
        };
        ToolSpec {
            name,
            title,
            description,
            input_schema,
            access: Access::Write,
            idempotent: true,
        }
    }

    async fn call(&self, caller: &Caller, args: Value) -> Result<Value, ToolError> {
        let (id, action) = self.parse(args)?;
        let (org, id) = (caller.scope.organisation.id, record_id(&id)?);
        self.change
            .run(org, caller.scope.member.user_id, id, action)
            .await?;
        let d = self.get.run(org, id).await?;
        to_json(&detail(d, &link_base(&self.web_base_url, caller)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Duration;
    use opsagent_core::repo::SystemClock;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::{
        actions::{
            billing::BillingGate, findings::test_support::seeded, orgs::test_support::owned_org,
            uow::Repos,
        },
        adapters::memory::MemStore,
        tools::test_support::caller,
    };

    fn tool(store: &MemStore, kind: Triage) -> TriageFindingTool {
        gated_tool(store, kind, false)
    }

    fn gated_tool(store: &MemStore, kind: Triage, enforced: bool) -> TriageFindingTool {
        let uow = Arc::new(store.clone());
        let gate = BillingGate::new(enforced, Arc::new(SystemClock));
        TriageFindingTool::new(
            kind,
            ChangeFindingStatus::new(uow.clone(), Arc::new(SystemClock), gate),
            GetFinding::new(uow),
            "https://web.test".into(),
        )
    }

    async fn status(store: &MemStore, org: Uuid, id: Uuid) -> String {
        let f = store.findings().get(org, id).await.unwrap().unwrap();
        f.status
    }

    #[tokio::test]
    async fn accept_snooze_and_reopen_change_the_finding_and_return_it() {
        let store = MemStore::default();
        let org = Uuid::new_v4();
        let (id, _) = seeded(&store, org, "x").await;
        let me = caller(org);
        let args = json!({"id": id.to_string(), "reason": " staging only "});
        let got = tool(&store, Triage::Accept).call(&me, args).await.unwrap();
        assert_eq!(got["status"], "accepted");
        assert_eq!(got["accepted_reason"], "staging only");
        assert_eq!(got["url"], format!("https://web.test/o/o/findings/{id}"));
        assert_eq!(got["events"][0]["event_type"], "accepted");
        let reopen = tool(&store, Triage::Reopen);
        let got = reopen.call(&me, json!({"id": id.to_string()})).await;
        assert_eq!(got.unwrap()["status"], "open");
        let until = (Utc::now() + Duration::days(3)).to_rfc3339();
        let args = json!({"id": id.to_string(), "until": until});
        let got = tool(&store, Triage::Snooze).call(&me, args).await.unwrap();
        assert_eq!(got["status"], "snoozed");
        assert!(got["snoozed_until"].is_string());
        // Each change is audited by the Action as the member, like REST.
        let actions: Vec<_> = store
            .audit_entries()
            .into_iter()
            .map(|a| a.action)
            .collect();
        assert_eq!(
            actions,
            ["finding.accepted", "finding.reopened", "finding.snoozed"]
        );
    }

    /// A read-only organisation (billing enforced, never subscribed) cannot triage through an
    /// agent, as it cannot through REST; the finding and the audit log stay as they were.
    #[tokio::test]
    async fn read_only_organisation_gets_billing_required_and_nothing_changes() {
        let store = MemStore::default();
        let (_, o) = owned_org(&store, "own@example.com", "Acme").await;
        let (id, _) = seeded(&store, o.id, "x").await;
        let (me, id_s) = (caller(o.id), id.to_string());
        let until = (Utc::now() + Duration::days(3)).to_rfc3339();
        let before = store.audit_entries().len();
        for (kind, args) in [
            (Triage::Accept, json!({"id": id_s, "reason": "r"})),
            (Triage::Snooze, json!({"id": id_s, "until": until})),
            (Triage::Reopen, json!({"id": id_s})),
        ] {
            let e = gated_tool(&store, kind, true).call(&me, args).await;
            assert_eq!(e.unwrap_err().code(), "billing_required", "{kind:?}");
        }
        assert_eq!(status(&store, o.id, id).await, "open");
        assert_eq!(store.audit_entries().len(), before);
        // Not enforced, the same organisation triages.
        let args = json!({"id": id_s, "reason": "r"});
        let got = tool(&store, Triage::Accept).call(&me, args).await.unwrap();
        assert_eq!(got["status"], "accepted");
    }

    #[tokio::test]
    async fn bad_arguments_and_other_orgs_change_nothing() {
        let store = MemStore::default();
        let org = Uuid::new_v4();
        let (id, _) = seeded(&store, org, "x").await;
        let (me, id_s) = (caller(org), id.to_string());
        let past = (Utc::now() - Duration::days(1)).to_rfc3339();
        let far = (Utc::now() + Duration::days(31)).to_rfc3339();
        let invalid = [
            (Triage::Accept, json!({"id": id_s})),
            (Triage::Accept, json!({"id": id_s, "reason": "  "})),
            (
                Triage::Accept,
                json!({"id": id_s, "reason": "x".repeat(501)}),
            ),
            (
                Triage::Accept,
                json!({"id": id_s, "reason": "r", "until": "tomorrow"}),
            ),
            (Triage::Snooze, json!({"id": id_s})),
            (Triage::Snooze, json!({"id": id_s, "until": past})),
            (Triage::Snooze, json!({"id": id_s, "until": far})),
            // Only an accepted or snoozed finding reopens: the same rule as REST.
            (Triage::Reopen, json!({"id": id_s})),
            (Triage::Reopen, json!({"id": id_s, "extra": 1})),
        ];
        for (kind, args) in invalid {
            let e = tool(&store, kind).call(&me, args.clone()).await;
            assert_eq!(e.unwrap_err().code(), "invalid", "{kind:?} {args}");
        }
        let other = caller(Uuid::new_v4());
        for id in [id_s.as_str(), "nope"] {
            let args = json!({"id": id, "reason": "r"});
            let e = tool(&store, Triage::Accept).call(&other, args).await;
            assert_eq!(e.unwrap_err().code(), "not_found");
        }
        assert_eq!(status(&store, org, id).await, "open");
        assert!(store.audit_entries().is_empty());
    }
}
