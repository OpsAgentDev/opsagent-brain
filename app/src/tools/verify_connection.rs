use async_trait::async_trait;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{
    owner_only, parse_args, record_id, schema_of, Access, Caller, Tool, ToolError, ToolSpec,
};
use crate::actions::connections::{GetConnection, RequestVerify};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Args {
    /// Connection id, from `connect_cloud_account` or `list_connections`.
    connection: String,
    /// The stack output `RoleArn`: `arn:aws:iam::<account>:role/...`.
    role_arn: String,
}

/// Reports the read role and queues its verification: the same Action as REST's verify.
pub struct VerifyConnectionTool {
    verify: RequestVerify,
    get: GetConnection,
}

impl VerifyConnectionTool {
    pub fn new(verify: RequestVerify, get: GetConnection) -> Self {
        Self { verify, get }
    }
}

#[async_trait]
impl Tool for VerifyConnectionTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "verify_connection",
            title: "Verify a cloud connection",
            description: "Tells OpsAgent the read role's ARN (the stack output RoleArn) and \
                          queues its verification. Owners only. Returns the connection's status; \
                          poll list_connections and read its `status` and `status_reason`. \
                          `connected`: run_check may start the first scan. `pending` with \
                          `access_denied`: the cloud refused the role, so check the stack \
                          finished and the RoleArn is its output, then verify again.",
            input_schema: schema_of::<Args>(),
            access: Access::Write,
            idempotent: true,
        }
    }

    async fn call(&self, caller: &Caller, args: Value) -> Result<Value, ToolError> {
        let a: Args = parse_args(args)?;
        let id = record_id(&a.connection)?;
        self.verify
            .run(&caller.scope, id, &a.role_arn)
            .await
            .map_err(owner_only)?;
        let (c, _) = self.get.run(caller.scope.organisation.id, id).await?;
        Ok(json!({ "status": c.status, "status_reason": c.status_reason }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use opsagent_connectors::Registry;
    use opsagent_core::{org::Role, repo::SystemClock};
    use uuid::Uuid;

    use super::*;
    use crate::{
        actions::{
            billing::BillingGate,
            connections::{CreateConnection, QuickCreate},
            orgs::test_support::{kek, owned_org, scope},
            runs::RunDispatcher,
            uow::Repos,
        },
        adapters::memory::MemStore,
        config::Config,
        tools::{test_support::caller, ConnectCloudAccountTool},
    };

    const ROLE: &str = "arn:aws:iam::123456789012:role/OpsAgentRead";

    fn tools(store: &MemStore, principal: bool) -> (ConnectCloudAccountTool, VerifyConnectionTool) {
        let uow = Arc::new(store.clone());
        let clock = Arc::new(SystemClock);
        let config = Config::from_vars(|k| match k {
            "APP_ENV" => Some("test".into()),
            "OPSAGENT_AWS_OUTBOUND_ROLE_ARN" if principal => {
                Some("arn:aws:iam::111111111111:role/opsagent-outbound".into())
            }
            _ => None,
        })
        .unwrap();
        let links = QuickCreate::new(&config);
        let create = CreateConnection::new(
            uow.clone(),
            kek(),
            Registry::new(Default::default(), true),
            BillingGate::new(false, clock.clone()),
            links.clone(),
        );
        let dispatcher = Arc::new(RunDispatcher::new(uow.clone()));
        let verify = RequestVerify::new(uow.clone(), kek(), dispatcher, clock);
        (
            ConnectCloudAccountTool::new(create, links),
            VerifyConnectionTool::new(verify, GetConnection::new(uow)),
        )
    }

    /// The owner of a new organisation, as an MCP caller with a write grant.
    async fn owner(store: &MemStore) -> Caller {
        let (user, org) = owned_org(store, "own@example.com", "Acme").await;
        Caller {
            scope: scope(store, &org, &user).await,
            ..caller(org.id)
        }
    }

    #[tokio::test]
    async fn owner_connects_and_verifies_an_account() {
        let store = MemStore::default();
        let (connect, verify) = tools(&store, true);
        let me = owner(&store).await;
        let org = me.scope.organisation.id;
        let got = connect.call(&me, json!({"name": " Prod "})).await.unwrap();
        let url = got["launch_url"].as_str().unwrap();
        assert!(url.contains("quickcreate?templateURL="), "{url}");
        assert!(url.contains("param_ExternalId="), "{url}");
        assert_eq!(got["template_version"], "3");
        assert!(got["next_step"]
            .as_str()
            .unwrap()
            .contains("verify_connection"));
        let id: Uuid = got["connection_id"].as_str().unwrap().parse().unwrap();
        let c = store.connections().get(org, id).await.unwrap().unwrap();
        assert_eq!(c.display_name.as_deref(), Some("Prod"));
        let args = json!({"connection": id.to_string(), "role_arn": ROLE});
        let got = verify.call(&me, args.clone()).await.unwrap();
        assert_eq!(got, json!({"status": "verifying", "status_reason": null}));
        // Asking again is the same request, not a second connection.
        assert_eq!(verify.call(&me, args).await.unwrap()["status"], "verifying");
        assert_eq!(store.connections().list(org).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn member_is_forbidden_and_nothing_is_created() {
        let store = MemStore::default();
        let (connect, verify) = tools(&store, true);
        let me = owner(&store).await;
        let org = me.scope.organisation.id;
        let got = connect.call(&me, json!({"name": "Prod"})).await.unwrap();
        let id = got["connection_id"].as_str().unwrap().to_owned();
        let mut member = me.clone();
        member.scope.member.role = Role::Member;
        let refusals = [
            connect.call(&member, json!({"name": "Dev"})).await,
            verify
                .call(&member, json!({"connection": id, "role_arn": ROLE}))
                .await,
        ];
        for r in refusals {
            let e = r.unwrap_err();
            assert_eq!(e.code(), "forbidden");
            assert_eq!(e.to_string(), "Only an owner can connect a cloud account.");
        }
        let all = store.connections().list(org).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(
            all[0].status,
            opsagent_core::connection::ConnectionStatus::Pending
        );
    }

    #[tokio::test]
    async fn errors_match_rest() {
        let store = MemStore::default();
        let (connect, verify) = tools(&store, true);
        let me = owner(&store).await;
        for bad in [json!({}), json!({"name": ""}), json!({"name": "a\nb"})] {
            let e = connect.call(&me, bad).await.unwrap_err();
            assert_eq!(e.code(), "invalid");
        }
        let got = connect.call(&me, json!({"name": "Prod"})).await.unwrap();
        let id = got["connection_id"].as_str().unwrap().to_owned();
        let e = verify
            .call(&me, json!({"connection": id, "role_arn": "nope"}))
            .await
            .unwrap_err();
        assert_eq!(e.to_string(), "role_arn must be an IAM role ARN");
        for unknown in [Uuid::new_v4().to_string(), "nope".into()] {
            let args = json!({"connection": unknown, "role_arn": ROLE});
            assert_eq!(
                verify.call(&me, args).await.unwrap_err().code(),
                "not_found"
            );
        }
        // Without the outbound role there is no link to give: REST's 503, before any row.
        let (connect, _) = tools(&store, false);
        let e = connect.call(&me, json!({"name": "Dev"})).await.unwrap_err();
        assert_eq!(e.code(), "connector_unavailable");
        let org = me.scope.organisation.id;
        assert_eq!(store.connections().list(org).await.unwrap().len(), 1);
    }
}
