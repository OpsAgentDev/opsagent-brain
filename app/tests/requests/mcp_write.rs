//! The write tools over MCP (mcp-contract.md, "Version 0.3"): a read-only grant never reaches
//! a write Action, a write grant does what REST does, and the dashboard chat stays read-only.
use axum_test::TestServer;
use chrono::{Duration, Utc};
use opsagent_brain::{
    actions::ai::CHAT_TOOLS,
    models::_entities::{audit_events, connections, findings},
    tools::Access,
};
use opsagent_core::oauth::SCOPE_READ_WRITE;
use sea_orm::{entity::prelude::*, ConnectionTrait};
use serde_json::{json, Value};
use serial_test::serial;

use super::{
    mcp_auth::{call, mint_scoped, rpc, Agent},
    mcp_tools::{draft, result, seed, world},
    support::*,
};

const WRITE_TOOLS: [&str; 6] = [
    "accept_finding",
    "snooze_finding",
    "reopen_finding",
    "connect_cloud_account",
    "verify_connection",
    "run_check",
];
const ROLE_ARN: &str = "arn:aws:iam::123456789012:role/OpsAgentReadRole-abcd1234";

/// A token for the agent's member on a grant approved for changes.
async fn write_token(app: &TestApp, a: &Agent) -> String {
    let ttl = Duration::hours(1);
    mint_scoped(app, a.org, a.member, ttl, SCOPE_READ_WRITE)
        .await
        .1
}

/// The world of `mcp_tools` with one open finding; returns its id too.
async fn with_finding(req: &TestServer, app: &TestApp, email: &str) -> (Agent, Uuid, String) {
    let (a, conn, _) = world(req, app, email).await;
    seed(app, a.org, conn, &[draft(conn, "no_mfa", "", "u", "x")]).await;
    let got = call(req, &a.token, "list_findings", json!({})).await;
    let id = result(&got)["items"][0]["id"].as_str().unwrap().to_owned();
    (a, conn, id)
}

fn soon() -> String {
    (Utc::now() + Duration::days(2)).to_rfc3339()
}

async fn finding_statuses(app: &TestApp, org: Uuid) -> Vec<String> {
    let rows = findings::Entity::find()
        .filter(findings::Column::OrganisationId.eq(org))
        .all(&app.db)
        .await
        .unwrap();
    rows.into_iter().map(|f| f.status).collect()
}

async fn connection_statuses(app: &TestApp, org: Uuid) -> Vec<String> {
    let rows = connections::Entity::find()
        .filter(connections::Column::OrganisationId.eq(org))
        .all(&app.db)
        .await
        .unwrap();
    rows.into_iter().map(|c| c.status).collect()
}

async fn audit_count(app: &TestApp, org: Uuid, action: &str) -> u64 {
    audit_events::Entity::find()
        .filter(audit_events::Column::OrganisationId.eq(org))
        .filter(audit_events::Column::Action.eq(action))
        .count(&app.db)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn read_only_grant_is_refused_on_every_write_tool_and_changes_nothing() {
    serve(|req, app| async move {
        let (a, conn, id) = with_finding(&req, &app, "ro@example.com").await;
        let calls = [
            ("accept_finding", json!({"id": id, "reason": "fine"})),
            ("snooze_finding", json!({"id": id, "until": soon()})),
            ("reopen_finding", json!({"id": id})),
            ("connect_cloud_account", json!({"name": "Second"})),
            (
                "verify_connection",
                json!({"connection": conn.to_string(), "role_arn": ROLE_ARN}),
            ),
            ("run_check", json!({"connection": conn.to_string()})),
        ];
        assert_eq!(calls.clone().map(|(name, _)| name), WRITE_TOOLS);
        for (tool, args) in calls {
            let got = call(&req, &a.token, tool, args).await;
            assert_eq!(got["result"]["isError"], true, "{tool}: {got}");
            assert_eq!(
                result(&got),
                &json!({
                    "code": "insufficient_scope",
                    "message": "This connection is read-only. Revoke it under Settings > Connected agents, connect the agent again and tick 'Let this agent make changes'.",
                }),
                "{tool}"
            );
        }
        assert_eq!(finding_statuses(&app, a.org).await, ["open"]);
        assert_eq!(connection_statuses(&app, a.org).await, ["pending"]);
        for action in [
            "finding.accepted",
            "finding.snoozed",
            "finding.reopened",
            "connection.verify_requested",
        ] {
            assert_eq!(audit_count(&app, a.org, action).await, 0, "{action}");
        }
        // The one connection `world` made through REST is the only one ever created.
        assert_eq!(audit_count(&app, a.org, "connection.create").await, 1);
        // Each refusal is audited as the grant's call.
        let refused = audit_events::Entity::find()
            .filter(audit_events::Column::OrganisationId.eq(a.org))
            .filter(audit_events::Column::Outcome.eq("insufficient_scope"))
            .all(&app.db)
            .await
            .unwrap();
        assert_eq!(refused.len(), WRITE_TOOLS.len());
        for r in refused {
            assert_eq!(r.action, "mcp.tool.call");
            assert_eq!(r.actor_id.as_deref(), Some(a.grant.to_string().as_str()));
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn write_grant_triages_a_finding_like_rest() {
    serve(|req, app| async move {
        let (a, _, id) = with_finding(&req, &app, "tri@example.com").await;
        let token = write_token(&app, &a).await;
        let args = json!({"id": id, "reason": "staging only"});
        let got = call(&req, &token, "accept_finding", args).await;
        assert_eq!(got["result"]["isError"], false, "{got}");
        let f = result(&got);
        assert_eq!(f["status"], "accepted");
        assert_eq!(f["accepted_reason"], "staging only");
        assert_eq!(f["url"], format!("{WEB_ORIGIN}/o/{}/findings/{id}", a.slug));
        assert!(f["evidence"].is_array() && f["events"].is_array(), "{f}");
        // The same record REST shows, with the same link.
        let rest = req.get(&format!("/v1/orgs/{}/findings/{id}", a.slug)).await;
        let rest: Value = rest.json();
        assert_eq!(rest["status"], "accepted");
        assert_eq!(rest["url"], f["url"]);

        let got = call(&req, &token, "reopen_finding", json!({"id": id})).await;
        assert_eq!(result(&got)["status"], "open", "{got}");
        let args = json!({"id": id, "until": soon()});
        let got = call(&req, &token, "snooze_finding", args).await;
        assert_eq!(result(&got)["status"], "snoozed", "{got}");
        for action in ["finding.accepted", "finding.reopened", "finding.snoozed"] {
            assert_eq!(audit_count(&app, a.org, action).await, 1, "{action}");
        }

        // REST-equal errors: the Action's own validation and wording.
        let far = (Utc::now() + Duration::days(40)).to_rfc3339();
        let got = call(
            &req,
            &token,
            "snooze_finding",
            json!({"id": id, "until": far}),
        )
        .await;
        assert_eq!(result(&got)["code"], "invalid", "{got}");
        let rest = req
            .post(&format!("/v1/orgs/{}/findings/{id}/snooze", a.slug))
            .add_header("X-CSRF-Token", csrf(&req).await)
            .json(&json!({"until": far}))
            .await;
        assert_eq!(rest.status_code(), 422);
        assert_eq!(result(&got)["message"], rest.json::<Value>()["detail"]);
        let got = call(
            &req,
            &token,
            "accept_finding",
            json!({"id": id, "reason": " "}),
        )
        .await;
        assert_eq!(result(&got)["code"], "invalid");
        let other = Uuid::new_v4().to_string();
        let got = call(&req, &token, "reopen_finding", json!({"id": other})).await;
        assert_eq!(result(&got)["code"], "not_found");
        assert_eq!(finding_statuses(&app, a.org).await, ["snoozed"]);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn another_organisations_write_grant_cannot_touch_the_finding() {
    serve(|req, app| async move {
        let (a, conn, id) = with_finding(&req, &app, "iso-w@example.com").await;
        let csrf = csrf(&req).await;
        let other = create_org(&req, &csrf, "Beta").await;
        let other: Uuid = other["id"].as_str().unwrap().parse().unwrap();
        let m = super::mcp_auth::member_of(&app, other).await;
        let ttl = Duration::hours(1);
        let (_, token) = mint_scoped(&app, other, m, ttl, SCOPE_READ_WRITE).await;
        let calls = [
            ("accept_finding", json!({"id": id, "reason": "r"})),
            (
                "verify_connection",
                json!({"connection": conn.to_string(), "role_arn": ROLE_ARN}),
            ),
        ];
        for (tool, args) in calls {
            let got = call(&req, &token, tool, args).await;
            assert_eq!(result(&got)["code"], "not_found", "{tool}: {got}");
        }
        assert_eq!(finding_statuses(&app, a.org).await, ["open"]);
        assert_eq!(connection_statuses(&app, a.org).await, ["pending"]);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn owner_connects_and_verifies_a_cloud_account_and_a_member_cannot() {
    serve(|req, app| async move {
        let (a, _) = super::mcp_auth::agent(&req, &app, "conn@example.com", "Connect").await;
        let token = write_token(&app, &a).await;
        let got = call(
            &req,
            &token,
            "connect_cloud_account",
            json!({"name": "Prod"}),
        )
        .await;
        assert_eq!(got["result"]["isError"], false, "{got}");
        let c = result(&got);
        let id = c["connection_id"].as_str().unwrap().to_owned();
        let url = c["launch_url"].as_str().unwrap();
        assert!(url.starts_with("https://console.aws.amazon.com/cloudformation/home"));
        assert!(url.contains("param_ExternalId="), "{url}");
        assert_eq!(c["template_version"], "4");
        assert!(c["next_step"]
            .as_str()
            .unwrap()
            .contains("verify_connection"));
        // The same connection REST lists, pending until its role is reported.
        let rest = req
            .get(&format!("/v1/orgs/{}/connections/{id}", a.slug))
            .await;
        let rest: Value = rest.json();
        assert_eq!(
            (&rest["status"], &rest["display_name"]),
            (&json!("pending"), &json!("Prod"))
        );

        let bad = json!({"connection": id, "role_arn": "not-an-arn"});
        let got = call(&req, &token, "verify_connection", bad).await;
        assert_eq!(result(&got)["code"], "invalid", "{got}");
        assert_eq!(connection_statuses(&app, a.org).await, ["pending"]);
        let args = json!({"connection": id, "role_arn": ROLE_ARN});
        let got = call(&req, &token, "verify_connection", args.clone()).await;
        assert_eq!(got["result"]["isError"], false, "{got}");
        assert_eq!(
            result(&got),
            &json!({"status": "verifying", "status_reason": null})
        );
        assert_eq!(audit_count(&app, a.org, "connection.create").await, 1);
        assert_eq!(
            audit_count(&app, a.org, "connection.verify_requested").await,
            1
        );

        // The role is read on every call: the same grant, once its member is no longer an owner.
        app.db
            .execute_unprepared(&format!(
                "UPDATE members SET role = 'member' WHERE organisation_id = '{}' AND id = '{}'",
                a.org, a.member
            ))
            .await
            .unwrap();
        for (tool, args) in [
            ("connect_cloud_account", json!({"name": "Dev"})),
            ("verify_connection", args),
        ] {
            let got = call(&req, &token, tool, args).await;
            assert_eq!(
                result(&got),
                &json!({
                    "code": "forbidden",
                    "message": "Only an owner can connect a cloud account.",
                }),
                "{tool}"
            );
        }
        assert_eq!(connection_statuses(&app, a.org).await.len(), 1);
        assert_eq!(
            audit_count(&app, a.org, "connection.verify_requested").await,
            1
        );
        // A member still triages: REST lets any member accept, snooze and reopen.
        let got = call(
            &req,
            &token,
            "reopen_finding",
            json!({"id": Uuid::new_v4().to_string()}),
        )
        .await;
        assert_eq!(result(&got)["code"], "not_found");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn write_tools_are_annotated_and_instructions_follow_the_grant() {
    serve(|req, app| async move {
        let (a, _) = super::mcp_auth::agent(&req, &app, "ann@example.com", "Ann").await;
        let token = write_token(&app, &a).await;
        let body: Value = rpc(&req, Some(&a.token), "tools/list", json!({}))
            .await
            .json();
        let tools = body["result"]["tools"].as_array().unwrap();
        for name in WRITE_TOOLS {
            let t = tools.iter().find(|t| t["name"] == name).expect(name);
            assert_eq!(t["inputSchema"]["type"], "object", "{name}");
        }
        let init = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        });
        let instructions = |token: String| {
            let (req, init) = (&req, init.clone());
            async move {
                let body: Value = rpc(req, Some(&token), "initialize", init).await.json();
                body["result"]["instructions"].as_str().unwrap().to_owned()
            }
        };
        let read = instructions(a.token.clone()).await;
        assert!(read.contains("Everything here is read-only."), "{read}");
        let write = instructions(token).await;
        assert!(!write.contains("Everything here is read-only."), "{write}");
        for name in WRITE_TOOLS {
            assert!(!read.contains(name), "{name} in read-only instructions");
            assert!(write.contains(name), "{name} missing: {write}");
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn chat_has_no_write_tool() {
    serve(|_, app| async move {
        let specs = app.state.tools.specs();
        let mut write: Vec<_> = specs
            .iter()
            .filter(|s| s.access == Access::Write)
            .map(|s| s.name)
            .collect();
        let mut expected = WRITE_TOOLS.to_vec();
        write.sort_unstable();
        expected.sort_unstable();
        assert_eq!(write, expected);
        for name in CHAT_TOOLS {
            let spec = specs.iter().find(|s| s.name == name).expect(name);
            assert_eq!(spec.access, Access::Read, "{name} is offered to the chat");
        }
    })
    .await;
}
