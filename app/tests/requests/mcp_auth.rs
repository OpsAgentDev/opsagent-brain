use axum_test::{TestResponse, TestServer};
use chrono::{Duration, Utc};
use opsagent_brain::{
    models::_entities::audit_events,
    tokens::{hash_token, new_token},
};
use opsagent_core::oauth::{AccessToken, Grant};
use sea_orm::entity::prelude::*;
use serde_json::{json, Value};
use serial_test::serial;

use super::{oauth_authorize::*, support::*};

const META: &str =
    "Bearer resource_metadata=\"http://localhost:5150/.well-known/oauth-protected-resource/mcp\", scope=\"opsagent.read\"";

/// An organisation, its owner's member id, and an access token for a grant on it.
struct Agent {
    slug: String,
    org: Uuid,
    member: Uuid,
    grant: Uuid,
    token: String,
}

/// Signs in `email` (session kept on `req`), creates `org_name`, and mints a token.
async fn agent(req: &TestServer, app: &TestApp, email: &str, org_name: &str) -> (Agent, String) {
    let mail = prepare(app);
    let csrf = sign_in(req, &mail, email).await;
    let org = create_org(req, &csrf, org_name).await;
    let slug = slug(&org);
    let members = req
        .get(&format!("/v1/orgs/{slug}/members"))
        .await
        .json::<Vec<Value>>();
    let member: Uuid = members[0]["id"].as_str().unwrap().parse().unwrap();
    let org: Uuid = org["id"].as_str().unwrap().parse().unwrap();
    client(app).await;
    let (grant, token) = mint(app, org, member, Duration::hours(1)).await;
    let a = Agent {
        slug,
        org,
        member,
        grant,
        token,
    };
    (a, csrf)
}

/// A grant for `member` and an access token expiring after `ttl`.
async fn mint(app: &TestApp, org: Uuid, member: Uuid, ttl: Duration) -> (Uuid, String) {
    let o = app.state.uow.oauth();
    let g = Grant {
        id: Uuid::new_v4(),
        client_id: CLIENT.into(),
        member_id: member,
        organisation_id: org,
        created_at: Utc::now(),
        last_used_at: None,
        revoked_at: None,
    };
    o.insert_grant(&g).await.unwrap();
    let token = new_token();
    o.insert_access(&AccessToken {
        id: Uuid::new_v4(),
        grant_id: g.id,
        organisation_id: org,
        token_hash: hash_token(&token),
        expires_at: Utc::now() + ttl,
    })
    .await
    .unwrap();
    (g.id, token)
}

async fn rpc(req: &TestServer, token: Option<&str>, method: &str, params: Value) -> TestResponse {
    let mut r = req
        .post("/mcp")
        .add_header("Host", "localhost:5150")
        .add_header("Accept", "application/json, text/event-stream")
        .add_header("MCP-Protocol-Version", "2025-11-25");
    if let Some(t) = token {
        r = r.add_header("Authorization", format!("Bearer {t}"));
    }
    r.json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .await
}

async fn call(req: &TestServer, token: &str, tool: &str, args: Value) -> Value {
    let res = rpc(
        req,
        Some(token),
        "tools/call",
        json!({"name": tool, "arguments": args}),
    )
    .await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
    res.json::<Value>()
}

fn assert_401(res: &TestResponse) {
    assert_eq!(res.status_code(), 401, "{}", res.text());
    assert_eq!(res.header("www-authenticate").to_str().unwrap(), META);
}

#[tokio::test]
#[serial]
async fn no_token_is_401_with_resource_metadata() {
    serve(|req, _| async move {
        assert_401(&rpc(&req, None, "tools/list", json!({})).await);
        assert_401(&rpc(&req, Some("not-a-token"), "tools/list", json!({})).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn expired_token_is_401() {
    serve(|req, app| async move {
        let (a, _) = agent(&req, &app, "exp@example.com", "Exp").await;
        let (_, old) = mint(&app, a.org, a.member, Duration::seconds(-1)).await;
        assert_401(&rpc(&req, Some(&old), "tools/list", json!({})).await);
        assert_eq!(
            rpc(&req, Some(&a.token), "tools/list", json!({}))
                .await
                .status_code(),
            200
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn removed_member_token_is_rejected_next_call() {
    serve(|req, app| async move {
        let (a, _) = agent(&req, &app, "rm@example.com", "Removal").await;
        assert_eq!(
            rpc(&req, Some(&a.token), "tools/list", json!({}))
                .await
                .status_code(),
            200
        );
        // Bypasses the revocation that member removal does: the scope check alone refuses.
        assert!(app
            .state
            .uow
            .orgs()
            .remove_member(a.org, a.member)
            .await
            .unwrap());
        assert_401(&rpc(&req, Some(&a.token), "tools/list", json!({})).await);
        let grant = app.state.uow.oauth().grant(a.org, a.grant).await.unwrap();
        assert!(grant.unwrap().revoked_at.is_none());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn initialize_and_list_tools() {
    serve(|req, app| async move {
        let (a, _) = agent(&req, &app, "init@example.com", "Init").await;
        let init = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        });
        let res = rpc(&req, Some(&a.token), "initialize", init).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert!(res.maybe_header("mcp-session-id").is_none());
        let body: Value = res.json();
        assert_eq!(body["result"]["protocolVersion"], "2025-11-25", "{body}");
        assert!(
            body["result"]["capabilities"]["tools"].is_object(),
            "{body}"
        );
        let res = rpc(&req, Some(&a.token), "tools/list", json!({})).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let body: Value = res.json();
        let tools = body["result"]["tools"].as_array().unwrap();
        let t = tools
            .iter()
            .find(|t| t["name"] == "list_connections")
            .unwrap();
        assert_eq!(t["inputSchema"]["type"], "object");
        assert_eq!(
            t["annotations"],
            json!({
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false,
            })
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn list_connections_is_org_scoped() {
    serve(|req, app| async move {
        let (a, csrf) = agent(&req, &app, "scope@example.com", "Alpha").await;
        let conn = create_connection(&req, &csrf, &a.slug, "aws", "Prod").await;
        let other = create_org(&req, &csrf, "Beta").await;
        let other: Uuid = other["id"].as_str().unwrap().parse().unwrap();
        let (_, b_token) = mint(
            &app,
            other,
            member_of(&app, other).await,
            Duration::hours(1),
        )
        .await;
        let got = call(&req, &a.token, "list_connections", json!({})).await;
        let list = &got["result"]["structuredContent"]["connections"];
        assert_eq!(list.as_array().unwrap().len(), 1, "{got}");
        assert_eq!(list[0]["id"], conn["id"]);
        assert_eq!(list[0]["provider"], "aws");
        assert_eq!(list[0]["name"], "Prod");
        assert_eq!(list[0]["status"], "pending");
        assert_eq!(list[0]["last_scan"], Value::Null);
        assert!(got["result"]["content"][0]["text"].is_string());
        let got = call(&req, &b_token, "list_connections", json!({})).await;
        assert_eq!(got["result"]["structuredContent"]["connections"], json!([]));
    })
    .await;
}

async fn member_of(app: &TestApp, org: Uuid) -> Uuid {
    app.state.uow.orgs().members(org).await.unwrap()[0].id
}

#[tokio::test]
#[serial]
async fn token_rate_limit_61st_call_is_429() {
    serve(|req, app| async move {
        let (a, _) = agent(&req, &app, "rate@example.com", "Rate").await;
        for i in 0..60 {
            let res = rpc(&req, Some(&a.token), "tools/list", json!({})).await;
            assert_eq!(res.status_code(), 200, "call {i}");
        }
        let res = rpc(&req, Some(&a.token), "tools/list", json!({})).await;
        assert_eq!(res.status_code(), 429);
        assert_eq!(res.header("retry-after"), "60");
        // Another token on the same grant has its own budget.
        let (_, fresh) = mint(&app, a.org, a.member, Duration::hours(1)).await;
        assert_eq!(
            rpc(&req, Some(&fresh), "tools/list", json!({}))
                .await
                .status_code(),
            200
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn wrong_host_header_is_rejected() {
    serve(|req, app| async move {
        let (a, _) = agent(&req, &app, "host@example.com", "Host").await;
        let res = req
            .post("/mcp")
            .add_header("Host", "evil.example")
            .add_header("Accept", "application/json, text/event-stream")
            .add_header("Authorization", format!("Bearer {}", a.token))
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
            .await;
        assert_eq!(res.status_code(), 403, "{}", res.text());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn mcp_cors_for_any_origin() {
    serve(|req, _| async move {
        let origin = "https://any.example";
        let res = req
            .method(axum::http::Method::OPTIONS, "/mcp")
            .add_header("Origin", origin)
            .add_header("Access-Control-Request-Method", "POST")
            .add_header(
                "Access-Control-Request-Headers",
                "authorization,content-type,mcp-protocol-version",
            )
            .await;
        assert!(res.status_code().is_success(), "{}", res.status_code());
        assert_eq!(res.header("access-control-allow-origin"), "*");
        assert!(res
            .maybe_header("access-control-allow-credentials")
            .is_none());
        let res = req
            .post("/mcp")
            .add_header("Origin", origin)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
            .await;
        assert_401(&res);
        assert_eq!(res.header("access-control-allow-origin"), "*");
        let exposed = res.header("access-control-expose-headers");
        assert!(exposed.to_str().unwrap().contains("www-authenticate"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn tool_call_is_audited_without_arguments() {
    serve(|req, app| async move {
        let (a, _) = agent(&req, &app, "audit@example.com", "Audit").await;
        let got = call(&req, &a.token, "list_connections", json!({})).await;
        assert_eq!(got["result"]["isError"], false, "{got}");
        let got = call(
            &req,
            &a.token,
            "list_connections",
            json!({"secret": "s3cret"}),
        )
        .await;
        assert_eq!(got["result"]["isError"], true, "{got}");
        assert_eq!(
            got["result"]["structuredContent"]["code"], "invalid",
            "{got}"
        );
        let rows = audit_events::Entity::find()
            .filter(audit_events::Column::OrganisationId.eq(a.org))
            .filter(audit_events::Column::Action.eq("mcp.tool.call"))
            .all(&app.db)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        let mut outcomes = Vec::new();
        for r in &rows {
            assert_eq!(r.actor_type, "mcp_client");
            assert_eq!(r.actor_id.as_deref(), Some(a.grant.to_string().as_str()));
            let outcome = r.outcome.clone().unwrap();
            assert_eq!(
                r.metadata,
                json!({"client_id": CLIENT, "tool": "list_connections", "outcome": outcome})
            );
            outcomes.push(outcome);
        }
        outcomes.sort();
        assert_eq!(outcomes, ["invalid", "success"]);
        // An unknown tool is a protocol error, not a call.
        let got = call(&req, &a.token, "remediate", json!({})).await;
        assert!(
            got["error"]["message"]
                .as_str()
                .unwrap()
                .contains("remediate"),
            "{got}"
        );
    })
    .await;
}
