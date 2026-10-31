//! Dashboard AI settings, connections per slot and top-ups (Plan 5 Task 3, Plan 7 Task 6).
use std::sync::Arc;

use async_trait::async_trait;
use axum_test::{TestResponse, TestServer};
use opsagent_brain::{adapters::db::Pg, config::Config, models::_entities::audit_events};
use opsagent_core::{
    ai::AiRepo,
    billing::BillingRepo,
    model::{Endpoint, ModelError, ModelInfo, ModelProvider, ModelRequest, ModelTurn, TextSink},
};
use sea_orm::{prelude::Decimal, ColumnTrait, EntityTrait, QueryFilter};
use serde_json::{json, Value};
use serial_test::serial;
use uuid::Uuid;
use wiremock::{
    matchers::{body_string_contains, header, header_regex, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::{
    billing::{deliver, event, org_with_customer, stripe_on},
    support::*,
};

const KEY: &str = "sk-ant-api03-secret-key-wxyz";
const BACKUP_KEY: &str = "sk-ant-api03-backup-key-bkup";
/// A compatible vendor's key: no official prefix.
const CUSTOM_KEY: &str = "gsk_custom_key_1234";

/// Lists `models` for any key; never streams.
struct ListOnly(Vec<ModelInfo>);

#[async_trait]
impl ModelProvider for ListOnly {
    async fn stream(
        &self,
        _: &Endpoint<'_>,
        _: &ModelRequest,
        _: &mut dyn TextSink,
    ) -> Result<ModelTurn, ModelError> {
        unreachable!("settings make no model call")
    }

    async fn list_models(&self, _: &Endpoint<'_>) -> Result<Vec<ModelInfo>, ModelError> {
        Ok(self.0.clone())
    }
}

fn models(ctx: &TestApp, list: &[(&str, bool)]) {
    let list = list
        .iter()
        .map(|(id, tools)| ModelInfo {
            id: (*id).into(),
            tools: *tools,
        })
        .collect();
    ctx.state.set_models(Arc::new(ListOnly(list)));
}

/// The test app's one model cell holds the Anthropic adapter; custom endpoints here are
/// OpenAI-style.
fn openai(ctx: &TestApp) {
    let live = opsagent_brain::adapters::model::openai::OpenAiModels::new();
    ctx.state.set_models(Arc::new(live));
}

/// Custom URLs may point at the local mocks.
fn private(c: &mut Config) {
    c.allow_private = true;
}

async fn audits(ctx: &TestApp, action: &str) -> Vec<audit_events::Model> {
    audit_events::Entity::find()
        .filter(audit_events::Column::Action.eq(action))
        .all(&ctx.db)
        .await
        .unwrap()
}

async fn status(req: &TestServer, org: &str) -> Value {
    let res = req.get(&format!("/v1/orgs/{org}/ai")).await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
    res.json()
}

async fn patch_ai(req: &TestServer, csrf: &str, org: &str, body: Value) -> TestResponse {
    req.patch(&format!("/v1/orgs/{org}/ai"))
        .add_header("X-CSRF-Token", csrf)
        .json(&body)
        .await
}

async fn enable(req: &TestServer, csrf: &str, org: &str, on: bool) -> TestResponse {
    patch_ai(req, csrf, org, json!({ "enabled": on })).await
}

async fn put_slot(
    req: &TestServer,
    csrf: &str,
    org: &str,
    slot: &str,
    body: Value,
) -> TestResponse {
    req.put(&format!("/v1/orgs/{org}/ai/keys/{slot}"))
        .add_header("X-CSRF-Token", csrf)
        .json(&body)
        .await
}

async fn put_key(req: &TestServer, csrf: &str, org: &str, key: &str) -> TestResponse {
    let body = json!({ "style": "anthropic", "api_key": key });
    put_slot(req, csrf, org, "primary", body).await
}

/// An OpenAI-style connection on `server`'s `/v1`.
fn custom(server: &MockServer, key: &str) -> Value {
    json!({ "style": "openai", "base_url": format!("{}/v1", server.uri()), "api_key": key })
}

fn with_models(mut body: Value, routine: &str, chat: &str) -> Value {
    body["models"] = json!({ "routine": routine, "chat": chat });
    body
}

async fn patch_slot(
    req: &TestServer,
    csrf: &str,
    org: &str,
    slot: &str,
    body: Value,
) -> TestResponse {
    req.patch(&format!("/v1/orgs/{org}/ai/keys/{slot}"))
        .add_header("X-CSRF-Token", csrf)
        .json(&body)
        .await
}

fn delete_slot(req: &TestServer, csrf: &str, org: &str, slot: &str) -> axum_test::TestRequest {
    req.delete(&format!("/v1/orgs/{org}/ai/keys/{slot}"))
        .add_header("X-CSRF-Token", csrf)
}

async fn mount_list(server: &MockServer, ids: &[&str]) {
    let data: Vec<Value> = ids.iter().map(|id| json!({ "id": id })).collect();
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": data })))
        .mount(server)
        .await;
}

async fn mount_no_list(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
}

/// The 1-token check answers with `status` (200: one capped chunk).
async fn mount_check(server: &MockServer, status: u16) {
    let sse = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"O\"},\"finish_reason\":\"length\"}]}\n\ndata: [DONE]\n\n";
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(status).set_body_raw(sse, "text/event-stream"))
        .mount(server)
        .await;
}

async fn posts(server: &MockServer) -> Vec<Value> {
    let reqs = server.received_requests().await.unwrap();
    reqs.iter()
        .filter(|r| r.method.as_str() == "POST")
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

fn code(res: &TestResponse) -> String {
    res.json::<Value>()["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// Status and problem code.
fn refusal(res: &TestResponse) -> (u16, String) {
    (res.status_code().as_u16(), code(res))
}

async fn owner(req: &TestServer, ctx: &TestApp) -> (String, String) {
    let mail = prepare(ctx);
    let t = sign_in(req, &mail, "owner@example.com").await;
    let org = slug(&create_org(req, &t, "Acme").await);
    (t, org)
}

#[tokio::test]
#[serial]
async fn enable_owner_only_with_csrf_and_audited() {
    serve(|req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        let s = status(&req, &org).await;
        assert_eq!(
            (s["enabled"].as_bool(), s["state"].as_str()),
            (Some(false), Some("ai_disabled"))
        );
        assert_eq!(s["usage"]["quota"], "1000.00");
        assert_eq!(s["usage"]["used"], "0.00");
        assert_eq!(s["source"], Value::Null);
        assert_eq!(s["keys"], json!({ "primary": null, "backup": null }));
        assert_eq!(s["monthly_credit_ceiling"], Value::Null);
        assert_eq!(s["topup_available"], false);
        let no_csrf = req
            .patch(&format!("/v1/orgs/{org}/ai"))
            .json(&json!({ "enabled": true }))
            .await;
        assert_eq!(no_csrf.status_code(), 403);
        let on = enable(&req, &t, &org, true).await;
        assert_eq!(on.status_code(), 200, "{}", on.text());
        let on: Value = on.json();
        // No OpsAgent key configured and no BYOK key: dark.
        assert_eq!(
            (on["enabled"].as_bool(), on["state"].as_str()),
            (Some(true), Some("ai_unavailable"))
        );
        assert_eq!(audits(&ctx, "ai.enable").await.len(), 1);
        assert_eq!(enable(&req, &t, &org, false).await.status_code(), 200);
        assert_eq!(audits(&ctx, "ai.disable").await.len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn member_sees_status_but_cannot_enable() {
    serve(|mut req, ctx| async move {
        let (_, org) = owner(&req, &ctx).await;
        let mail = prepare(&ctx);
        let t = as_member(&mut req, &ctx, &mail, &org, "member@example.com").await;
        assert_eq!(status(&req, &org).await["state"], "ai_disabled");
        assert_eq!(enable(&req, &t, &org, true).await.status_code(), 403);
        let ceiling = json!({ "monthly_credit_ceiling": 5 });
        assert_eq!(patch_ai(&req, &t, &org, ceiling).await.status_code(), 403);
        assert_eq!(put_key(&req, &t, &org, KEY).await.status_code(), 403);
        let m = json!({ "models": { "routine": "a", "chat": "b" } });
        assert_eq!(
            patch_slot(&req, &t, &org, "primary", m).await.status_code(),
            403
        );
        assert_eq!(
            delete_slot(&req, &t, &org, "primary").await.status_code(),
            403
        );
        let listed = req
            .get(&format!("/v1/orgs/{org}/ai/keys/primary/models"))
            .await;
        assert_eq!(listed.status_code(), 403);
        let topup = req
            .post(&format!("/v1/orgs/{org}/ai/topup"))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(topup.status_code(), 403);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn put_key_bad_shape_422_no_network() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&api)
        .await;
    let base = api.uri();
    serve_with(
        move |c| c.anthropic_api_base = base,
        |req, ctx| async move {
            let (t, org) = owner(&req, &ctx).await;
            for bad in [
                "sk-proj-123456789012345678",
                "sk-ant-short",
                "sk-ant-has space 1234567890",
            ] {
                let res = put_key(&req, &t, &org, bad).await;
                assert_eq!(res.status_code(), 422, "{bad}");
                assert_eq!(code(&res), "ai_key_invalid");
            }
            let unknown = json!({ "style": "gemini", "api_key": KEY });
            let res = put_slot(&req, &t, &org, "primary", unknown).await;
            assert_eq!(refusal(&res), (422, "invalid".into()));
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn put_key_validates_with_models_list() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("x-api-key", KEY))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .expect(1)
        .mount(&api)
        .await;
    let list = json!({ "data": [{ "id": "claude-sonnet-4-5" }, { "id": "claude-haiku-4-5" }] });
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list))
        .mount(&api)
        .await;
    let base = api.uri();
    serve_with(
        move |c| c.anthropic_api_base = base,
        |req, ctx| async move {
            let (t, org) = owner(&req, &ctx).await;
            let refused = put_key(&req, &t, &org, KEY).await;
            assert_eq!(refused.status_code(), 422, "{}", refused.text());
            assert_eq!(code(&refused), "ai_key_invalid");
            let saved = put_key(&req, &t, &org, KEY).await;
            assert_eq!(saved.status_code(), 200, "{}", saved.text());
            assert!(!saved.text().contains(KEY));
            let out: Value = saved.json();
            let live = json!([{ "id": "claude-sonnet-4-5", "tools": true, "default_for": "chat" },
                { "id": "claude-haiku-4-5", "tools": true, "default_for": "routine" }]);
            assert_eq!(out["models"], live);
            let s = &out["status"];
            assert_eq!(s["source"], "byok");
            let k = &s["keys"]["primary"];
            assert_eq!(
                (k["style"].as_str(), k["last4"].as_str()),
                (Some("anthropic"), Some("wxyz"))
            );
            assert_eq!(
                (k["status"].as_str(), k["base_host"].clone()),
                (Some("ok"), Value::Null)
            );
            // The preferred defaults present on the live list.
            assert_eq!(
                k["models"],
                json!({ "routine": "claude-haiku-4-5", "chat": "claude-sonnet-4-5" })
            );
            assert_eq!(s["keys"]["backup"], Value::Null);
            let listed = req
                .get(&format!("/v1/orgs/{org}/ai/keys/primary/models"))
                .await;
            assert_eq!(listed.status_code(), 200, "{}", listed.text());
            assert_eq!(listed.json::<Value>(), live);
            let empty = req
                .get(&format!("/v1/orgs/{org}/ai/keys/backup/models"))
                .await;
            assert_eq!(empty.status_code(), 404);
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn patch_key_rejects_toolless_chat_model() {
    serve(|req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        models(
            &ctx,
            &[
                ("claude-haiku-5-5", true),
                ("claude-sonnet-5-5", true),
                ("text-only", false),
            ],
        );
        assert_eq!(put_key(&req, &t, &org, KEY).await.status_code(), 200);
        let toolless = json!({ "models": { "routine": "text-only", "chat": "text-only" } });
        let res = patch_slot(&req, &t, &org, "primary", toolless).await;
        assert_eq!(res.status_code(), 422, "{}", res.text());
        assert_eq!(code(&res), "invalid");
        // A tool-less model is fine for routine work.
        let ok = json!({ "models": { "routine": "text-only", "chat": "claude-sonnet-5-5" } });
        let res = patch_slot(&req, &t, &org, "primary", ok).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(
            res.json::<Value>()["keys"]["primary"]["models"]["routine"],
            "text-only"
        );
        let m = json!({ "models": { "routine": "text-only", "chat": "claude-sonnet-5-5" } });
        assert_eq!(
            patch_slot(&req, &t, &org, "backup", m).await.status_code(),
            404
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn delete_key_returns_to_opsagent() {
    serve_with(
        |c| {
            c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(
                "sk-ant-opsagent-test",
            ))
        },
        |req, ctx| async move {
            let (t, org) = owner(&req, &ctx).await;
            assert_eq!(status(&req, &org).await["source"], "opsagent");
            models(
                &ctx,
                &[("claude-haiku-5-5", true), ("claude-sonnet-5-5", true)],
            );
            assert_eq!(put_key(&req, &t, &org, KEY).await.status_code(), 200);
            assert_eq!(status(&req, &org).await["source"], "byok");
            assert_eq!(
                delete_slot(&req, &t, &org, "primary").await.status_code(),
                204
            );
            let s = status(&req, &org).await;
            assert_eq!(
                (s["source"].as_str(), s["keys"]["primary"].clone()),
                (Some("opsagent"), Value::Null)
            );
            assert_eq!(audits(&ctx, "ai.key.delete").await.len(), 1);
            assert_eq!(
                delete_slot(&req, &t, &org, "primary").await.status_code(),
                404
            );
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn put_backup_without_primary_409() {
    serve(|req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        models(
            &ctx,
            &[("claude-haiku-5-5", true), ("claude-sonnet-5-5", true)],
        );
        let body = json!({ "style": "anthropic", "api_key": BACKUP_KEY });
        let res = put_slot(&req, &t, &org, "backup", body).await;
        assert_eq!(res.status_code(), 409, "{}", res.text());
        let p: Value = res.json();
        assert_eq!(
            (p["code"].as_str(), p["detail"].as_str()),
            (
                Some("ai_primary_required"),
                Some("Save a primary key first.")
            )
        );
        assert_eq!(
            status(&req, &org).await["keys"],
            json!({ "primary": null, "backup": null })
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn put_custom_endpoint_refused_with_reason() {
    serve(|req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        for (url, reason) in [
            ("http://gw.example/v1", "Use an https URL."),
            (
                "https://10.0.0.1/v1",
                "Use the provider's DNS name, not an IP address or local name.",
            ),
        ] {
            let body = json!({ "style": "openai", "base_url": url, "api_key": CUSTOM_KEY });
            let res = put_slot(&req, &t, &org, "primary", body).await;
            assert_eq!(res.status_code(), 422, "{url}: {}", res.text());
            let p: Value = res.json();
            assert_eq!(
                (p["code"].as_str(), p["detail"].as_str()),
                (Some("ai_endpoint_invalid"), Some(reason)),
                "{url}"
            );
        }
        assert_eq!(status(&req, &org).await["keys"]["primary"], Value::Null);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn put_custom_openai_endpoint_with_list_saves_defaults() {
    let api = MockServer::start().await;
    mount_list(&api, &["m-a", "m-b"]).await;
    let body = custom(&api, CUSTOM_KEY);
    serve_with(private, |req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        openai(&ctx);
        let res = put_slot(&req, &t, &org, "primary", body).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let out: Value = res.json();
        let listed = out["models"].as_array().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|m| m["tools"] == true), "{listed:?}");
        let k = &out["status"]["keys"]["primary"];
        assert_eq!(k["models"], json!({ "routine": "m-a", "chat": "m-a" }));
        assert_eq!(
            (
                k["style"].as_str(),
                k["base_host"].as_str(),
                k["last4"].as_str()
            ),
            (Some("openai"), Some("127.0.0.1"), Some("1234"))
        );
        let live = req
            .get(&format!("/v1/orgs/{org}/ai/keys/primary/models"))
            .await;
        assert_eq!(live.status_code(), 200, "{}", live.text());
        assert_eq!(live.json::<Value>().as_array().unwrap().len(), 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn put_custom_endpoint_without_list() {
    let ok = MockServer::start().await;
    mount_no_list(&ok).await;
    mount_check(&ok, 200).await;
    let gone = MockServer::start().await;
    mount_no_list(&gone).await;
    mount_check(&gone, 404).await;
    let refused = MockServer::start().await;
    mount_no_list(&refused).await;
    mount_check(&refused, 401).await;
    serve_with(private, |req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        openai(&ctx);
        let res = put_slot(&req, &t, &org, "primary", custom(&ok, CUSTOM_KEY)).await;
        assert_eq!(res.status_code(), 422, "{}", res.text());
        let p: Value = res.json();
        assert_eq!(
            (p["code"].as_str(), p["detail"].as_str()),
            (
                Some("models_required"),
                Some("This endpoint has no models list; type the routine and chat model ids.")
            )
        );
        assert!(posts(&ok).await.is_empty());
        assert_eq!(
            status(&req, &org).await["keys"],
            json!({ "primary": null, "backup": null })
        );

        let typed = with_models(custom(&ok, CUSTOM_KEY), "r1", "c1");
        let res = put_slot(&req, &t, &org, "primary", typed).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let sent = posts(&ok).await;
        assert_eq!(sent.len(), 1);
        assert_eq!(
            (sent[0]["model"].as_str(), sent[0]["max_tokens"].as_u64()),
            (Some("c1"), Some(1))
        );
        let out: Value = res.json();
        assert_eq!(out["models"], json!([]));
        let k = &out["status"]["keys"]["primary"];
        assert_eq!(k["models"], json!({ "routine": "r1", "chat": "c1" }));
        let listed = req
            .get(&format!("/v1/orgs/{org}/ai/keys/primary/models"))
            .await;
        assert_eq!(
            (listed.status_code().as_u16(), listed.json::<Value>()),
            (200, json!([]))
        );

        // PATCH runs the same 1-token check on the new chat model.
        let m = json!({ "models": { "routine": "r2", "chat": "c2" } });
        let res = patch_slot(&req, &t, &org, "primary", m).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(
            res.json::<Value>()["keys"]["primary"]["models"]["chat"],
            "c2"
        );
        assert_eq!(posts(&ok).await[1]["model"], "c2");

        let res = put_slot(
            &req,
            &t,
            &org,
            "backup",
            with_models(custom(&gone, CUSTOM_KEY), "r1", "c1"),
        )
        .await;
        assert_eq!(refusal(&res), (422, "ai_model_invalid".into()));
        let res = put_slot(
            &req,
            &t,
            &org,
            "backup",
            with_models(custom(&refused, CUSTOM_KEY), "r1", "c1"),
        )
        .await;
        assert_eq!(refusal(&res), (422, "ai_key_invalid".into()));
        assert_eq!(status(&req, &org).await["keys"]["backup"], Value::Null);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn put_typed_model_id_shape() {
    let api = MockServer::start().await;
    mount_no_list(&api).await;
    mount_check(&api, 200).await;
    serve_with(private, |req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        openai(&ctx);
        let long = "m".repeat(201);
        for bad in ["", long.as_str(), "a b"] {
            for (routine, chat) in [(bad, "c1"), ("r1", bad)] {
                let body = with_models(custom(&api, CUSTOM_KEY), routine, chat);
                let res = put_slot(&req, &t, &org, "primary", body).await;
                assert_eq!(refusal(&res), (422, "invalid".into()), "{bad:?}");
            }
        }
        assert!(posts(&api).await.is_empty());
        let ok = with_models(custom(&api, CUSTOM_KEY), &"m".repeat(200), "c1");
        assert_eq!(
            put_slot(&req, &t, &org, "primary", ok).await.status_code(),
            200
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn custom_key_shape() {
    let silent = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&silent)
        .await;
    let api = MockServer::start().await;
    mount_list(&api, &["m-a"]).await;
    serve_with(private, |req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        openai(&ctx);
        for bad in ["1234567", "gsk_1234 5678"] {
            let res = put_slot(&req, &t, &org, "primary", custom(&silent, bad)).await;
            assert_eq!(refusal(&res), (422, "ai_key_invalid".into()), "{bad}");
        }
        let res = put_slot(&req, &t, &org, "primary", custom(&api, "gsk_12345678")).await; // gitleaks:allow (fake, 12-char shape case)
        assert_eq!(res.status_code(), 200, "{}", res.text());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn delete_primary_promotes_backup_and_audits_slot() {
    serve(|req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        models(
            &ctx,
            &[("claude-haiku-5-5", true), ("claude-sonnet-5-5", true)],
        );
        assert_eq!(put_key(&req, &t, &org, KEY).await.status_code(), 200);
        let body = json!({ "style": "anthropic", "api_key": BACKUP_KEY });
        let res = put_slot(&req, &t, &org, "backup", body).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(
            res.json::<Value>()["status"]["keys"]["backup"]["last4"],
            "bkup"
        );
        assert_eq!(
            delete_slot(&req, &t, &org, "primary").await.status_code(),
            204
        );
        let keys = status(&req, &org).await["keys"].clone();
        assert_eq!(
            (keys["primary"]["last4"].as_str(), keys["backup"].clone()),
            (Some("bkup"), Value::Null)
        );
        let del = audits(&ctx, "ai.key.delete").await;
        assert_eq!(del.len(), 1);
        assert_eq!(
            del[0].metadata,
            json!({ "slot": "primary", "style": "anthropic", "base_host": null })
        );
        assert_eq!(
            delete_slot(&req, &t, &org, "backup").await.status_code(),
            404
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn put_key_audit_has_slot_style_host_no_key() {
    let api = MockServer::start().await;
    mount_list(&api, &["m-a"]).await;
    let body = custom(&api, CUSTOM_KEY);
    let uri = api.uri();
    serve_with(private, |req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        openai(&ctx);
        assert_eq!(
            put_slot(&req, &t, &org, "primary", body)
                .await
                .status_code(),
            200
        );
        let set = audits(&ctx, "ai.key.set").await;
        assert_eq!(set.len(), 1);
        let meta = &set[0].metadata;
        assert_eq!(
            *meta,
            json!({ "provider": "openai", "last4": "1234", "slot": "primary",
                "style": "openai", "base_host": "127.0.0.1" })
        );
        let text = meta.to_string();
        assert!(!text.contains(CUSTOM_KEY) && !text.contains(&uri) && !text.contains("http"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn patch_ai_sets_and_clears_ceiling() {
    serve(|req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        let res = patch_ai(&req, &t, &org, json!({ "monthly_credit_ceiling": 50 })).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let s: Value = res.json();
        assert_eq!(
            (s["monthly_credit_ceiling"].as_str(), s["enabled"].as_bool()),
            (Some("50.00"), Some(false))
        );
        let res = patch_ai(&req, &t, &org, json!({ "monthly_credit_ceiling": null })).await;
        assert_eq!(res.json::<Value>()["monthly_credit_ceiling"], Value::Null);
        for bad in [json!({ "monthly_credit_ceiling": -1 }), json!({})] {
            let res = patch_ai(&req, &t, &org, bad.clone()).await;
            assert_eq!(refusal(&res), (422, "invalid".into()), "{bad}");
        }
        let both = json!({ "enabled": true, "monthly_credit_ceiling": 12.5 });
        let s: Value = patch_ai(&req, &t, &org, both).await.json();
        assert_eq!(
            (s["monthly_credit_ceiling"].as_str(), s["enabled"].as_bool()),
            (Some("12.50"), Some(true))
        );
        assert_eq!(audits(&ctx, "ai.enable").await.len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn unknown_slot_404() {
    serve(|req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        let body = json!({ "style": "anthropic", "api_key": KEY });
        assert_eq!(
            put_slot(&req, &t, &org, "tertiary", body.clone())
                .await
                .status_code(),
            404
        );
        let m = json!({ "models": { "routine": "a", "chat": "b" } });
        assert_eq!(
            patch_slot(&req, &t, &org, "tertiary", m)
                .await
                .status_code(),
            404
        );
        assert_eq!(
            delete_slot(&req, &t, &org, "tertiary").await.status_code(),
            404
        );
        let listed = req
            .get(&format!("/v1/orgs/{org}/ai/keys/tertiary/models"))
            .await;
        assert_eq!(listed.status_code(), 404);
        // The single-key routes are gone.
        let old = req
            .put(&format!("/v1/orgs/{org}/ai/key"))
            .add_header("X-CSRF-Token", &t)
            .json(&body)
            .await;
        assert_eq!(old.status_code(), 404);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn topup_503_without_stripe() {
    serve(|req, ctx| async move {
        let (t, org) = owner(&req, &ctx).await;
        let res = req
            .post(&format!("/v1/orgs/{org}/ai/topup"))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(res.status_code(), 503);
        assert_eq!(res.json::<Value>()["code"], "billing_unavailable");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn topup_503_without_opsagent_key() {
    serve_with(
        stripe_on("http://127.0.0.1:1".into()),
        |req, ctx| async move {
            let (t, org) = owner(&req, &ctx).await;
            assert_eq!(status(&req, &org).await["topup_available"], false);
            let res = req
                .post(&format!("/v1/orgs/{org}/ai/topup"))
                .add_header("X-CSRF-Token", &t)
                .await;
            assert_eq!(res.status_code(), 503);
            assert_eq!(res.json::<Value>()["code"], "billing_unavailable");
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn topup_checkout_sends_payment_mode() {
    let api = MockServer::start().await;
    let base = api.uri();
    let config = |c: &mut opsagent_brain::config::Config| {
        stripe_on(base)(c);
        c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(
            "sk-ant-test",
        ));
    };
    serve_with(config, |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        Mock::given(method("POST"))
            .and(path("/v1/checkout/sessions"))
            .and(header_regex("Idempotency-Key", "^topup:"))
            .and(body_string_contains("mode=payment"))
            .and(body_string_contains("customer=cus_1"))
            .and(body_string_contains(format!("client_reference_id={id}")))
            .and(body_string_contains("price_data%5D%5Bunit_amount%5D=1500"))
            .and(body_string_contains("price_data%5D%5Bcurrency%5D=usd"))
            .and(body_string_contains("metadata%5Bpurpose%5D=ai_topup"))
            .and(body_string_contains("payment_method_types%5B0%5D=card"))
            .and(body_string_contains("settings%2Fai%3Ftopup%3Dsuccess"))
            .and(body_string_contains("settings%2Fai%3Ftopup%3Dcanceled"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "url": "https://checkout.test/t" })),
            )
            .expect(1)
            .mount(&api)
            .await;
        assert_eq!(status(&req, &org).await["topup_available"], true);
        let res = req
            .post(&format!("/v1/orgs/{org}/ai/topup"))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(res.json::<Value>()["url"], "https://checkout.test/t");
    })
    .await;
}

fn topup_event(id: &str, org: Uuid) -> Value {
    event(
        id,
        "checkout.session.completed",
        10,
        json!({ "id": "cs_t", "object": "checkout.session", "mode": "payment",
            "payment_status": "paid", "client_reference_id": org.to_string(),
            "customer": "cus_1", "metadata": { "purpose": "ai_topup" } }),
    )
}

#[tokio::test]
#[serial]
async fn topup_webhook_grants_once() {
    serve_with(
        stripe_on("http://127.0.0.1:1".into()),
        |req, ctx| async move {
            let (_, org, id) = org_with_customer(&req, &ctx).await;
            deliver(&req, &topup_event("evt_t1", id)).await;
            deliver(&req, &topup_event("evt_t1", id)).await;
            let repo = Pg::new(&ctx.db);
            assert_eq!(repo.topup_balance(id).await.unwrap(), Decimal::from(1000));
            assert_eq!(
                status(&req, &org).await["usage"]["topup_balance"],
                "1000.00"
            );
            deliver(&req, &topup_event("evt_t2", id)).await;
            assert_eq!(repo.topup_balance(id).await.unwrap(), Decimal::from(2000));
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn subscription_checkout_webhook_unchanged() {
    serve_with(stripe_on("http://127.0.0.1:1".into()), |req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = create_org(&req, &t, "Acme").await;
        let id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
        let session = json!({ "id": "cs_s", "object": "checkout.session", "mode": "subscription",
            "payment_status": "paid", "client_reference_id": id.to_string(), "customer": "cus_9" });
        deliver(&req, &event("evt_s1", "checkout.session.completed", 10, session)).await;
        let repo = Pg::new(&ctx.db);
        assert_eq!(repo.billing(id).await.unwrap().customer_id.as_deref(), Some("cus_9"));
        assert_eq!(repo.topup_balance(id).await.unwrap(), Decimal::ZERO);
    })
    .await;
}
