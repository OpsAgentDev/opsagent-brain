//! Dashboard AI settings, BYOK and top-ups (Plan 5 Task 3).
use std::sync::Arc;

use async_trait::async_trait;
use axum_test::{TestResponse, TestServer};
use opsagent_brain::{adapters::db::Pg, models::_entities::audit_events};
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

async fn enable(req: &TestServer, csrf: &str, org: &str, on: bool) -> TestResponse {
    req.patch(&format!("/v1/orgs/{org}/ai"))
        .add_header("X-CSRF-Token", csrf)
        .json(&json!({ "enabled": on }))
        .await
}

async fn put_key(req: &TestServer, csrf: &str, org: &str, key: &str) -> TestResponse {
    req.put(&format!("/v1/orgs/{org}/ai/key"))
        .add_header("X-CSRF-Token", csrf)
        .json(&json!({ "provider": "anthropic", "api_key": key }))
        .await
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
        assert_eq!(
            (s["source"].clone(), s["key"].clone()),
            (Value::Null, Value::Null)
        );
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
        assert_eq!(put_key(&req, &t, &org, KEY).await.status_code(), 403);
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
                assert_eq!(res.json::<Value>()["code"], "ai_key_invalid");
            }
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
            assert_eq!(refused.json::<Value>()["code"], "ai_key_invalid");
            let saved = put_key(&req, &t, &org, KEY).await;
            assert_eq!(saved.status_code(), 200, "{}", saved.text());
            assert!(!saved.text().contains(KEY));
            let s: Value = saved.json();
            assert_eq!(s["source"], "byok");
            let k = &s["key"];
            assert_eq!(
                (k["provider"].as_str(), k["last4"].as_str()),
                (Some("anthropic"), Some("wxyz"))
            );
            assert_eq!(k["status"], "ok");
            // The preferred defaults present on the live list.
            assert_eq!(
                k["models"],
                json!({ "routine": "claude-haiku-4-5", "chat": "claude-sonnet-4-5" })
            );
            assert_eq!(k["monthly_credit_ceiling"], Value::Null);
            let set = audits(&ctx, "ai.key.set").await;
            assert_eq!(set.len(), 1);
            assert_eq!(
                set[0].metadata,
                json!({ "provider": "anthropic", "last4": "wxyz" })
            );
            let listed = req.get(&format!("/v1/orgs/{org}/ai/key/models")).await;
            assert_eq!(listed.status_code(), 200, "{}", listed.text());
            assert_eq!(
                listed.json::<Value>(),
                json!([{ "id": "claude-sonnet-4-5", "tools": true, "default_for": "chat" },
                    { "id": "claude-haiku-4-5", "tools": true, "default_for": "routine" }])
            );
        },
    )
    .await;
}

async fn patch_key(req: &TestServer, csrf: &str, org: &str, body: Value) -> TestResponse {
    req.patch(&format!("/v1/orgs/{org}/ai/key"))
        .add_header("X-CSRF-Token", csrf)
        .json(&body)
        .await
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
        let res = patch_key(&req, &t, &org, toolless).await;
        assert_eq!(res.status_code(), 422, "{}", res.text());
        assert_eq!(res.json::<Value>()["code"], "invalid");
        // A tool-less model is fine for routine work; the ceiling is set and then cleared.
        let ok = json!({ "models": { "routine": "text-only", "chat": "claude-sonnet-5-5" },
            "monthly_credit_ceiling": 250.5 });
        let res = patch_key(&req, &t, &org, ok).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let k = res.json::<Value>()["key"].clone();
        assert_eq!(k["models"]["routine"], "text-only");
        assert_eq!(k["monthly_credit_ceiling"], "250.50");
        let cleared = patch_key(&req, &t, &org, json!({ "monthly_credit_ceiling": null })).await;
        let k = cleared.json::<Value>()["key"].clone();
        assert_eq!(
            (
                k["monthly_credit_ceiling"].clone(),
                k["models"]["routine"].clone()
            ),
            (Value::Null, json!("text-only"))
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn delete_key_returns_to_opsagent() {
    serve_with(
        |c| c.anthropic_api_key = "sk-ant-opsagent-test".into(),
        |req, ctx| async move {
            let (t, org) = owner(&req, &ctx).await;
            assert_eq!(status(&req, &org).await["source"], "opsagent");
            models(
                &ctx,
                &[("claude-haiku-5-5", true), ("claude-sonnet-5-5", true)],
            );
            assert_eq!(put_key(&req, &t, &org, KEY).await.status_code(), 200);
            assert_eq!(status(&req, &org).await["source"], "byok");
            let del = |req: &TestServer| {
                req.delete(&format!("/v1/orgs/{org}/ai/key"))
                    .add_header("X-CSRF-Token", &t)
            };
            assert_eq!(del(&req).await.status_code(), 204);
            let s = status(&req, &org).await;
            assert_eq!(
                (s["source"].as_str(), s["key"].clone()),
                (Some("opsagent"), Value::Null)
            );
            assert_eq!(audits(&ctx, "ai.key.delete").await.len(), 1);
            assert_eq!(del(&req).await.status_code(), 404);
        },
    )
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
        c.anthropic_api_key = "sk-ant-test".into();
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
