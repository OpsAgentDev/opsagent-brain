//! Billing API and the Stripe webhook (Plan 6 Task 2).
use axum_test::{TestResponse, TestServer};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use opsagent_brain::adapters::db::Pg;
use opsagent_core::billing::{BillingRepo, BillingStatus as B, SubscriptionState, Tier};
use sea_orm::{ConnectionTrait, Statement};
use serde_json::{json, Value};
use serial_test::serial;
use sha2::Sha256;
use uuid::Uuid;
use wiremock::{
    matchers::{body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::support::*;

const SECRET: &str = "whsec_test";

/// Stripe configured, pointed at `api`.
fn stripe_on(api: String) -> impl FnOnce(&mut opsagent_brain::config::Config) {
    move |c| {
        c.stripe_secret_key = "sk_test_x".into();
        c.stripe_webhook_secret = SECRET.into();
        c.stripe_price_starter = "price_starter".into();
        c.stripe_price_team = "price_team".into();
        c.stripe_price_scale = "price_scale".into();
        c.stripe_api_base = api;
    }
}

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
}

fn sign(body: &str, t: i64) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    m.update(format!("{t}.{body}").as_bytes());
    let hex: String = m
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("t={t},v1={hex}")
}

async fn post_raw(req: &TestServer, body: &str, sig: &str) -> TestResponse {
    req.post("/v1/webhooks/stripe")
        .add_header("Stripe-Signature", sig)
        .add_header("Content-Type", "application/json")
        .bytes(body.to_owned().into())
        .await
}

/// Posts `event` signed now.
async fn deliver(req: &TestServer, event: &Value) -> TestResponse {
    let body = event.to_string();
    post_raw(req, &body, &sign(&body, Utc::now().timestamp())).await
}

fn event(id: &str, kind: &str, created: i64, object: Value) -> Value {
    json!({ "id": id, "object": "event", "type": kind, "created": at(created).timestamp(),
        "data": { "object": object } })
}

/// A subscription event; the period sits on the item (Stripe-Version 2025-09-30.clover).
fn sub_event(id: &str, kind: &str, created: i64, status: &str, qty: i32, period_end: i64) -> Value {
    let item = json!({ "id": "si_1", "quantity": qty, "price": { "id": "price_team" },
        "current_period_start": at(0).timestamp(), "current_period_end": at(period_end).timestamp() });
    let object = json!({ "id": "sub_1", "object": "subscription", "customer": "cus_1",
        "status": status, "trial_end": at(14 * 86_400).timestamp(), "items": { "data": [item] } });
    event(id, kind, created, object)
}

fn invoice_event(id: &str, kind: &str, created: i64) -> Value {
    event(
        id,
        kind,
        created,
        json!({ "id": "in_1", "object": "invoice", "customer": "cus_1" }),
    )
}

/// Signs in an owner and creates an org whose Stripe customer is `cus_1`; (csrf, slug, id).
async fn org_with_customer(req: &TestServer, ctx: &TestApp) -> (String, String, Uuid) {
    let mail = prepare(ctx);
    let t = sign_in(req, &mail, "owner@example.com").await;
    let org = create_org(req, &t, "Acme").await;
    let id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
    Pg::new(&ctx.db).set_customer(id, "cus_1").await.unwrap();
    (t, slug(&org), id)
}

async fn status_of(ctx: &TestApp, org: Uuid) -> B {
    Pg::new(&ctx.db).billing(org).await.unwrap().status
}

async fn get_billing(req: &TestServer, org: &str) -> Value {
    let res = req.get(&format!("/v1/orgs/{org}/billing")).await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
    res.json()
}

async fn checkout(req: &TestServer, csrf: &str, org: &str, body: Value) -> TestResponse {
    req.post(&format!("/v1/orgs/{org}/billing/checkout"))
        .add_header("X-CSRF-Token", csrf)
        .json(&body)
        .await
}

async fn portal(req: &TestServer, csrf: &str, org: &str) -> TestResponse {
    req.post(&format!("/v1/orgs/{org}/billing/portal"))
        .add_header("X-CSRF-Token", csrf)
        .await
}

#[tokio::test]
#[serial]
async fn checkout_owner_only_and_returns_url() {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "cus_new" })))
        .expect(1)
        .mount(&api)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .and(body_string_contains("customer=cus_new"))
        .and(body_string_contains("price%5D=price_team"))
        .and(body_string_contains("trial_period_days%5D=14"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "url": "https://checkout.test/s" })),
        )
        .expect(2)
        .mount(&api)
        .await;
    serve_with(stripe_on(api.uri()), |mut req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = slug(&create_org(&req, &t, "Acme").await);
        let b = get_billing(&req, &org).await;
        assert_eq!(b["status"], "none");
        assert_eq!(b["enforced"], false);
        let res = checkout(&req, &t, &org, json!({})).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(res.json::<Value>()["url"], "https://checkout.test/s");
        // The customer is created once, on first use, and reused after.
        let res = checkout(&req, &t, &org, json!({ "tier": "team" })).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let bad = checkout(&req, &t, &org, json!({ "tier": "gold" })).await;
        assert_eq!(bad.status_code(), 422, "{}", bad.text());

        let tm = as_member(&mut req, &ctx, &mail, &org, "member@example.com").await;
        assert_eq!(get_billing(&req, &org).await["status"], "none");
        assert_eq!(
            checkout(&req, &tm, &org, json!({})).await.status_code(),
            403
        );
        assert_eq!(portal(&req, &tm, &org).await.status_code(), 403);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn checkout_after_cancel_buys_the_tier_without_trial() {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .and(body_string_contains("price%5D=price_starter"))
        .and(|r: &wiremock::Request| !String::from_utf8_lossy(&r.body).contains("trial"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "url": "https://checkout.test/s" })),
        )
        .expect(1)
        .mount(&api)
        .await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, _) = org_with_customer(&req, &ctx).await;
        deliver(
            &req,
            &sub_event(
                "evt_1",
                "customer.subscription.created",
                10,
                "active",
                1,
                30,
            ),
        )
        .await;
        // Subscribed: the Portal, not a second Checkout.
        let dup = checkout(&req, &t, &org, json!({ "tier": "starter" })).await;
        assert_eq!(dup.status_code(), 409, "{}", dup.text());
        deliver(
            &req,
            &sub_event(
                "evt_2",
                "customer.subscription.deleted",
                20,
                "canceled",
                1,
                30,
            ),
        )
        .await;
        assert_eq!(get_billing(&req, &org).await["status"], "canceled");
        let res = checkout(&req, &t, &org, json!({ "tier": "starter" })).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn portal_requires_customer() {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/billing_portal/sessions"))
        .and(body_string_contains("customer=cus_1"))
        .and(body_string_contains("settings%2Fbilling"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "url": "https://portal.test/p" })),
        )
        .expect(1)
        .mount(&api)
        .await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = create_org(&req, &t, "Acme").await;
        let res = portal(&req, &t, &slug(&org)).await;
        assert_eq!(res.status_code(), 409, "{}", res.text());
        assert_eq!(res.json::<Value>()["code"], "no_customer");
        let id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
        Pg::new(&ctx.db).set_customer(id, "cus_1").await.unwrap();
        let res = portal(&req, &t, &slug(&org)).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(res.json::<Value>()["url"], "https://portal.test/p");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn webhook_bad_signature_400_no_write() {
    serve_with(
        stripe_on("http://127.0.0.1:9".into()),
        |req, ctx| async move {
            let (_, _, org) = org_with_customer(&req, &ctx).await;
            let body = sub_event(
                "evt_1",
                "customer.subscription.created",
                10,
                "active",
                1,
                30,
            )
            .to_string();
            let now = Utc::now().timestamp();
            let tampered = body.replace("active", "trialing");
            for (b, sig) in [
                (tampered.as_str(), sign(&body, now)),
                (body.as_str(), sign(&body, now - 301)),
                (body.as_str(), "v1=00".to_owned()),
            ] {
                let res = post_raw(&req, b, &sig).await;
                assert_eq!(res.status_code(), 400, "{}", res.text());
            }
            let missing = req
                .post("/v1/webhooks/stripe")
                .bytes(body.clone().into())
                .await;
            assert_eq!(missing.status_code(), 400);
            let sql = Statement::from_string(
                ctx.db.get_database_backend(),
                "SELECT count(*)::int8 AS n FROM stripe_events",
            );
            let row = ctx.db.query_one_raw(sql).await.unwrap().unwrap();
            assert_eq!(row.try_get::<i64>("", "n").unwrap(), 0);
            assert_eq!(status_of(&ctx, org).await, B::None);
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn webhook_duplicate_event_noop() {
    serve_with(
        stripe_on("http://127.0.0.1:9".into()),
        |req, ctx| async move {
            let (_, org_slug, org) = org_with_customer(&req, &ctx).await;
            let first = sub_event(
                "evt_1",
                "customer.subscription.created",
                10,
                "active",
                2,
                30,
            );
            assert_eq!(deliver(&req, &first).await.status_code(), 200);
            // The same event id again, whatever it says, changes nothing.
            let again = sub_event(
                "evt_1",
                "customer.subscription.created",
                20,
                "canceled",
                1,
                30,
            );
            assert_eq!(deliver(&req, &again).await.status_code(), 200);
            let b = get_billing(&req, &org_slug).await;
            assert_eq!(
                (b["status"].as_str(), b["quantity"].as_i64()),
                (Some("active"), Some(2))
            );
            assert_eq!(b["tier"], "team");
            assert_eq!(b["limits"]["members"], 5);
            assert_eq!(b["over_limit"], false);
            assert_eq!(status_of(&ctx, org).await, B::Active);
            // Unknown customers and unhandled types are acknowledged and ignored.
            let mut stranger = sub_event(
                "evt_2",
                "customer.subscription.updated",
                30,
                "canceled",
                1,
                30,
            );
            stranger["data"]["object"]["customer"] = "cus_unknown".into();
            assert_eq!(deliver(&req, &stranger).await.status_code(), 200);
            let other = event("evt_3", "charge.refunded", 40, json!({ "id": "ch_1" }));
            assert_eq!(deliver(&req, &other).await.status_code(), 200);
            assert_eq!(status_of(&ctx, org).await, B::Active);
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn subscription_updated_out_of_order_ignored() {
    serve_with(
        stripe_on("http://127.0.0.1:9".into()),
        |req, ctx| async move {
            let (_, org_slug, _) = org_with_customer(&req, &ctx).await;
            let kind = "customer.subscription.updated";
            deliver(&req, &sub_event("evt_new", kind, 200, "active", 3, 60)).await;
            let res = deliver(&req, &sub_event("evt_old", kind, 100, "trialing", 1, 30)).await;
            assert_eq!(res.status_code(), 200);
            // Same second: the one with the earlier period end is the older.
            deliver(&req, &sub_event("evt_tie", kind, 200, "trialing", 1, 30)).await;
            let b = get_billing(&req, &org_slug).await;
            assert_eq!(
                (b["status"].as_str(), b["quantity"].as_i64()),
                (Some("active"), Some(3))
            );
            assert_eq!(b["current_period_end"], json!(at(60)));
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn deleted_while_trialing_is_trial_ended() {
    serve_with(
        stripe_on("http://127.0.0.1:9".into()),
        |req, ctx| async move {
            let (_, _, org) = org_with_customer(&req, &ctx).await;
            deliver(
                &req,
                &sub_event(
                    "evt_1",
                    "customer.subscription.created",
                    10,
                    "trialing",
                    1,
                    30,
                ),
            )
            .await;
            assert_eq!(status_of(&ctx, org).await, B::Trialing);
            deliver(
                &req,
                &sub_event(
                    "evt_2",
                    "customer.subscription.deleted",
                    20,
                    "canceled",
                    1,
                    30,
                ),
            )
            .await;
            assert_eq!(status_of(&ctx, org).await, B::TrialEnded);
            // A paying subscription deleted is canceled.
            deliver(
                &req,
                &sub_event(
                    "evt_3",
                    "customer.subscription.created",
                    30,
                    "active",
                    1,
                    30,
                ),
            )
            .await;
            deliver(
                &req,
                &sub_event(
                    "evt_4",
                    "customer.subscription.deleted",
                    40,
                    "canceled",
                    1,
                    30,
                ),
            )
            .await;
            assert_eq!(status_of(&ctx, org).await, B::Canceled);
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn payment_failed_sets_past_due_since() {
    serve_with(
        stripe_on("http://127.0.0.1:9".into()),
        |req, ctx| async move {
            let (_, _, org) = org_with_customer(&req, &ctx).await;
            deliver(
                &req,
                &sub_event(
                    "evt_1",
                    "customer.subscription.created",
                    10,
                    "active",
                    1,
                    30,
                ),
            )
            .await;
            deliver(&req, &invoice_event("evt_2", "invoice.payment_failed", 20)).await;
            deliver(&req, &invoice_event("evt_3", "invoice.payment_failed", 25)).await;
            let b = Pg::new(&ctx.db).billing(org).await.unwrap();
            assert_eq!((b.status, b.past_due_since), (B::PastDue, Some(at(20))));
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn payment_succeeded_clears_past_due_and_paused() {
    serve_with(
        stripe_on("http://127.0.0.1:9".into()),
        |req, ctx| async move {
            let (_, _, org) = org_with_customer(&req, &ctx).await;
            // A trial's $0 invoice does not end the trial.
            deliver(
                &req,
                &sub_event(
                    "evt_0",
                    "customer.subscription.created",
                    5,
                    "trialing",
                    1,
                    30,
                ),
            )
            .await;
            deliver(
                &req,
                &invoice_event("evt_1", "invoice.payment_succeeded", 6),
            )
            .await;
            assert_eq!(status_of(&ctx, org).await, B::Trialing);
            deliver(
                &req,
                &sub_event(
                    "evt_2",
                    "customer.subscription.updated",
                    10,
                    "past_due",
                    1,
                    30,
                ),
            )
            .await;
            deliver(
                &req,
                &invoice_event("evt_3", "invoice.payment_succeeded", 20),
            )
            .await;
            let b = Pg::new(&ctx.db).billing(org).await.unwrap();
            assert_eq!((b.status, b.past_due_since), (B::Active, None));
            // billing_sync's paused, cleared the same way.
            let paused = SubscriptionState {
                subscription_id: "sub_1".into(),
                status: B::Paused,
                tier: Some(Tier::Team),
                quantity: 1,
                trial_ends_at: None,
                current_period_start: Some(at(0)),
                current_period_end: Some(at(30)),
            };
            Pg::new(&ctx.db)
                .apply_subscription(org, &paused, at(30))
                .await
                .unwrap();
            deliver(
                &req,
                &invoice_event("evt_4", "invoice.payment_succeeded", 40),
            )
            .await;
            let b = Pg::new(&ctx.db).billing(org).await.unwrap();
            assert_eq!((b.status, b.past_due_since), (B::Active, None));
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn billing_503_when_unconfigured() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = slug(&create_org(&req, &t, "Acme").await);
        let res = req.get(&format!("/v1/orgs/{org}/billing")).await;
        assert_eq!(res.status_code(), 503);
        assert_eq!(res.json::<Value>()["code"], "billing_unavailable");
        assert_eq!(checkout(&req, &t, &org, json!({})).await.status_code(), 503);
        assert_eq!(portal(&req, &t, &org).await.status_code(), 503);
        let body = invoice_event("evt_1", "invoice.payment_failed", 1).to_string();
        let res = post_raw(&req, &body, &sign(&body, Utc::now().timestamp())).await;
        assert_eq!(res.status_code(), 503);
    })
    .await;
}
