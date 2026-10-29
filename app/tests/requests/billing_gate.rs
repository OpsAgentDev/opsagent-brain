//! Billing gating behind `BILLING_ENFORCED` (Plan 6 Task 4).
use axum_test::{TestResponse, TestServer};
use opsagent_brain::adapters::db::ledger_storage::stmt;
use sea_orm::ConnectionTrait;
use serde_json::{json, Value};
use serial_test::serial;
use uuid::Uuid;

use opsagent_brain::mailers::CaptureMailer;

use super::support::*;

pub fn enforced(c: &mut opsagent_brain::config::Config) {
    c.billing_enforced = true;
}

/// Stores `status` (and `tier`) on the org, as the webhooks would; `past_due_days` back-dates
/// `past_due_since`.
pub async fn set_billing(ctx: &TestApp, org: Uuid, status: &str, tier: &str, past_due_days: i64) {
    ctx.db
        .execute_raw(stmt(
            "UPDATE organisations SET stripe_subscription_id = 'sub_1', billing_status = $2, \
             billing_tier = $3, billing_quantity = 1, current_period_start = now() - interval '1 day', \
             past_due_since = CASE WHEN $4 > 0 THEN now() - make_interval(days => $4::int) END \
             WHERE id = $1",
            vec![org.into(), status.into(), tier.into(), past_due_days.into()],
        ))
        .await
        .unwrap();
}

/// Owner signs in and creates an org; (csrf, slug, id).
pub async fn owner_org(req: &TestServer, mail: &CaptureMailer) -> (String, String, Uuid) {
    let t = sign_in(req, mail, "owner@example.com").await;
    let org = create_org(req, &t, "Acme").await;
    (t, slug(&org), org["id"].as_str().unwrap().parse().unwrap())
}

async fn post(req: &TestServer, csrf: &str, path: &str, body: Value) -> TestResponse {
    req.post(path)
        .add_header("X-CSRF-Token", csrf)
        .json(&body)
        .await
}

async fn new_connection(req: &TestServer, csrf: &str, org: &str) -> TestResponse {
    let body = json!({ "provider": "fake", "display_name": "acct" });
    post(req, csrf, &format!("/v1/orgs/{org}/connections"), body).await
}

fn refused(res: &TestResponse, code: &str) {
    assert_eq!(res.status_code(), 402, "{}", res.text());
    assert_eq!(res.json::<Value>()["code"], code);
}

#[tokio::test]
#[serial]
async fn not_enforced_nothing_gated() {
    serve(|req, ctx| async move {
        let (t, org, id) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, id, "canceled", "starter", 0).await;
        assert_eq!(new_connection(&req, &t, &org).await.status_code(), 201);
        let res = req
            .patch(&format!("/v1/orgs/{org}"))
            .add_header("X-CSRF-Token", &t)
            .json(&json!({ "name": "Acme 2" }))
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let invite = json!({ "email": "a@example.com", "role": "member" });
        let res = post(&req, &t, &format!("/v1/orgs/{org}/invites"), invite).await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn read_only_blocks_writes_402_allows_gets() {
    serve_with(enforced, |req, ctx| async move {
        let (t, org, id) = owner_org(&req, &prepare(&ctx)).await;
        // A new organisation has no subscription (`none`): read-only until checkout.
        refused(&new_connection(&req, &t, &org).await, "billing_required");
        for status in ["paused", "canceled", "trial_ended"] {
            set_billing(&ctx, id, status, "team", 0).await;
            refused(&new_connection(&req, &t, &org).await, "billing_required");
            let res = req
                .patch(&format!("/v1/orgs/{org}"))
                .add_header("X-CSRF-Token", &t)
                .json(&json!({ "name": "Acme 2" }))
                .await;
            refused(&res, "billing_required");
            for path in ["", "/connections", "/members", "/findings"] {
                let res = req.get(&format!("/v1/orgs/{org}{path}")).await;
                assert_eq!(res.status_code(), 200, "{path}: {}", res.text());
            }
        }
        // Org-less routes are not gated.
        let res = post(&req, &t, "/v1/orgs", json!({ "name": "Other" })).await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn read_only_exemptions_pass() {
    serve_with(enforced, |req, ctx| async move {
        let (t, org, id) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, id, "trial_ended", "team", 0).await;
        // Stripe is not configured here: 503 shows the request got past the gate.
        let res = post(
            &req,
            &t,
            &format!("/v1/orgs/{org}/billing/checkout"),
            json!({}),
        )
        .await;
        assert_eq!(res.status_code(), 503, "{}", res.text());
        let res = post(
            &req,
            &t,
            &format!("/v1/orgs/{org}/billing/portal"),
            json!({}),
        )
        .await;
        assert_eq!(res.status_code(), 503, "{}", res.text());
        let res = req
            .delete(&format!("/v1/orgs/{org}"))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(res.status_code(), 204, "{}", res.text());
        sign_out(&req, &t).await;
    })
    .await;
}

#[tokio::test]
#[serial]
async fn trial_second_connection_402_trial_limit() {
    serve_with(enforced, |req, ctx| async move {
        let (t, org, id) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, id, "trialing", "team", 0).await;
        let res = new_connection(&req, &t, &org).await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        let conn: Uuid = res.json::<Value>()["id"].as_str().unwrap().parse().unwrap();
        ctx.db
            .execute_raw(stmt(
                "UPDATE connections SET status = 'connected', external_account_id = 'a1' WHERE id = $1",
                vec![conn.into()],
            ))
            .await
            .unwrap();
        refused(&new_connection(&req, &t, &org).await, "trial_limit");
        // Once paying, more connections are fine.
        set_billing(&ctx, id, "active", "team", 0).await;
        assert_eq!(new_connection(&req, &t, &org).await.status_code(), 201);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn over_member_limit_blocks_invite() {
    serve_with(enforced, |mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (_, org, id) = owner_org(&req, &mail).await;
        set_billing(&ctx, id, "active", "starter", 0).await;
        // Starter allows 2 members: the owner plus one.
        as_member(&mut req, &ctx, &mail, &org, "member@example.com").await;
        req.clear_cookies();
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let invite = json!({ "email": "third@example.com", "role": "member" });
        let path = format!("/v1/orgs/{org}/invites");
        refused(&post(&req, &t, &path, invite.clone()).await, "plan_limit");
        // At (not over) the member limit, a Slack install still starts.
        let slack = format!("/v1/orgs/{org}/integrations/slack/start");
        assert_ne!(post(&req, &t, &slack, json!({})).await.status_code(), 402);
        // Over it, new integrations are refused too.
        as_member(&mut req, &ctx, &mail, &org, "extra@example.com").await;
        req.clear_cookies();
        let t = sign_in(&req, &mail, "owner@example.com").await;
        refused(&post(&req, &t, &slack, json!({})).await, "plan_limit");
        // The team tier allows 5.
        set_billing(&ctx, id, "active", "team", 0).await;
        let res = post(&req, &t, &path, invite).await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
    })
    .await;
}
