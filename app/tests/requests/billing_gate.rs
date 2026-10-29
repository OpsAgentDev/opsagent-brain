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

async fn invite(req: &TestServer, csrf: &str, org: &str, email: &str) -> TestResponse {
    let body = json!({ "email": email, "role": "member" });
    post(req, csrf, &format!("/v1/orgs/{org}/invites"), body).await
}

#[tokio::test]
#[serial]
async fn pending_invites_count_toward_member_limit() {
    serve_with(enforced, |req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) = owner_org(&req, &mail).await;
        set_billing(&ctx, id, "active", "starter", 0).await;
        // Owner plus one pending invite fills the starter's 2 seats.
        assert_eq!(
            invite(&req, &t, &org, "a@example.com").await.status_code(),
            201
        );
        refused(&invite(&req, &t, &org, "b@example.com").await, "plan_limit");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn accept_refused_over_limit_or_read_only() {
    serve_with(enforced, |mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) = owner_org(&req, &mail).await;
        set_billing(&ctx, id, "active", "team", 0).await;
        assert_eq!(
            invite(&req, &t, &org, "late@example.com")
                .await
                .status_code(),
            201
        );
        let accept = format!("/v1/invites/{}/accept", token_of(&last_link(&mail)));
        // Downgraded to starter, and the second seat taken meanwhile.
        set_billing(&ctx, id, "active", "starter", 0).await;
        as_member(&mut req, &ctx, &mail, &org, "member@example.com").await;
        req.clear_cookies();
        let tl = sign_in(&req, &mail, "late@example.com").await;
        let res = req.post(&accept).add_header("X-CSRF-Token", &tl).await;
        refused(&res, "plan_limit");
        // Read-only refuses too; the invite stayed pending, so it can still be accepted later.
        set_billing(&ctx, id, "canceled", "team", 0).await;
        let res = req.post(&accept).add_header("X-CSRF-Token", &tl).await;
        refused(&res, "billing_required");
        set_billing(&ctx, id, "active", "team", 0).await;
        let res = req.post(&accept).add_header("X-CSRF-Token", &tl).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
    })
    .await;
}

async fn connection_row(ctx: &TestApp, id: &str) -> (String, Option<String>) {
    let r = ctx
        .db
        .query_one_raw(stmt(
            "SELECT status, status_reason FROM connections WHERE id = $1::uuid",
            vec![id.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    (
        r.try_get("", "status").unwrap(),
        r.try_get("", "status_reason").unwrap(),
    )
}

async fn count(ctx: &TestApp, sql: &str) -> i64 {
    let r = ctx
        .db
        .query_one_raw(stmt(sql, vec![]))
        .await
        .unwrap()
        .unwrap();
    r.try_get("", "n").unwrap()
}

#[tokio::test]
#[serial]
async fn trial_pending_connection_counts_and_verify_holds_second() {
    serve_with(enforced, |req, ctx| async move {
        let (t, org, id) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, id, "trialing", "team", 0).await;
        assert_eq!(new_connection(&req, &t, &org).await.status_code(), 201);
        // Still pending, it is the trial's one connection.
        refused(&new_connection(&req, &t, &org).await, "trial_limit");

        // Two pending from before the trial: the second to verify stays pending.
        ctx.db
            .execute_raw(stmt(
                "UPDATE connections SET status = 'disconnected', disconnected_at = now() \
                 WHERE organisation_id = $1",
                vec![id.into()],
            ))
            .await
            .unwrap();
        set_billing(&ctx, id, "active", "team", 0).await;
        let a = create_connection(&req, &t, &org, "fake", "clean").await;
        let b = create_connection(&req, &t, &org, "fake", "noisy").await;
        let (a, b) = (a["id"].as_str().unwrap(), b["id"].as_str().unwrap());
        set_billing(&ctx, id, "trialing", "team", 0).await;
        assert_eq!(verify(&req, &t, &org, a, "").await.status_code(), 202);
        assert_eq!(connection_row(&ctx, a).await.0, "connected");
        assert_eq!(verify(&req, &t, &org, b, "").await.status_code(), 202);
        assert_eq!(
            connection_row(&ctx, b).await,
            ("pending".into(), Some("trial_limit".into()))
        );
        let q = format!(
            "SELECT count(*) n FROM runs WHERE connection_id = '{b}' AND job_type = 'verify' \
             AND status = 'skipped' AND partial_reason = 'trial_limit'"
        );
        assert_eq!(count(&ctx, &q).await, 1);
        // Subscribed: verifying again connects it (a later minute, so a new verify run).
        set_billing(&ctx, id, "active", "team", 0).await;
        let earlier = format!(
            "UPDATE runs SET scheduled_at = scheduled_at - interval '1 hour' WHERE connection_id = '{b}'"
        );
        ctx.db.execute_raw(stmt(&earlier, vec![])).await.unwrap();
        assert_eq!(verify(&req, &t, &org, b, "").await.status_code(), 202);
        assert_eq!(connection_row(&ctx, b).await.0, "connected");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn trial_reconnects_its_account_but_not_another() {
    serve_with(enforced, |req, ctx| async move {
        let (t, org, id) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, id, "trialing", "team", 0).await;
        let disconnect = |c: String| {
            let (req, t, org) = (&req, &t, &org);
            async move {
                let res = req
                    .delete(&format!("/v1/orgs/{org}/connections/{c}"))
                    .add_header("X-CSRF-Token", t)
                    .await;
                assert_eq!(res.status_code(), 200, "{}", res.text());
            }
        };
        let connect = |account: &'static str| {
            let (req, t, org) = (&req, &t, &org);
            async move {
                let c = create_connection(req, t, org, "fake", account).await;
                let c = c["id"].as_str().unwrap().to_owned();
                assert_eq!(verify(req, t, org, &c, "").await.status_code(), 202);
                c
            }
        };
        let first = connect("clean").await;
        assert_eq!(connection_row(&ctx, &first).await.0, "connected");
        disconnect(first).await;
        // The same account again in the trial: allowed, it is already the one paid for.
        let again = connect("clean").await;
        assert_eq!(connection_row(&ctx, &again).await.0, "connected");
        disconnect(again).await;
        // A different account would be a second one this period.
        let other = connect("noisy").await;
        assert_eq!(
            connection_row(&ctx, &other).await,
            ("pending".into(), Some("trial_limit".into()))
        );
    })
    .await;
}

fn key(org: Uuid, conn: &str, job: &str) -> opsagent_core::run::RunKey {
    opsagent_core::run::RunKey {
        organisation_id: Some(org),
        connection_id: Some(conn.parse().unwrap()),
        job_type: job.into(),
        scheduled_at: chrono::Utc::now(),
    }
}

#[tokio::test]
#[serial]
async fn worker_skips_gated_jobs_but_verifies_without_first_scan() {
    serve_with(enforced, |req, ctx| async move {
        let (t, org, id) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, id, "active", "team", 0).await;
        let c = create_connection(&req, &t, &org, "fake", "clean").await;
        let c = c["id"].as_str().unwrap();
        set_billing(&ctx, id, "paused", "team", 8).await;
        let d = actions(&ctx).unwrap().runs.dispatcher.clone();
        // As `POST .../verify` leaves it (that route is read-only now).
        ctx.db
            .execute_raw(stmt(
                "UPDATE connections SET status = 'verifying' WHERE id = $1::uuid",
                vec![c.into()],
            ))
            .await
            .unwrap();
        // Verify is not gated: the connection connects, but no first scan is queued.
        d.enqueue(key(id, c, "verify"), chrono::Utc::now()).await.unwrap();
        ctx.drain_jobs().await;
        assert_eq!(connection_row(&ctx, c).await.0, "connected");
        let scans = format!("SELECT count(*) n FROM runs WHERE connection_id = '{c}' AND job_type = 'full_scan'");
        assert_eq!(count(&ctx, &scans).await, 0);
        // Jobs already queued (or retried, or continued) end skipped when a worker picks them up.
        for job in ["full_scan", "deliver_briefing"] {
            d.enqueue(key(id, c, job), chrono::Utc::now()).await.unwrap();
        }
        ctx.drain_jobs().await;
        let skipped = format!(
            "SELECT count(*) n FROM runs WHERE connection_id = '{c}' \
             AND job_type IN ('full_scan', 'deliver_briefing') AND status = 'skipped' AND partial_reason = 'billing'"
        );
        assert_eq!(count(&ctx, &skipped).await, 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn past_due_7_days_is_read_only_before_the_nightly() {
    serve_with(enforced, |req, ctx| async move {
        let (t, org, id) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, id, "past_due", "team", 6).await;
        assert_eq!(new_connection(&req, &t, &org).await.status_code(), 201);
        set_billing(&ctx, id, "past_due", "team", 7).await;
        refused(&new_connection(&req, &t, &org).await, "billing_required");
    })
    .await;
}
