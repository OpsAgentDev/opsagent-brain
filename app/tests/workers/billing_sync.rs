//! `billing_sync` (billing.md, Build decisions 3, 8 and 13; PRD 7.9): quantity sync at
//! connection lifecycle points against the period's paid quantity, and the nightly sweep of
//! revoked connections before renewal.
use axum_test::TestServer;
use chrono::{DateTime, Duration, DurationRound, Utc};
use opsagent_brain::models::_entities::connections;
use opsagent_brain::{adapters::db::ledger_storage::PgStorage, adapters::db::Pg};
use opsagent_core::{
    billing::{BillingRepo, BillingStatus as B, SubscriptionState, Tier},
    run::RunKey,
};
use opsagent_ledger::{JobKind, Storage};
use sea_orm::{entity::prelude::*, ConnectionTrait, Set};
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;
use wiremock::{
    matchers::{body_string_contains, header_exists, method, path},
    Mock, MockServer, ResponseTemplate,
};

use crate::requests::{billing::*, support::*};

/// Whole seconds, as Stripe stamps them.
fn secs(t: DateTime<Utc>) -> DateTime<Utc> {
    t.duration_trunc(Duration::seconds(1)).unwrap()
}

/// Stores an `active` Team subscription `sub_1` of `quantity` whose period began at `start`.
async fn subscribe(ctx: &TestApp, org: Uuid, quantity: i32, start: DateTime<Utc>) {
    let s = SubscriptionState {
        subscription_id: "sub_1".into(),
        status: B::Active,
        tier: Some(Tier::Team),
        quantity,
        trial_ends_at: None,
        current_period_start: Some(start),
        current_period_end: Some(start + Duration::days(30)),
    };
    let created = Utc::now() - Duration::hours(1);
    assert!(Pg::new(&ctx.db)
        .apply_subscription(org, &s, created)
        .await
        .unwrap());
}

/// `GET /v1/subscriptions/sub_1` (the item id `set_quantity` needs).
async fn subscription_mock(api: &MockServer) {
    let body = json!({ "id": "sub_1", "items": { "data": [{ "id": "si_1" }] } });
    Mock::given(method("GET"))
        .and(path("/v1/subscriptions/sub_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(api)
        .await;
}

/// Expects `n` quantity updates to `quantity` with `proration`.
async fn expect_update(api: &MockServer, quantity: i32, proration: &str, n: u64) {
    Mock::given(method("POST"))
        .and(path("/v1/subscriptions/sub_1"))
        .and(header_exists("Idempotency-Key"))
        .and(body_string_contains(format!(
            "items%5B0%5D%5Bquantity%5D={quantity}"
        )))
        .and(body_string_contains(format!(
            "proration_behavior={proration}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "sub_1" })))
        .expect(n)
        .named(format!("quantity {quantity} {proration}"))
        .mount(api)
        .await;
}

/// Creates a fake connection for fixture `account` and verifies it (the worker runs).
async fn connect(req: &TestServer, csrf: &str, org: &str, account: &str) -> Uuid {
    let c = create_connection(req, csrf, org, "fake", account).await;
    let id = c["id"].as_str().unwrap();
    assert_eq!(verify(req, csrf, org, id, "").await.status_code(), 202);
    id.parse().unwrap()
}

async fn status(ctx: &TestApp, id: Uuid) -> String {
    let c = connections::Entity::find_by_id(id).one(&ctx.db).await;
    c.unwrap().unwrap().status
}

async fn sync_runs(ctx: &TestApp) -> (i64, i64) {
    let sql = "SELECT count(*) AS n, count(*) FILTER (WHERE status = 'done') AS done \
               FROM runs WHERE job_type = 'billing_sync'";
    let r = ctx
        .db
        .query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            sql,
        ))
        .await
        .unwrap()
        .unwrap();
    (r.try_get("", "n").unwrap(), r.try_get("", "done").unwrap())
}

/// One nightly (global) run, performed.
async fn nightly(ctx: &TestApp) {
    let key = RunKey {
        organisation_id: None,
        connection_id: None,
        job_type: JobKind::BillingSync.as_str().into(),
        scheduled_at: Utc::now(),
    };
    let id = PgStorage::new(ctx.db.clone())
        .create_run(key)
        .await
        .unwrap()
        .run
        .id;
    perform(ctx, JobKind::BillingSync, id).await.unwrap();
}

#[tokio::test]
#[serial]
async fn connect_increases_quantity_with_proration() {
    let api = MockServer::start().await;
    subscription_mock(&api).await;
    expect_update(&api, 2, "create_prorations", 1).await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        subscribe(&ctx, id, 1, Utc::now() - Duration::days(1)).await;
        // The first connection is the quantity already paid for.
        let a = connect(&req, &t, &org, "clean").await;
        assert_eq!(status(&ctx, a).await, "connected");
        let b = connect(&req, &t, &org, "degraded").await;
        assert_eq!(status(&ctx, b).await, "degraded");
        let (n, done) = sync_runs(&ctx).await;
        assert_eq!((n, done), (2, 2));
        // Internal billing runs stay out of the organisation's run history.
        let runs: serde_json::Value = req.get(&format!("/v1/orgs/{org}/runs")).await.json();
        let types: Vec<_> = runs["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["job_type"].clone())
            .collect();
        assert!(
            !types.is_empty() && !types.contains(&json!("billing_sync")),
            "{types:?}"
        );
    })
    .await;
    api.verify().await;
}

/// Expects no prorated update at all.
async fn expect_no_proration(api: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/subscriptions/sub_1"))
        .and(body_string_contains("proration_behavior=create_prorations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "sub_1" })))
        .expect(0)
        .named("no proration")
        .mount(api)
        .await;
}

async fn disconnect(req: &TestServer, csrf: &str, org: &str, id: Uuid) {
    let res = req
        .delete(&format!("/v1/orgs/{org}/connections/{id}"))
        .add_header("X-CSRF-Token", csrf)
        .await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
}

/// (stored quantity, paid quantity).
async fn quantities(ctx: &TestApp, org: Uuid) -> (i32, Option<i32>) {
    let b = Pg::new(&ctx.db).billing(org).await.unwrap();
    (b.subscription.unwrap().quantity, b.paid_quantity)
}

#[tokio::test]
#[serial]
async fn disconnect_decreases_at_once_and_reconnect_is_not_charged_again() {
    let api = MockServer::start().await;
    subscription_mock(&api).await;
    expect_no_proration(&api).await;
    // Each twice: the first connect alone is below the 2 paid, then the second brings it back.
    expect_update(&api, 1, "none", 2).await;
    expect_update(&api, 2, "none", 2).await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        subscribe(&ctx, id, 2, Utc::now() - Duration::days(1)).await;
        connect(&req, &t, &org, "clean").await;
        let second = connect(&req, &t, &org, "degraded").await;
        // Stripe bills the next period in advance: the decrease goes now, with no refund.
        disconnect(&req, &t, &org, second).await;
        assert_eq!(status(&ctx, second).await, "disconnected");
        assert_eq!(quantities(&ctx, id).await, (1, Some(2)));
        // The same account back inside the period: already paid for, so no charge.
        let again = connect(&req, &t, &org, "degraded").await;
        assert_eq!(status(&ctx, again).await, "degraded");
        assert_eq!(quantities(&ctx, id).await, (2, Some(2)));
        assert_eq!(sync_runs(&ctx).await, (4, 4));
    })
    .await;
    api.verify().await;
}

#[tokio::test]
#[serial]
async fn rollover_resets_paid_quantity_without_a_write() {
    let api = MockServer::start().await;
    subscription_mock(&api).await;
    expect_update(&api, 1, "none", 1).await;
    expect_update(&api, 2, "create_prorations", 1).await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        let old = secs(Utc::now() - Duration::days(31));
        subscribe(&ctx, id, 3, old).await;
        // Fewer connections than paid for: down at once, the paid quantity kept.
        connect(&req, &t, &org, "clean").await;
        assert_eq!(quantities(&ctx, id).await, (1, Some(3)));
        let new = secs(Utc::now() - Duration::hours(1));
        let item = json!({ "id": "si_1", "quantity": 1, "price": { "id": "price_team" },
            "current_period_start": new.timestamp(),
            "current_period_end": (new + Duration::days(30)).timestamp() });
        let object = json!({ "id": "sub_1", "object": "subscription", "customer": "cus_1",
            "status": "active", "items": { "data": [item] } });
        let created = Utc::now().timestamp() - at(0).timestamp();
        deliver(
            &req,
            &event("evt_roll", "customer.subscription.updated", created, object),
        )
        .await;
        ctx.drain_jobs().await;
        // The renewal billed 1: that is all this period has paid for.
        assert_eq!(quantities(&ctx, id).await, (1, Some(1)));
        assert_eq!(sync_runs(&ctx).await, (1, 1));
        connect(&req, &t, &org, "degraded").await;
        assert_eq!(quantities(&ctx, id).await, (2, Some(2)));
    })
    .await;
    api.verify().await;
}

#[tokio::test]
#[serial]
async fn increase_past_paid_restores_free_then_prorates_the_rest() {
    let api = MockServer::start().await;
    subscription_mock(&api).await;
    expect_update(&api, 1, "none", 2).await;
    expect_update(&api, 2, "none", 2).await;
    expect_update(&api, 3, "create_prorations", 1).await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        subscribe(&ctx, id, 2, Utc::now() - Duration::days(1)).await;
        let a = connect(&req, &t, &org, "clean").await;
        let b = connect(&req, &t, &org, "degraded").await;
        disconnect(&req, &t, &org, a).await;
        disconnect(&req, &t, &org, b).await;
        assert_eq!(quantities(&ctx, id).await, (1, Some(2)));
        // Three at once (a dropped connection from before): back to 2 free, then prorate 3.
        for c in [a, b] {
            let row = connections::Entity::find_by_id(c).one(&ctx.db).await;
            let mut m: connections::ActiveModel = row.unwrap().unwrap().into();
            m.status = Set("connected".into());
            m.update(&ctx.db).await.unwrap();
        }
        connect(&req, &t, &org, "noisy").await;
        assert_eq!(quantities(&ctx, id).await, (3, Some(3)));
    })
    .await;
    api.verify().await;
}

#[tokio::test]
#[serial]
async fn revoked_through_period_end_disconnected_before_renewal() {
    let api = MockServer::start().await;
    subscription_mock(&api).await;
    expect_no_proration(&api).await;
    expect_update(&api, 1, "none", 1).await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        // The period ends in 12 hours.
        let start = Utc::now() - Duration::days(30) + Duration::hours(12);
        subscribe(&ctx, id, 2, start).await;
        let gone = connect(&req, &t, &org, "clean").await;
        let kept = connect(&req, &t, &org, "degraded").await;
        let row = connections::Entity::find_by_id(gone).one(&ctx.db).await;
        let mut a: connections::ActiveModel = row.unwrap().unwrap().into();
        a.status = Set("revoked".into());
        a.verify_denied_streak = Set(3);
        a.verify_denied_first_at = Set(Some((start + Duration::days(10)).into()));
        a.update(&ctx.db).await.unwrap();
        nightly(&ctx).await;
        assert_eq!(status(&ctx, gone).await, "disconnected");
        let row = connections::Entity::find_by_id(gone).one(&ctx.db).await;
        let reason = row.unwrap().unwrap().status_reason;
        assert_eq!(reason.as_deref(), Some("revoked_at_period_end"));
        assert_eq!(status(&ctx, kept).await, "degraded");
        // Down to 1 before the period ends, so the renewal does not bill it.
        assert_eq!(quantities(&ctx, id).await, (1, Some(2)));
        // Idempotent: a second night changes nothing.
        nightly(&ctx).await;
    })
    .await;
    api.verify().await;
}

#[tokio::test]
#[serial]
async fn nightly_reconciles_a_drifted_quantity() {
    let api = MockServer::start().await;
    subscription_mock(&api).await;
    expect_update(&api, 1, "none", 1).await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        subscribe(&ctx, id, 1, Utc::now() - Duration::days(1)).await;
        connect(&req, &t, &org, "clean").await;
        // Stripe reports 3 (changed outside billing_sync) for one live connection.
        Pg::new(&ctx.db).record_quantity(id, 3, 3).await.unwrap();
        nightly(&ctx).await;
        assert_eq!(quantities(&ctx, id).await, (1, Some(3)));
    })
    .await;
    api.verify().await;
}
