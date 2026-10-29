//! `billing_sync` (billing.md, Build decisions 3, 8 and 13): quantity sync at connection
//! lifecycle points and at period rollover, and the nightly revoked-connection sweep.
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

/// No quantity update at all.
async fn expect_no_update(api: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/subscriptions/sub_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "sub_1" })))
        .expect(0)
        .named("no quantity update")
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

#[tokio::test]
#[serial]
async fn disconnect_reconnect_same_period_no_extra_charge() {
    let api = MockServer::start().await;
    subscription_mock(&api).await;
    expect_no_update(&api).await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        subscribe(&ctx, id, 1, Utc::now() - Duration::days(1)).await;
        let first = connect(&req, &t, &org, "clean").await;
        let res = req
            .delete(&format!("/v1/orgs/{org}/connections/{first}"))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(status(&ctx, first).await, "disconnected");
        // The same account again, inside the period: still one billable connection.
        let again = connect(&req, &t, &org, "clean").await;
        assert_eq!(status(&ctx, again).await, "connected");
        // Connect, disconnect, reconnect each synced, and none changed the quantity.
        assert_eq!(sync_runs(&ctx).await, (3, 3));
    })
    .await;
    api.verify().await;
}

#[tokio::test]
#[serial]
async fn rollover_decreases_without_proration() {
    let api = MockServer::start().await;
    subscription_mock(&api).await;
    expect_update(&api, 1, "none", 1).await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        let old = secs(Utc::now() - Duration::days(31));
        subscribe(&ctx, id, 3, old).await;
        // Fewer connections than paid for: no change until the period rolls over.
        connect(&req, &t, &org, "clean").await;
        let new = secs(Utc::now() - Duration::hours(1));
        let item = json!({ "id": "si_1", "quantity": 3, "price": { "id": "price_team" },
            "current_period_start": new.timestamp(),
            "current_period_end": (new + Duration::days(30)).timestamp() });
        let object = json!({ "id": "sub_1", "object": "subscription", "customer": "cus_1",
            "status": "active", "items": { "data": [item] } });
        let created = Utc::now().timestamp() - at(0).timestamp();
        let ev = event("evt_roll", "customer.subscription.updated", created, object);
        deliver(&req, &ev).await;
        ctx.drain_jobs().await;
        // A redelivery of the same rollover adds no second decrease.
        let mut dup = ev.clone();
        dup["id"] = "evt_roll_2".into();
        deliver(&req, &dup).await;
        ctx.drain_jobs().await;
        assert_eq!(sync_runs(&ctx).await, (2, 2));
    })
    .await;
    api.verify().await;
}

#[tokio::test]
#[serial]
async fn revoked_past_period_end_disconnected() {
    let api = MockServer::start().await;
    subscription_mock(&api).await;
    expect_no_update(&api).await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        let start = Utc::now() - Duration::days(2);
        subscribe(&ctx, id, 2, start).await;
        let old = connect(&req, &t, &org, "clean").await;
        let recent = connect(&req, &t, &org, "degraded").await;
        // Revoked before this period began (its period ended revoked), and during it.
        for (c, since) in [
            (old, start - Duration::days(3)),
            (recent, start + Duration::days(1)),
        ] {
            let row = connections::Entity::find_by_id(c).one(&ctx.db).await;
            let mut a: connections::ActiveModel = row.unwrap().unwrap().into();
            a.status = Set("revoked".into());
            a.verify_denied_streak = Set(3);
            a.verify_denied_first_at = Set(Some(since.into()));
            a.update(&ctx.db).await.unwrap();
        }
        nightly(&ctx).await;
        assert_eq!(status(&ctx, old).await, "disconnected");
        let row = connections::Entity::find_by_id(old).one(&ctx.db).await;
        let reason = row.unwrap().unwrap().status_reason;
        assert_eq!(reason.as_deref(), Some("revoked_at_period_end"));
        assert_eq!(status(&ctx, recent).await, "revoked");
        // Idempotent: a second night changes nothing.
        nightly(&ctx).await;
        assert_eq!(status(&ctx, recent).await, "revoked");
    })
    .await;
    api.verify().await;
}

#[tokio::test]
#[serial]
async fn rollover_ends_revoked_and_bills_one_less() {
    let api = MockServer::start().await;
    subscription_mock(&api).await;
    expect_update(&api, 1, "none", 1).await;
    serve_with(stripe_on(api.uri()), |req, ctx| async move {
        let (t, org, id) = org_with_customer(&req, &ctx).await;
        let old = secs(Utc::now() - Duration::days(31));
        subscribe(&ctx, id, 2, old).await;
        // The revoked one was connected (billable_from set), so only the reason keeps it unbilled.
        let gone = connect(&req, &t, &org, "clean").await;
        connect(&req, &t, &org, "degraded").await;
        // Revoked during the period that is about to end.
        let row = connections::Entity::find_by_id(gone).one(&ctx.db).await;
        let mut a: connections::ActiveModel = row.unwrap().unwrap().into();
        a.status = Set("revoked".into());
        a.verify_denied_first_at = Set(Some((old + Duration::days(10)).into()));
        a.update(&ctx.db).await.unwrap();
        let new = secs(Utc::now() - Duration::hours(1));
        let item = json!({ "id": "si_1", "quantity": 2, "price": { "id": "price_team" },
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
        assert_eq!(status(&ctx, gone).await, "disconnected");
        // The nightly pass after it bills nothing more and changes nothing.
        nightly(&ctx).await;
    })
    .await;
    api.verify().await;
}
