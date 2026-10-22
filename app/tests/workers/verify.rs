use chrono::{Duration, Utc};
use loco_rs::{bgworker::BackgroundWorker, prelude::*};
use opsagent_brain::{
    models::{
        _entities::{audit_events, connection_verifications, connections, runs},
        ledger_storage::PgStorage,
    },
    workers::verify::{VerifyArgs, VerifyWorker},
};
use opsagent_core::run::RunKey;
use opsagent_ledger::Storage;
use serial_test::serial;
use uuid::Uuid;

use crate::requests::support::*;

async fn conn(ctx: &AppContext, id: Uuid) -> connections::Model {
    connections::Entity::find_by_id(id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
}

/// Creates a run for the connection at a fixed key and performs the worker on it.
async fn run_worker(ctx: &AppContext, id: Uuid, minute: i64) -> Uuid {
    let c = conn(ctx, id).await;
    let run = PgStorage::new(ctx.db.clone())
        .create_run(RunKey {
            organisation_id: Some(c.organisation_id),
            connection_id: Some(id),
            job_type: "verify".into(),
            scheduled_at: chrono::DateTime::from_timestamp(1_800_000_000 + minute * 60, 0).unwrap(),
        })
        .await
        .unwrap()
        .run;
    VerifyWorker::build(ctx)
        .perform(VerifyArgs { run_id: run.id })
        .await
        .unwrap();
    run.id
}

async fn set(ctx: &AppContext, id: Uuid, f: impl FnOnce(&mut connections::ActiveModel)) {
    let mut a: connections::ActiveModel = conn(ctx, id).await.into();
    f(&mut a);
    a.update(&ctx.db).await.unwrap();
}

#[tokio::test]
#[serial]
async fn second_org_racing_to_same_account_ends_blocked() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (_, oa, ida) = fake_connection(&req, &mail, "a@example.com", "Alpha", "clean").await;
        req.clear_cookies();
        let (_, _, idb) = fake_connection(&req, &mail, "b@example.com", "Beta", "clean").await;
        let idb: Uuid = idb.parse().unwrap();
        // B's verify was accepted before A's worker claimed the account.
        set(&ctx, idb, |a| a.status = Set("verifying".into())).await;
        req.clear_cookies();
        let ta = sign_in(&req, &mail, "a@example.com").await;
        assert_eq!(verify(&req, &ta, &oa, &ida, "").await.status_code(), 202);
        assert_eq!(conn(&ctx, ida.parse().unwrap()).await.status, "connected");

        run_worker(&ctx, idb, 0).await;
        let b = conn(&ctx, idb).await;
        assert_eq!(b.status, "blocked");
        assert_eq!(
            b.status_reason.as_deref(),
            Some("account_already_connected")
        );
        assert!(b.billable_from.is_none());
        assert_eq!(conn(&ctx, ida.parse().unwrap()).await.status, "connected");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn same_run_key_is_one_run_and_one_verification() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (_, _, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        let id: Uuid = id.parse().unwrap();
        set(&ctx, id, |a| a.status = Set("verifying".into())).await;
        let r1 = run_worker(&ctx, id, 0).await;
        let r2 = run_worker(&ctx, id, 0).await;
        assert_eq!(r1, r2);
        let n = runs::Entity::find()
            .filter(runs::Column::ConnectionId.eq(id))
            .count(&ctx.db)
            .await
            .unwrap();
        assert_eq!(n, 1);
        let v = connection_verifications::Entity::find()
            .filter(connection_verifications::Column::ConnectionId.eq(id))
            .count(&ctx.db)
            .await
            .unwrap();
        assert_eq!(v, 1);
        let run = runs::Entity::find_by_id(r1)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.status, "done");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn access_denied_three_times_over_an_hour_revokes() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (_, _, id) = fake_connection(&req, &mail, "o@example.com", "Org", "denied").await;
        let id: Uuid = id.parse().unwrap();
        // Previously connected; the customer deleted the stack.
        set(&ctx, id, |a| {
            a.status = Set("connected".into());
            a.external_account_id = Set(Some("denied".into()));
        })
        .await;

        let r = run_worker(&ctx, id, 0).await;
        let c = conn(&ctx, id).await;
        assert_eq!(
            (c.status.as_str(), c.verify_denied_streak),
            ("connected", 1)
        );
        let run = runs::Entity::find_by_id(r)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((run.status.as_str(), run.attempts), ("queued", 1));
        assert!(run.next_attempt_at.is_some());

        run_worker(&ctx, id, 1).await;
        run_worker(&ctx, id, 2).await;
        // Three denials within minutes: not yet an hour, stays connected.
        let c = conn(&ctx, id).await;
        assert_eq!(
            (c.status.as_str(), c.verify_denied_streak),
            ("connected", 3)
        );

        set(&ctx, id, |a| {
            a.verify_denied_first_at = Set(Some((Utc::now() - Duration::hours(2)).into()))
        })
        .await;
        run_worker(&ctx, id, 3).await;
        let c = conn(&ctx, id).await;
        assert_eq!(c.status, "revoked");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn non_retryable_connector_error_is_recorded_on_first_run() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        // No fixture for this account: the fake connector answers NotFound.
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "nosuch").await;
        let res = verify(&req, &t, &org, &id, "").await;
        assert_eq!(res.status_code(), 202, "{}", res.text());
        let id: Uuid = id.parse().unwrap();
        let c = conn(&ctx, id).await;
        assert_eq!(c.status, "verifying");
        assert_eq!(c.status_reason.as_deref(), Some("verify_error:not_found"));
        let v = connection_verifications::Entity::find()
            .filter(connection_verifications::Column::ConnectionId.eq(id))
            .all(&ctx.db)
            .await
            .unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].outcome, "error");
        let run = runs::Entity::find_by_id(v[0].run_id.unwrap())
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((run.status.as_str(), run.attempts), ("failed", 0));
        let a = audit_events::Entity::find()
            .filter(audit_events::Column::Action.eq("connection.verify_outcome"))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(a.outcome.as_deref(), Some("error"));
        assert_eq!(a.metadata["code"], "not_found");
    })
    .await;
}
