use chrono::{Duration, Utc};
use opsagent_brain::adapters::db::ledger_storage::PgStorage;
use opsagent_brain::models::_entities::{
    audit_events, connection_verifications, connections, runs, schedules,
};
use opsagent_core::run::RunKey;
use opsagent_ledger::{JobKind, Storage};
use sea_orm::{entity::prelude::*, Set};
use serial_test::serial;
use uuid::Uuid;

use crate::requests::support::*;

async fn conn(ctx: &TestApp, id: Uuid) -> connections::Model {
    connections::Entity::find_by_id(id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
}

/// Creates a run for the connection at a fixed key and performs the worker on it.
async fn run_worker(ctx: &TestApp, id: Uuid, minute: i64) -> Uuid {
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
    perform(ctx, JobKind::Verify, run.id).await.unwrap();
    run.id
}

async fn set(ctx: &TestApp, id: Uuid, f: impl FnOnce(&mut connections::ActiveModel)) {
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
        // Blocked is not connected: no default schedules.
        let n = schedules::Entity::find()
            .filter(schedules::Column::ConnectionId.eq(idb))
            .count(&ctx.db)
            .await
            .unwrap();
        assert_eq!(n, 0);
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
            .filter(runs::Column::JobType.eq("verify"))
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

async fn set_fixture(ctx: &TestApp, id: Uuid, account: &str) {
    use opsagent_brain::{adapters::db::Pg, creds};
    let kek = kek(ctx).unwrap();
    let (org, repo) = (conn(ctx, id).await.organisation_id, Pg::new(&ctx.db));
    let mut c = creds::load(&repo, kek.as_ref(), org, id).await.unwrap();
    c.fake_account = Some(account.into());
    creds::save(&repo, kek.as_ref(), org, id, &c).await.unwrap();
}

async fn verify_cron(ctx: &TestApp, id: Uuid) -> String {
    schedules::Entity::find()
        .filter(schedules::Column::ConnectionId.eq(id))
        .filter(schedules::Column::JobType.eq("verify"))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
        .cron_local
}

async fn scans(ctx: &TestApp, id: Uuid) -> Vec<runs::Model> {
    runs::Entity::find()
        .filter(runs::Column::ConnectionId.eq(id))
        .filter(runs::Column::JobType.eq("full_scan"))
        .all(&ctx.db)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn first_connect_queues_one_first_scan() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        let id: Uuid = id.parse().unwrap();
        let first = scans(&ctx, id).await;
        assert_eq!(first.len(), 1);
        // Foreground workers: the scan ran inline and the outbox marker is cleared.
        assert_eq!(first[0].status, "done");
        assert!(first[0].next_attempt_at.is_none());
        // Later verifications of a connected connection queue nothing.
        run_worker(&ctx, id, 7).await;
        assert_eq!(scans(&ctx, id).await.len(), 1);
    })
    .await;
}

/// The customer deletes the stack: three denials over more than an hour revoke it (minutes 0-3).
async fn revoke(ctx: &TestApp, id: Uuid) {
    set_fixture(ctx, id, "denied").await;
    for n in 0..3 {
        run_worker(ctx, id, n).await;
    }
    set(ctx, id, |a| {
        a.verify_denied_first_at = Set(Some((Utc::now() - Duration::hours(2)).into()))
    })
    .await;
    run_worker(ctx, id, 3).await;
    assert_eq!(conn(ctx, id).await.status, "revoked");
}

#[tokio::test]
#[serial]
async fn revoked_connection_recovering_degraded_goes_back_to_weekly_verify() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        let id: Uuid = id.parse().unwrap();
        revoke(&ctx, id).await;
        assert_eq!(verify_cron(&ctx, id).await, "0 4 * * *");

        set_fixture(&ctx, id, "degraded").await;
        run_worker(&ctx, id, 4).await;
        assert_eq!(conn(&ctx, id).await.status, "degraded");
        assert_eq!(verify_cron(&ctx, id).await, "0 3 * * 1");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn revoked_connection_is_rechecked_daily_and_recovers() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        let id: Uuid = id.parse().unwrap();
        assert_eq!(verify_cron(&ctx, id).await, "0 3 * * 1");

        revoke(&ctx, id).await;
        assert_eq!(verify_cron(&ctx, id).await, "0 4 * * *");

        // A daily check while the role is still gone: stays revoked, no retry parked.
        let r = run_worker(&ctx, id, 4).await;
        let run = runs::Entity::find_by_id(r)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((run.status.as_str(), run.attempts), ("done", 0));
        assert_eq!(conn(&ctx, id).await.status, "revoked");

        // The role returns: the next daily check re-verifies in full and recovers.
        set_fixture(&ctx, id, "clean").await;
        run_worker(&ctx, id, 5).await;
        let c = conn(&ctx, id).await;
        assert_eq!(
            (c.status.as_str(), c.verify_denied_streak),
            ("connected", 0)
        );
        assert_eq!(verify_cron(&ctx, id).await, "0 3 * * 1");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn killed_verify_resumes_to_the_uninterrupted_outcome() {
    use opsagent_brain::models::_entities::audit_events;
    use opsagent_core::run::RunStatus;
    use opsagent_ledger::{lease, LedgerError};
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (_, _, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        let id: Uuid = id.parse().unwrap();
        set(&ctx, id, |a| a.status = Set("verifying".into())).await;
        let c = conn(&ctx, id).await;
        let storage = PgStorage::new(ctx.db.clone());
        let run = storage
            .create_run(RunKey {
                organisation_id: Some(c.organisation_id),
                connection_id: Some(id),
                job_type: "verify".into(),
                scheduled_at: chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            })
            .await
            .unwrap()
            .run;

        // A worker takes the lease, starts the run, and dies before writing any outcome.
        let r = redis_of(&ctx);
        let dead = lease::acquire(
            &storage,
            &r,
            run.id,
            "dead",
            std::time::Duration::from_secs(60),
        )
        .await
        .unwrap()
        .unwrap();
        storage
            .set_status(run.id, dead.fence, RunStatus::Running, None)
            .await
            .unwrap();
        // Its lease expires.
        lease::release(&r, &dead).await;

        // Redelivery: a fresh worker resumes and reaches the normal outcome.
        perform(&ctx, JobKind::Verify, run.id).await.unwrap();
        let row = runs::Entity::find_by_id(run.id)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "done");
        assert_eq!(conn(&ctx, id).await.status, "connected");

        // The dead worker wakes up: its fence is stale, so it can change nothing.
        assert!(matches!(
            storage
                .set_status(run.id, dead.fence, RunStatus::Failed, None)
                .await,
            Err(LedgerError::StaleFence)
        ));
        // A second redelivery of the finished run is a no-op.
        perform(&ctx, JobKind::Verify, run.id).await.unwrap();
        let verifications = connection_verifications::Entity::find()
            .filter(connection_verifications::Column::ConnectionId.eq(id))
            .count(&ctx.db)
            .await
            .unwrap();
        let outcomes = audit_events::Entity::find()
            .filter(audit_events::Column::Action.eq("connection.verify_outcome"))
            .count(&ctx.db)
            .await
            .unwrap();
        assert_eq!((verifications, outcomes), (1, 1));
        assert_eq!(scans(&ctx, id).await.len(), 1, "one first scan");
        let row = runs::Entity::find_by_id(run.id)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "done");
    })
    .await;
}
