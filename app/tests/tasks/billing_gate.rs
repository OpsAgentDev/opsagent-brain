//! The scheduler under `BILLING_ENFORCED` (Plan 6 Task 4).
use chrono::{Duration, Utc};
use opsagent_brain::adapters::db::ledger_storage::stmt;
use sea_orm::ConnectionTrait;
use serial_test::serial;
use uuid::Uuid;

use super::scheduler_tick::{count, reset};
use crate::requests::{
    billing_gate::{enforced, owner_org, set_billing},
    support::*,
};

/// A connected connection of `org` with a due `full_scan` schedule.
async fn due_scan(ctx: &TestApp, org: Uuid) {
    let conn = Uuid::new_v4();
    ctx.db
        .execute_raw(stmt(
            "INSERT INTO connections (id, organisation_id, provider, status, external_account_id) \
             VALUES ($1, $2, 'fake', 'connected', 'acct-1')",
            vec![conn.into(), org.into()],
        ))
        .await
        .unwrap();
    ctx.db
        .execute_raw(stmt(
            "INSERT INTO schedules (id, organisation_id, connection_id, job_type, cron_local, next_due_at) \
             VALUES ($1, $2, $3, 'full_scan', '0 6 * * *', $4)",
            vec![
                Uuid::new_v4().into(),
                org.into(),
                conn.into(),
                (Utc::now() - Duration::minutes(1)).into(),
            ],
        ))
        .await
        .unwrap();
}

/// One tick, without a worker draining what it enqueued.
async fn tick(ctx: &TestApp) {
    let actions = actions(ctx).unwrap();
    actions.runs.scheduler_tick.run(Utc::now()).await.unwrap();
}

const SKIPPED: &str = "SELECT count(*) n FROM runs WHERE job_type = 'full_scan' \
    AND status = 'skipped' AND partial_reason = 'billing'";
const QUEUED: &str =
    "SELECT count(*) n FROM runs WHERE job_type = 'full_scan' AND status = 'queued'";
const JOBS: &str = "SELECT count(*) n FROM jobs";

#[tokio::test]
#[serial]
async fn scheduler_skips_gated_org() {
    serve_with(enforced, |req, ctx| async move {
        reset(&ctx).await;
        let (_, _, org) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, org, "paused", "team", 8).await;
        due_scan(&ctx, org).await;
        tick(&ctx).await;
        assert_eq!(count(&ctx, SKIPPED).await, 1);
        assert_eq!(count(&ctx, JOBS).await, 0);
        // The schedule moved on: the next tick adds nothing.
        tick(&ctx).await;
        assert_eq!(count(&ctx, "SELECT count(*) n FROM runs").await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn past_due_under_7_days_still_runs() {
    serve_with(enforced, |req, ctx| async move {
        reset(&ctx).await;
        let (_, _, org) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, org, "past_due", "team", 3).await;
        due_scan(&ctx, org).await;
        tick(&ctx).await;
        assert_eq!(count(&ctx, QUEUED).await, 1);
        assert_eq!(count(&ctx, SKIPPED).await, 0);
        assert_eq!(count(&ctx, JOBS).await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn not_enforced_scheduler_runs_canceled_org() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let (_, _, org) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, org, "canceled", "team", 0).await;
        due_scan(&ctx, org).await;
        tick(&ctx).await;
        assert_eq!(count(&ctx, QUEUED).await, 1);
        assert_eq!(count(&ctx, JOBS).await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn past_due_7_days_skipped_before_the_nightly() {
    serve_with(enforced, |req, ctx| async move {
        reset(&ctx).await;
        let (_, _, org) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, org, "past_due", "team", 7).await;
        due_scan(&ctx, org).await;
        tick(&ctx).await;
        assert_eq!(count(&ctx, SKIPPED).await, 1);
        assert_eq!(count(&ctx, JOBS).await, 0);
    })
    .await;
}

/// The seat lock serialises seat checks but, unlike the org row's `FOR UPDATE`, does not block
/// the FK `KEY SHARE` of a runs insert (`DisconnectConnection` -> `enqueue_sync` while a
/// verify holds it: no deadlock).
#[tokio::test]
#[serial]
async fn seat_lock_does_not_block_run_inserts() {
    use opsagent_brain::{actions::uow::UnitOfWork, adapters::db::Pg};
    use opsagent_core::run::RunKey;
    serve(|req, ctx| async move {
        let (_, _, org) = owner_org(&req, &prepare(&ctx)).await;
        let pg = Pg::new(ctx.db.clone());
        let holder = pg.begin().await.unwrap();
        holder.billing().lock_seats(org).await.unwrap();
        let insert = async {
            let tx = pg.begin().await.unwrap();
            let key = RunKey {
                organisation_id: Some(org),
                connection_id: None,
                job_type: "billing_sync".into(),
                scheduled_at: Utc::now(),
            };
            tx.ledger().create_run(key).await.unwrap();
            tx.commit().await.unwrap();
        };
        let ok = tokio::time::timeout(std::time::Duration::from_secs(3), insert).await;
        assert!(ok.is_ok(), "a runs insert waited on the seat lock");
        // A second seat check waits for the first.
        let second = async {
            let tx = pg.begin().await.unwrap();
            tx.billing().lock_seats(org).await.unwrap();
        };
        let waited = tokio::time::timeout(std::time::Duration::from_millis(300), second).await;
        assert!(waited.is_err(), "the seat lock did not serialise");
        holder.commit().await.unwrap();
    })
    .await;
}

/// Quantity syncs of one organisation queue on their own lock, apart from the seat lock.
#[tokio::test]
#[serial]
async fn quantity_lock_serialises_and_is_apart_from_seats() {
    use opsagent_brain::{actions::uow::UnitOfWork, adapters::db::Pg};
    serve(|req, ctx| async move {
        let (_, _, org) = owner_org(&req, &prepare(&ctx)).await;
        let pg = Pg::new(ctx.db.clone());
        let holder = pg.begin().await.unwrap();
        holder.billing().lock_quantity(org).await.unwrap();
        let seats = async {
            let tx = pg.begin().await.unwrap();
            tx.billing().lock_seats(org).await.unwrap();
        };
        let ok = tokio::time::timeout(std::time::Duration::from_secs(3), seats).await;
        assert!(ok.is_ok(), "the seat lock waited on the quantity lock");
        let second = async {
            let tx = pg.begin().await.unwrap();
            tx.billing().lock_quantity(org).await.unwrap();
        };
        let waited = tokio::time::timeout(std::time::Duration::from_millis(300), second).await;
        assert!(waited.is_err(), "the quantity lock did not serialise");
        holder.commit().await.unwrap();
        let tx = pg.begin().await.unwrap();
        let after = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tx.billing().lock_quantity(org),
        );
        assert!(
            after.await.is_ok(),
            "the quantity lock outlived its transaction"
        );
    })
    .await;
}
