//! The retry pass and same-transaction enqueue: a run and its job commit together, a
//! duplicate key or a second requeue adds no job, and parked runs get their job back.
use chrono::{Duration, Utc};
use opsagent_brain::{
    actions::{runs::RunDispatcher, uow::UnitOfWork},
    adapters::db::{
        ledger_storage::{stmt, PgStorage},
        Pg,
    },
};
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_ledger::Storage;
use sea_orm::{ConnectionTrait, EntityTrait};
use serial_test::serial;
use std::sync::Arc;
use uuid::Uuid;

use super::scheduler_tick::{at, conn_schedule, count, reset, run_tick};
use crate::requests::support::*;
use opsagent_brain::actions::runs::TickReport as Report;

fn dispatcher(ctx: &TestApp) -> (Arc<dyn UnitOfWork>, RunDispatcher) {
    let uow: Arc<dyn UnitOfWork> = Arc::new(Pg::new(ctx.db.clone()));
    (uow.clone(), RunDispatcher::new(uow))
}

/// An org-less `full_scan` key; nothing in these tests drains its job.
fn key(scheduled_at: chrono::DateTime<Utc>) -> RunKey {
    RunKey {
        organisation_id: None,
        connection_id: None,
        job_type: "full_scan".into(),
        scheduled_at,
    }
}

const RUNS: &str = "SELECT count(*) n FROM runs";
const JOBS: &str = "SELECT count(*) n FROM jobs";

#[tokio::test]
#[serial]
async fn new_run_and_job_commit_together() {
    serve(|_req, ctx| async move {
        let (uow, d) = dispatcher(&ctx);
        let now = Utc::now();
        // A later write in the same transaction fails: the caller drops it, so neither row exists.
        let tx = uow.begin().await.unwrap();
        assert!(
            d.create_and_enqueue(&*tx, key(now), now)
                .await
                .unwrap()
                .created
        );
        let later = tx
            .ledger()
            .set_status(Uuid::new_v4(), 0, RunStatus::Done, None)
            .await;
        assert!(later.is_err());
        drop(tx);
        assert_eq!((count(&ctx, RUNS).await, count(&ctx, JOBS).await), (0, 0));
        // Committed: both.
        let tx = uow.begin().await.unwrap();
        d.create_and_enqueue(&*tx, key(now), now).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!((count(&ctx, RUNS).await, count(&ctx, JOBS).await), (1, 1));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn duplicate_run_key_creates_no_second_job() {
    serve(|_req, ctx| async move {
        let (_, d) = dispatcher(&ctx);
        let now = Utc::now();
        let first = d.enqueue(key(now), now).await.unwrap();
        assert!(first.created);
        assert!(!d.enqueue(key(now), now).await.unwrap().created);
        assert_eq!(count(&ctx, JOBS).await, 1);
        // Even once the first job is gone (done), the duplicate key adds none.
        ctx.db
            .execute_raw(stmt("DELETE FROM jobs", vec![]))
            .await
            .unwrap();
        assert!(!d.enqueue(key(now), now).await.unwrap().created);
        assert_eq!((count(&ctx, RUNS).await, count(&ctx, JOBS).await), (1, 0));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn requeue_skips_run_that_already_has_a_job() {
    serve(|_req, ctx| async move {
        let (_, d) = dispatcher(&ctx);
        let now = at("2026-10-22T10:00:00Z"); // whole seconds: the marker compares exactly
        let run = d.enqueue(key(now), now).await.unwrap().run.id;
        PgStorage::new(ctx.db.clone())
            .schedule_retry(run, 1, now)
            .await
            .unwrap();
        assert!(d.requeue(run, "full_scan", now).await.unwrap());
        assert_eq!(count(&ctx, JOBS).await, 1);
        // The marker is cleared in the same transaction: nothing is due any more.
        let q = "SELECT count(*) n FROM runs WHERE next_attempt_at IS NULL";
        assert_eq!(count(&ctx, q).await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn scheduled_run_is_done_after_tick_and_drain() {
    serve(|req, ctx| async move {
        let (_, _, id) = connected(&req, &ctx, "o@example.com", "clean").await;
        reset(&ctx).await;
        let now = at("2026-10-22T02:00:30Z");
        conn_schedule(
            &ctx,
            &id.to_string(),
            "full_scan",
            at("2026-10-22T02:00:00Z"),
        )
        .await;
        let tick = &actions(&ctx).unwrap().runs.scheduler_tick;
        let report = tick.run(now).await.unwrap().expect("lock acquired");
        assert_eq!(report.schedules_run, 1);
        // The tick committed the run with its job; nothing ran yet.
        assert_eq!(count(&ctx, JOBS).await, 1);
        assert_eq!(
            count(&ctx, "SELECT count(*) n FROM runs WHERE status = 'queued'").await,
            1
        );
        // The scan, then the deliver_alert its finalize enqueued.
        assert_eq!(ctx.drain_jobs().await, 2);
        assert_eq!(
            count(&ctx, "SELECT count(*) n FROM runs WHERE status = 'done'").await,
            2
        );
        assert_eq!(count(&ctx, JOBS).await, 0);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn parked_retry_is_requeued_by_the_next_tick() {
    serve(|req, ctx| async move {
        let (_, _, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        reset(&ctx).await;
        let m = opsagent_brain::models::_entities::connections::Entity::find_by_id(conn)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        let now = Utc::now();
        let storage = PgStorage::new(ctx.db.clone());
        let run = storage
            .create_run(RunKey {
                organisation_id: Some(m.organisation_id),
                connection_id: Some(conn),
                job_type: "full_scan".into(),
                scheduled_at: now - Duration::hours(2),
            })
            .await
            .unwrap()
            .run
            .id;
        storage
            .schedule_retry(run, 1, now - Duration::minutes(1))
            .await
            .unwrap();
        let tick = &actions(&ctx).unwrap().runs.scheduler_tick;
        assert_eq!(tick.run(now).await.unwrap().unwrap().retries_run, 1);
        assert_eq!(tick.run(now).await.unwrap().unwrap(), Report::default());
        let q = format!("SELECT count(*) n FROM jobs WHERE run_id = '{run}'");
        assert_eq!(count(&ctx, &q).await, 1);
        assert_eq!(ctx.drain_jobs().await, 2, "the scan and its deliver_alert");
        let q = format!(
            "SELECT count(*) n FROM runs WHERE id = '{run}' AND status = 'done' AND next_attempt_at IS NULL"
        );
        assert_eq!(count(&ctx, &q).await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn queued_run_with_due_next_attempt_is_reenqueued_once() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        reset(&ctx).await;
        let now = at("2026-10-22T10:00:00Z");
        let storage = PgStorage::new(ctx.db.clone());
        let conn_id: Uuid = id.parse().unwrap();
        let org_id: Uuid = ctx
            .db
            .query_one_raw(stmt(
                &format!("SELECT organisation_id FROM connections WHERE id = '{id}'"),
                vec![],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "organisation_id")
            .unwrap();
        let run = storage
            .create_run(RunKey {
                organisation_id: Some(org_id),
                connection_id: Some(conn_id),
                job_type: "full_scan".into(),
                scheduled_at: now - Duration::hours(2),
            })
            .await
            .unwrap();
        storage
            .schedule_retry(run.run.id, 1, now - Duration::minutes(1))
            .await
            .unwrap();
        // Exactly one real enqueue (the drained worker finishes the run), then nothing is due.
        assert_eq!(run_tick(&ctx, now).await.retries_run, 1);
        assert_eq!(run_tick(&ctx, now).await, Report::default());
        let q = "SELECT count(*) n FROM runs WHERE next_attempt_at IS NULL AND status = 'done' \
                 AND job_type = 'full_scan'";
        assert_eq!(count(&ctx, q).await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn run_written_but_not_enqueued_is_picked_up_by_the_next_tick() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        reset(&ctx).await;
        let now = at("2026-10-22T02:00:30Z");
        // A run committed with a marker and no job (an outbox marker from before same-transaction
        // enqueue, still in the database at deploy).
        conn_schedule(&ctx, &id, "full_scan", at("2026-10-22T02:00:00Z")).await;
        ctx.db
            .execute_raw(stmt(
                "INSERT INTO runs (id, organisation_id, connection_id, job_type, scheduled_at, next_attempt_at, checkpoint) \
                 SELECT gen_random_uuid(), organisation_id, connection_id, job_type, next_due_at, $1, jsonb_build_object('chunks_done', '[]'::jsonb, 'cursor', 'null'::jsonb, 'stats', '{}'::jsonb) FROM schedules",
                vec![now.into()],
            ))
            .await
            .unwrap();
        ctx.db
            .execute_raw(stmt(
                "UPDATE schedules SET next_due_at = '2026-10-23T02:00:00Z'",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(run_tick(&ctx, now).await.retries_run, 1);
        let q = "SELECT count(*) n FROM runs WHERE status = 'done' AND job_type = 'full_scan'";
        assert_eq!(count(&ctx, q).await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn retry_for_a_deleted_org_is_skipped_not_enqueued() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "gone@example.com").await;
        let org = create_org(&req, &t, "Gone").await;
        let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
        let now = at("2026-10-22T10:00:00Z");
        let storage = PgStorage::new(ctx.db.clone());
        let run = storage
            .create_run(RunKey {
                organisation_id: Some(org_id),
                connection_id: None,
                job_type: "full_scan".into(),
                scheduled_at: now - Duration::hours(2),
            })
            .await
            .unwrap()
            .run;
        storage
            .schedule_retry(run.id, 1, now - Duration::minutes(1))
            .await
            .unwrap();
        ctx.db
            .execute_raw(stmt(
                "UPDATE organisations SET deleted_at = now() WHERE id = $1",
                vec![org_id.into()],
            ))
            .await
            .unwrap();
        // A worker took the lease but has not written `running` yet.
        let redis = redis_of(&ctx);
        let lease = opsagent_ledger::lease::acquire(
            &storage,
            &redis,
            run.id,
            "slow-worker",
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(run_tick(&ctx, now).await, Report::default());
        let row = storage.load_run(run.id).await.unwrap();
        assert_eq!(row.status, RunStatus::Skipped);
        assert_eq!(row.partial_reason.as_deref(), Some("org_deleted"));
        // The skip bumped the fence: the worker cannot revive the run.
        let res = storage
            .set_status(run.id, lease.fence, RunStatus::Running, None)
            .await;
        assert!(matches!(res, Err(opsagent_ledger::LedgerError::StaleFence)));
        opsagent_ledger::lease::release(&redis, &lease).await;
    })
    .await;
}
