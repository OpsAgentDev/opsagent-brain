use chrono::{DateTime, Duration, Utc};
use loco_rs::prelude::*;
use opsagent_brain::{
    models::ledger_storage::{stmt, PgStorage},
    tasks::scheduler_tick::{tick, Report},
};
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_ledger::Storage;
use sea_orm::{ConnectionTrait, Database};
use serial_test::serial;
use uuid::Uuid;

use crate::requests::support::*;

fn at(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

async fn count(ctx: &AppContext, sql: &str) -> i64 {
    ctx.db
        .query_one_raw(stmt(sql, vec![]))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "n")
        .unwrap()
}

/// Drops every schedule and run (and what hangs off runs, such as a first scan's rows).
async fn reset(ctx: &AppContext) {
    ctx.db
        .execute_raw(stmt("TRUNCATE schedules, runs CASCADE", vec![]))
        .await
        .unwrap();
}

/// An org-less schedule for a job type with no worker, so ticks only create run rows.
async fn schedule(ctx: &AppContext, cron: &str, tz: &str, due: DateTime<Utc>) {
    ctx.db
        .execute_raw(stmt(
            "INSERT INTO schedules (id, job_type, cron_local, timezone, next_due_at) \
             VALUES ($1, 'no_worker', $2, $3, $4)",
            vec![Uuid::new_v4().into(), cron.into(), tz.into(), due.into()],
        ))
        .await
        .unwrap();
}

async fn next_due(ctx: &AppContext) -> DateTime<Utc> {
    ctx.db
        .query_one_raw(stmt("SELECT next_due_at FROM schedules", vec![]))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "next_due_at")
        .unwrap()
}

async fn run_tick(ctx: &AppContext, now: DateTime<Utc>) -> Report {
    tick(ctx, now).await.unwrap().expect("lock acquired")
}

#[tokio::test]
#[serial]
async fn due_schedule_yields_one_run_after_two_ticks() {
    serve(|_req, ctx| async move {
        reset(&ctx).await;
        let now = at("2026-10-22T08:00:30Z");
        schedule(&ctx, "0 8 * * *", "UTC", at("2026-10-22T08:00:00Z")).await;
        run_tick(&ctx, now).await; // no_worker has no worker: run row only
        assert_eq!(count(&ctx, "SELECT count(*) n FROM runs").await, 1);
        assert_eq!(run_tick(&ctx, now).await, Report::default());
        // next_due_at forced back into the past: the run exists, so no second enqueue.
        ctx.db
            .execute_raw(stmt(
                "UPDATE schedules SET next_due_at = '2026-10-22T08:00:00Z'",
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(run_tick(&ctx, now).await, Report::default());
        assert_eq!(count(&ctx, "SELECT count(*) n FROM runs").await, 1);
        assert_eq!(next_due(&ctx).await, at("2026-10-23T08:00:00Z"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn dst_gap_lands_on_next_valid_minute_and_overlap_runs_once() {
    serve(|_req, ctx| async move {
        reset(&ctx).await;
        // 02:30 does not exist on 2026-03-08 in New York: 03:30 EDT.
        schedule(
            &ctx,
            "30 2 * * *",
            "America/New_York",
            at("2026-03-07T07:30:00Z"),
        )
        .await;
        run_tick(&ctx, at("2026-03-07T07:31:00Z")).await;
        assert_eq!(next_due(&ctx).await, at("2026-03-08T07:30:00Z"));
        run_tick(&ctx, at("2026-03-08T07:31:00Z")).await;
        assert_eq!(next_due(&ctx).await, at("2026-03-09T06:30:00Z"));

        reset(&ctx).await;
        // 01:30 happens twice on 2026-11-01: only the first (EDT) fires.
        schedule(
            &ctx,
            "30 1 * * *",
            "America/New_York",
            at("2026-10-31T05:30:00Z"),
        )
        .await;
        run_tick(&ctx, at("2026-10-31T05:31:00Z")).await;
        assert_eq!(next_due(&ctx).await, at("2026-11-01T05:30:00Z"));
        run_tick(&ctx, at("2026-11-01T05:31:00Z")).await;
        assert_eq!(next_due(&ctx).await, at("2026-11-02T06:30:00Z"));
        // The repeated 01:30 EST (06:30Z) is not due again.
        assert_eq!(
            run_tick(&ctx, at("2026-11-01T06:31:00Z")).await,
            Report::default()
        );
        assert_eq!(count(&ctx, "SELECT count(*) n FROM runs").await, 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn second_lock_holder_does_not_tick() {
    serve(|_req, ctx| async move {
        reset(&ctx).await;
        schedule(&ctx, "0 8 * * *", "UTC", at("2026-10-22T08:00:00Z")).await;
        let other = Database::connect(ctx.config.database.uri.clone())
            .await
            .unwrap();
        // A pooled connection could differ between statements; keep the lock on a single one.
        let held = other.begin().await.unwrap();
        held.execute_raw(stmt(
            "SELECT pg_advisory_xact_lock(hashtext('opsagent-scheduler'))",
            vec![],
        ))
        .await
        .unwrap();
        let now = at("2026-10-22T08:01:00Z");
        assert_eq!(tick(&ctx, now).await.unwrap(), None);
        assert_eq!(count(&ctx, "SELECT count(*) n FROM runs").await, 0);
        held.commit().await.unwrap();
        run_tick(&ctx, now).await;
        assert_eq!(count(&ctx, "SELECT count(*) n FROM runs").await, 1);
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
        // Exactly one real enqueue (the inline worker finishes the run), then nothing is due.
        assert_eq!(run_tick(&ctx, now).await.retries_run, 1);
        assert_eq!(run_tick(&ctx, now).await, Report::default());
        let q = "SELECT count(*) n FROM runs WHERE next_attempt_at IS NULL AND status = 'done'";
        assert_eq!(count(&ctx, q).await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn schedule_three_days_overdue_catches_up_once() {
    serve(|_req, ctx| async move {
        reset(&ctx).await;
        let now = at("2026-10-22T09:00:00Z");
        schedule(&ctx, "0 8 * * *", "UTC", at("2026-10-19T08:00:00Z")).await;
        run_tick(&ctx, now).await;
        assert_eq!(run_tick(&ctx, now).await, Report::default());
        assert_eq!(count(&ctx, "SELECT count(*) n FROM runs").await, 1);
        assert_eq!(next_due(&ctx).await, at("2026-10-23T08:00:00Z"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn connecting_creates_default_schedules_once() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        // full_scan, verify, deliver_briefing, deliver_weekly; plus the organisation's summary.
        let q = format!("SELECT count(*) n FROM schedules WHERE connection_id = '{id}'");
        let org_q = "SELECT count(*) n FROM schedules WHERE connection_id IS NULL";
        assert_eq!(count(&ctx, &q).await, 4);
        assert_eq!(count(&ctx, org_q).await, 1);
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        assert_eq!(count(&ctx, &q).await, 4);
        assert_eq!(count(&ctx, org_q).await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn tick_gives_connected_connections_without_delivery_schedules_their_defaults_once() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        // Connected before delivery schedules existed: only its scan schedule is there.
        let (_, _, id) = connected(&req, &ctx, "old@example.com", "clean").await;
        conn_schedule(
            &ctx,
            &id.to_string(),
            "full_scan",
            Utc::now() + Duration::days(1),
        )
        .await;
        let pending = Uuid::new_v4();
        ctx.db
            .execute_raw(stmt(
                "INSERT INTO connections (id, organisation_id, provider, status) \
                 SELECT $1, organisation_id, 'aws', 'pending' FROM connections WHERE id = $2",
                vec![pending.into(), id.into()],
            ))
            .await
            .unwrap();
        let q = format!("SELECT count(*) n FROM schedules WHERE connection_id = '{id}'");
        let jobs = format!(
            "SELECT count(*) n FROM schedules WHERE connection_id = '{id}' \
             AND job_type IN ('deliver_briefing','deliver_weekly')"
        );
        let org_q = "SELECT count(*) n FROM schedules WHERE connection_id IS NULL";
        let pending_q =
            format!("SELECT count(*) n FROM schedules WHERE connection_id = '{pending}'");
        for _ in 0..2 {
            run_tick(&ctx, Utc::now()).await;
            assert_eq!(count(&ctx, &q).await, 4);
            assert_eq!(count(&ctx, &jobs).await, 2);
            assert_eq!(count(&ctx, org_q).await, 1);
            assert_eq!(
                count(&ctx, &pending_q).await,
                0,
                "not verified: no schedules"
            );
        }
    })
    .await;
}

/// Inserts a schedule for a real connection and returns nothing; `job` has a registered worker.
async fn conn_schedule(ctx: &AppContext, id: &str, job: &str, due: DateTime<Utc>) {
    ctx.db
        .execute_raw(stmt(
            &format!(
                "INSERT INTO schedules (id, organisation_id, connection_id, job_type, cron_local, timezone, next_due_at) \
                 SELECT gen_random_uuid(), organisation_id, id, '{job}', '0 2 * * *', 'UTC', $1 \
                 FROM connections WHERE id = '{id}'"
            ),
            vec![due.into()],
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[serial]
async fn due_full_scan_enqueues_the_real_worker_once() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        reset(&ctx).await; // drop the default schedules and the verify run
        let due = at("2026-10-22T02:00:00Z");
        let now = at("2026-10-22T02:00:30Z");
        conn_schedule(&ctx, &id, "full_scan", due).await;

        // Foreground worker mode: the enqueue runs the worker inline.
        assert_eq!(run_tick(&ctx, now).await.schedules_run, 1);
        let q = "SELECT count(*) n FROM runs WHERE job_type = 'full_scan' AND status = 'done' \
                 AND next_attempt_at IS NULL";
        assert_eq!(count(&ctx, q).await, 1);

        // Same slot again (next_due_at forced back): the run exists, so nothing is enqueued.
        // (The tick also backfilled the connection's delivery schedules, not yet due.)
        let scan_only = "UPDATE schedules SET next_due_at = $1 WHERE job_type = 'full_scan'";
        ctx.db
            .execute_raw(stmt(scan_only, vec![due.into()]))
            .await
            .unwrap();
        assert_eq!(run_tick(&ctx, now).await, Report::default());
        assert_eq!(count(&ctx, "SELECT count(*) n FROM runs").await, 1);
        let next: DateTime<Utc> = ctx
            .db
            .query_one_raw(stmt(
                "SELECT next_due_at FROM schedules WHERE job_type = 'full_scan'",
                vec![],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "next_due_at")
            .unwrap();
        assert_eq!(next, at("2026-10-23T02:00:00Z"));
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
        // Simulates a crash after due_schedule committed: run queued, outbox marker still set.
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
        let q = "SELECT count(*) n FROM runs WHERE status = 'done'";
        assert_eq!(count(&ctx, q).await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn worker_retry_written_during_inline_enqueue_survives_the_marker_clear() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let (_, _, id) = fake_connection(&req, &mail, "o@example.com", "Org", "denied").await;
        // Previously connected, role now denied: the verify worker parks a retry.
        ctx.db
            .execute_raw(stmt(
                &format!(
                    "UPDATE connections SET status = 'connected', external_account_id = 'denied' WHERE id = '{id}'"
                ),
                vec![],
            ))
            .await
            .unwrap();
        let now = Utc::now();
        conn_schedule(&ctx, &id, "verify", now - Duration::minutes(1)).await;

        // Foreground mode: the worker runs inside the enqueue, before the marker is cleared.
        assert_eq!(run_tick(&ctx, now).await.schedules_run, 1);
        let r = ctx
            .db
            .query_one_raw(stmt(
                "SELECT attempts, status, next_attempt_at FROM runs WHERE job_type = 'verify'",
                vec![],
            ))
            .await
            .unwrap()
            .unwrap();
        let next: DateTime<Utc> = r.try_get("", "next_attempt_at").unwrap();
        assert_eq!(r.try_get::<i32>("", "attempts").unwrap(), 1);
        assert_eq!(r.try_get::<String>("", "status").unwrap(), "queued");
        assert!(next > now, "retry time {next} was erased");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn api_run_whose_enqueue_failed_is_sent_by_the_next_tick() {
    serve(|req, ctx| async move {
        let (_, _, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        reset(&ctx).await;
        // A queue that refuses work: the run must still be recorded with its outbox marker.
        let mut broken = ctx.clone();
        broken.config.workers.mode = loco_rs::config::WorkerMode::BackgroundQueue;
        broken.queue_provider = None;
        let c = opsagent_brain::models::_entities::connections::Entity::find_by_id(conn)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        let now = Utc::now();
        let out = opsagent_brain::services::manual_scan::request(&broken, &c, Uuid::new_v4(), now)
            .await
            .unwrap();
        let q = format!(
            "SELECT count(*) n FROM runs WHERE id = '{}' AND status = 'queued' AND next_attempt_at IS NOT NULL",
            out.run.id
        );
        assert_eq!(count(&ctx, &q).await, 1);
        assert_eq!(run_tick(&ctx, now).await.retries_run, 1);
        let q = format!(
            "SELECT count(*) n FROM runs WHERE id = '{}' AND status = 'done' AND next_attempt_at IS NULL",
            out.run.id
        );
        assert_eq!(count(&ctx, &q).await, 1);
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
