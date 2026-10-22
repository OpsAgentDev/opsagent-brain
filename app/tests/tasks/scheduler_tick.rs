use chrono::{DateTime, Duration, Utc};
use loco_rs::{prelude::*, testing::prelude::request_with_config};
use opsagent_brain::{
    app::App,
    models::ledger_storage::{stmt, PgStorage},
    tasks::scheduler_tick::{tick, Report},
};
use opsagent_core::run::RunKey;
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

async fn reset(ctx: &AppContext) {
    for t in ["schedules", "runs"] {
        ctx.db
            .execute_raw(stmt(&format!("DELETE FROM {t}"), vec![]))
            .await
            .unwrap();
    }
}

/// An org-less schedule for a job type with no worker, so ticks only create run rows.
async fn schedule(ctx: &AppContext, cron: &str, tz: &str, due: DateTime<Utc>) {
    ctx.db
        .execute_raw(stmt(
            "INSERT INTO schedules (id, job_type, cron_local, timezone, next_due_at) \
             VALUES ($1, 'deliver_briefing', $2, $3, $4)",
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
    request_with_config::<App, _, _>(cookie_config(), |_req, ctx| async move {
        reset(&ctx).await;
        let now = at("2026-10-22T08:00:30Z");
        schedule(&ctx, "0 8 * * *", "UTC", at("2026-10-22T08:00:00Z")).await;
        run_tick(&ctx, now).await; // deliver_briefing has no worker: run row only
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
    request_with_config::<App, _, _>(cookie_config(), |_req, ctx| async move {
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
    request_with_config::<App, _, _>(cookie_config(), |_req, ctx| async move {
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
    request_with_config::<App, _, _>(cookie_config(), |_req, ctx| async move {
        reset(&ctx).await;
        let now = at("2026-10-22T10:00:00Z");
        let storage = PgStorage::new(ctx.db.clone());
        let run = storage
            .create_run(RunKey {
                organisation_id: None,
                connection_id: None,
                job_type: "deliver_briefing".into(),
                scheduled_at: now - Duration::hours(2),
            })
            .await
            .unwrap();
        storage
            .schedule_retry(run.run.id, 1, now - Duration::minutes(1))
            .await
            .unwrap();
        run_tick(&ctx, now).await;
        let q = "SELECT count(*) n FROM runs WHERE next_attempt_at IS NULL AND status = 'queued'";
        assert_eq!(count(&ctx, q).await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn schedule_three_days_overdue_catches_up_once() {
    request_with_config::<App, _, _>(cookie_config(), |_req, ctx| async move {
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
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        let q = format!("SELECT count(*) n FROM schedules WHERE connection_id = '{id}'");
        assert_eq!(count(&ctx, &q).await, 3);
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        assert_eq!(count(&ctx, &q).await, 3);
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
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
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
        ctx.db
            .execute_raw(stmt(
                "UPDATE schedules SET next_due_at = $1",
                vec![due.into()],
            ))
            .await
            .unwrap();
        assert_eq!(run_tick(&ctx, now).await, Report::default());
        assert_eq!(count(&ctx, "SELECT count(*) n FROM runs").await, 1);
        assert_eq!(next_due(&ctx).await, at("2026-10-23T02:00:00Z"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn run_written_but_not_enqueued_is_picked_up_by_the_next_tick() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
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
