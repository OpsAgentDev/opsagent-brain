use chrono::{DateTime, Duration, Utc};
use sea_orm::TransactionTrait;

use opsagent_brain::{actions::runs::TickReport as Report, adapters::db::ledger_storage::stmt};
use sea_orm::{ConnectionTrait, Database};
use serial_test::serial;
use uuid::Uuid;

use crate::requests::support::*;

pub(super) fn at(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

pub(super) async fn count(ctx: &TestApp, sql: &str) -> i64 {
    ctx.db
        .query_one_raw(stmt(sql, vec![]))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "n")
        .unwrap()
}

/// Drops every schedule and run (and what hangs off runs, such as a first scan's rows).
pub(super) async fn reset(ctx: &TestApp) {
    ctx.db
        .execute_raw(stmt("TRUNCATE schedules, runs CASCADE", vec![]))
        .await
        .unwrap();
}

/// An org-less schedule for a job type with no worker, so ticks only create run rows.
async fn schedule(ctx: &TestApp, cron: &str, tz: &str, due: DateTime<Utc>) {
    ctx.db
        .execute_raw(stmt(
            "INSERT INTO schedules (id, job_type, cron_local, timezone, next_due_at) \
             VALUES ($1, 'no_worker', $2, $3, $4)",
            vec![Uuid::new_v4().into(), cron.into(), tz.into(), due.into()],
        ))
        .await
        .unwrap();
}

async fn next_due(ctx: &TestApp) -> DateTime<Utc> {
    ctx.db
        .query_one_raw(stmt("SELECT next_due_at FROM schedules", vec![]))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "next_due_at")
        .unwrap()
}

/// One tick of the installed `SchedulerTick` at `now`; `None` when the lock is held elsewhere.
pub(super) async fn tick(
    ctx: &TestApp,
    now: DateTime<Utc>,
) -> opsagent_brain::error::AppResult<Option<Report>> {
    let actions = actions(ctx).unwrap();
    let report = actions.runs.scheduler_tick.run(now).await;
    // A worker picks up what the tick enqueued.
    ctx.drain_jobs().await;
    report
}

pub(super) async fn run_tick(ctx: &TestApp, now: DateTime<Utc>) -> Report {
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
        let other = Database::connect(ctx.state.config.database_url.clone())
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
        // full_scan, watch_scan, verify, deliver_briefing, deliver_weekly; plus the
        // organisation's summary.
        let q = format!("SELECT count(*) n FROM schedules WHERE connection_id = '{id}'");
        let org_q = "SELECT count(*) n FROM schedules WHERE connection_id IS NULL";
        assert_eq!(count(&ctx, &q).await, 5);
        assert_eq!(count(&ctx, org_q).await, 1);
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        assert_eq!(count(&ctx, &q).await, 5);
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
            assert_eq!(count(&ctx, &q).await, 5);
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

#[tokio::test]
#[serial]
async fn schedule_backfilled_for_existing_connection() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        // Connected before watch scans existed: every other schedule is there.
        let (_, _, id) = connected(&req, &ctx, "old@example.com", "clean").await;
        let later = Utc::now() + Duration::days(1);
        for job in ["full_scan", "verify", "deliver_briefing", "deliver_weekly"] {
            conn_schedule(&ctx, &id.to_string(), job, later).await;
        }
        let watch = format!(
            "SELECT count(*) n FROM schedules WHERE connection_id = '{id}' \
             AND job_type = 'watch_scan' AND cron_local = '*/15 * * * *' AND enabled"
        );
        let all = format!("SELECT count(*) n FROM schedules WHERE connection_id = '{id}'");
        for _ in 0..2 {
            run_tick(&ctx, Utc::now()).await;
            assert_eq!(count(&ctx, &watch).await, 1);
            assert_eq!(count(&ctx, &all).await, 5);
        }
    })
    .await;
}

/// Inserts a schedule for a real connection and returns nothing; `job` has a registered worker.
pub(super) async fn conn_schedule(ctx: &TestApp, id: &str, job: &str, due: DateTime<Utc>) {
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

        // The tick's drain runs the worker.
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
        let scans = "SELECT count(*) n FROM runs WHERE job_type = 'full_scan'";
        assert_eq!(count(&ctx, scans).await, 1);
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
