//! The nightly operator notice over real `jobs` and `runs` rows.
use chrono::{DateTime, Duration, DurationRound, Utc};
use opsagent_brain::adapters::db::ledger_storage::PgStorage;
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_ledger::{JobKind, RunChunkedOptions, Storage};
use serial_test::serial;
use uuid::Uuid;

use super::deliver_briefing::sql;
use crate::requests::support::*;

/// The night's run, with its job on the queue.
async fn night(ctx: &TestApp, at: DateTime<Utc>) -> Uuid {
    let key = RunKey {
        organisation_id: None,
        connection_id: None,
        job_type: JobKind::OperatorNotice.as_str().into(),
        scheduled_at: at,
    };
    PgStorage::new(ctx.db.clone())
        .create_run(key)
        .await
        .unwrap()
        .run
        .id
}

async fn failed_run(ctx: &TestApp, job: &str, finished: DateTime<Utc>) {
    sql(
        ctx,
        "INSERT INTO runs (id, job_type, scheduled_at, status, finished_at) \
         VALUES ($1, $2, $3, 'failed', $3)",
        vec![Uuid::new_v4().into(), job.into(), finished.into()],
    )
    .await;
}

async fn dead_job(ctx: &TestApp, kind: &str, locked: DateTime<Utc>) {
    sql(
        ctx,
        "INSERT INTO jobs (kind, args, run_at, attempts, max_attempts, locked_at) \
         VALUES ($1, '{}', now(), 5, 5, $2)",
        vec![kind.into(), locked.into()],
    )
    .await;
}

fn slot(hours_ago: i64) -> DateTime<Utc> {
    (Utc::now() - Duration::hours(hours_ago))
        .duration_trunc(Duration::seconds(1))
        .unwrap()
}

#[tokio::test]
#[serial]
async fn silent_when_healthy_counts_only_the_last_day_and_mails_once() {
    serve(|_req, ctx| async move {
        let mail = prepare(&ctx);
        // Old failures are not this night's news.
        let now = slot(0);
        failed_run(&ctx, "full_scan", now - Duration::hours(30)).await;
        dead_job(&ctx, "verify", now - Duration::hours(30)).await;
        let quiet = night(&ctx, now).await;
        perform(&ctx, JobKind::OperatorNotice, quiet).await.unwrap();
        assert!(mail.sent().is_empty());

        failed_run(&ctx, "billing_sync", now - Duration::hours(1)).await;
        failed_run(&ctx, "billing_sync", now - Duration::hours(2)).await;
        dead_job(&ctx, "full_scan", now - Duration::hours(1)).await;
        let run = night(&ctx, now + Duration::minutes(1)).await;
        perform(&ctx, JobKind::OperatorNotice, run).await.unwrap();
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "info@opsagent.dev");
        assert!(sent[0].text.contains("Failed runs: 2 (billing_sync 2)"), "{}", sent[0].text);
        assert!(sent[0].text.contains("Dead jobs: 1 (full_scan 1)"), "{}", sent[0].text);

        // A crash after the mail but before the checkpoint: the ledger stops a second one.
        sql(
            &ctx,
            r#"UPDATE runs SET status = 'queued', checkpoint = '{"chunks_done": [], "cursor": null, "stats": {}}' WHERE id = $1"#,
            vec![run.into()],
        )
        .await;
        let status = actions(&ctx)
            .unwrap()
            .runs
            .operator_notice
            .run(run, RunChunkedOptions::default())
            .await
            .unwrap();
        assert_eq!(status, RunStatus::Done);
        assert_eq!(mail.sent().len(), 1);
    })
    .await;
}
