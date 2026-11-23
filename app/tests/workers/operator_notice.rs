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
async fn quiet_night_mails_counts_only_the_last_day_and_mails_once() {
    serve(|_req, ctx| async move {
        let mail = prepare(&ctx);
        // Old failures are not this night's news.
        let now = slot(0);
        failed_run(&ctx, "full_scan", now - Duration::hours(30)).await;
        dead_job(&ctx, "verify", now - Duration::hours(30)).await;
        sql(
            &ctx,
            "INSERT INTO waitlist_entries (id, email, created_at) VALUES ($1, 'w@example.com', $2)",
            vec![Uuid::new_v4().into(), (now - Duration::hours(1)).into()],
        )
        .await;
        let quiet = night(&ctx, now).await;
        perform(&ctx, JobKind::OperatorNotice, quiet).await.unwrap();
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].subject, "OpsAgent: nightly notice, nothing failed");
        assert!(sent[0].text.contains("Waitlist: 1."), "{}", sent[0].text);
        assert!(sent[0].text.contains("Dead jobs: 0 ()"), "{}", sent[0].text);

        failed_run(&ctx, "billing_sync", now - Duration::hours(1)).await;
        failed_run(&ctx, "billing_sync", now - Duration::hours(2)).await;
        dead_job(&ctx, "full_scan", now - Duration::hours(1)).await;
        let run = night(&ctx, now + Duration::minutes(1)).await;
        perform(&ctx, JobKind::OperatorNotice, run).await.unwrap();
        let sent = mail.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].to, "info@opsagent.dev");
        assert_eq!(sent[1].subject, "OpsAgent: failures in the last 24 hours");
        assert!(sent[1].text.contains("Failed runs: 2 (billing_sync 2)"), "{}", sent[1].text);
        assert!(sent[1].text.contains("Dead jobs: 1 (full_scan 1)"), "{}", sent[1].text);

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
        assert_eq!(mail.sent().len(), 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn reports_a_refused_mail_alone_and_not_79_sent() {
    serve(|_req, ctx| async move {
        let mail = prepare(&ctx);
        let now = slot(0);
        let count = |outcome: &'static str, n: i64| {
            let key = format!("mail:{outcome}:{}", now.date_naive());
            let redis = ctx.redis();
            async move {
                let mut c = redis.get_multiplexed_async_connection().await.unwrap();
                let _: i64 = opsagent_ledger::redis::cmd("INCRBY")
                    .arg(key)
                    .arg(n)
                    .query_async(&mut c)
                    .await
                    .unwrap();
            }
        };
        count("sent", 79).await;
        let quiet = night(&ctx, now).await;
        perform(&ctx, JobKind::OperatorNotice, quiet).await.unwrap();
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert!(!sent[0].text.contains("Mail on"), "{}", sent[0].text);

        count("refused", 1).await;
        let run = night(&ctx, now + Duration::minutes(1)).await;
        perform(&ctx, JobKind::OperatorNotice, run).await.unwrap();
        let sent = &mail.sent()[1..];
        assert_eq!(sent.len(), 1);
        let line = format!(
            "Mail on {}: 79 sent, 1 not sent. The Resend plan stops at 100 a day.",
            now.date_naive()
        );
        assert!(sent[0].text.contains(&line), "{}", sent[0].text);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn mails_one_line_per_counted_failure() {
    serve(|_req, ctx| async move {
        let mail = prepare(&ctx);
        let now = slot(0);
        let day = now.date_naive();
        let mut c = ctx
            .redis()
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        for (kind, n) in [
            ("billing:failed", 2),
            ("payment:unmatched", 1),
            ("check:failed", 3),
            ("watch:partial", 4),
        ] {
            let _: i64 = opsagent_ledger::redis::cmd("INCRBY")
                .arg(format!("{kind}:{day}"))
                .arg(n)
                .query_async(&mut c)
                .await
                .unwrap();
        }
        let run = night(&ctx, now).await;
        perform(&ctx, JobKind::OperatorNotice, run).await.unwrap();
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        let lines = format!(
            "Billing on {day}: 2 organisations could not be processed.\n\
             Payments on {day}: 1 paid events matched no organisation or request.\n\
             Checks on {day}: 3 checks panicked or could not read their input.\n\
             Watch scans on {day}: 4 hit the time cap before running their checks.\n"
        );
        assert!(sent[0].text.contains(&lines), "{}", sent[0].text);
    })
    .await;
}

/// An organisation owned by `email`, created at `at`, with `source` as its `utm_source`.
async fn org(ctx: &TestApp, email: &str, source: Option<&str>, at: DateTime<Utc>) -> Uuid {
    let (org, user) = (Uuid::new_v4(), Uuid::new_v4());
    let src = source.map(|s| serde_json::json!({ "utm_source": s }));
    sql(
        ctx,
        "INSERT INTO organisations (id, name, slug, signup_source, created_at) VALUES ($1, 'o', $1::text, $2, $3)",
        vec![org.into(), src.into(), at.into()],
    )
    .await;
    sql(
        ctx,
        "INSERT INTO users (id, email) VALUES ($1, $2)",
        vec![user.into(), email.into()],
    )
    .await;
    sql(
        ctx,
        "INSERT INTO members (id, organisation_id, user_id, role) VALUES ($1, $2, $3, 'owner')",
        vec![Uuid::new_v4().into(), org.into(), user.into()],
    )
    .await;
    org
}

fn week(
    ctx: &TestApp,
    until: DateTime<Utc>,
) -> impl std::future::Future<Output = opsagent_brain::actions::runs::WeekCounts> {
    use opsagent_brain::{actions::runs::FailureCounts, adapters::db::PgFailures};
    let pg = PgFailures(ctx.db.clone());
    async move { pg.week_until(until).await.unwrap() }
}

#[tokio::test]
#[serial]
async fn week_counts_groups_by_source() {
    serve(|_req, ctx| async move {
        let now = slot(0);
        let day = now - Duration::days(2);
        org(&ctx, "a@example.com", Some("hn"), day).await;
        org(&ctx, "b@example.com", Some("hn"), day).await;
        org(&ctx, "c@example.com", None, day).await;
        org(&ctx, "old@example.com", Some("hn"), now - Duration::days(8)).await;
        let w = week(&ctx, now).await;
        assert_eq!(
            w.new_orgs_by_source,
            [("hn".to_string(), 2), ("unknown".to_string(), 1)]
        );
        assert_eq!(
            w.line(),
            "Week: new orgs by source hn 2, unknown 1 | trials started 0 | activated 0 | paying now 0 | MRR $0"
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn week_counts_excludes_internal() {
    serve(|_req, ctx| async move {
        let now = slot(0);
        let day = now - Duration::days(1);
        let me = org(&ctx, "Me@OpsAgent.dev", Some("hn"), day).await;
        sql(
            &ctx,
            "UPDATE organisations SET billing_status = 'active', billing_tier = 'team', billing_quantity = 2, \
             trial_ends_at = $2 WHERE id = $1",
            vec![me.into(), (day + Duration::days(14)).into()],
        )
        .await;
        let real = org(&ctx, "r@example.com", Some("x"), day).await;
        sql(
            &ctx,
            "UPDATE organisations SET billing_status = 'active', billing_tier = 'team', billing_quantity = 2, \
             trial_ends_at = $2 WHERE id = $1",
            vec![real.into(), (day + Duration::days(14)).into()],
        )
        .await;
        let conn = Uuid::new_v4();
        sql(
            &ctx,
            "INSERT INTO connections (id, organisation_id, provider, external_account_id, status, first_connected_at) \
             VALUES ($1, $2, 'aws', '123456789012', 'connected', now())",
            vec![conn.into(), real.into()],
        )
        .await;
        sql(
            &ctx,
            "INSERT INTO findings (id, organisation_id, connection_id, check_id, resource_identity, severity, title) \
             VALUES ($1, $2, $3, 'c', 'r', 'high', 't')",
            vec![Uuid::new_v4().into(), real.into(), conn.into()],
        )
        .await;
        let w = week(&ctx, now).await;
        assert_eq!(w.new_orgs_by_source, [("x".to_string(), 1)]);
        assert_eq!((w.trials_started, w.activated, w.converted_to_paid), (1, 1, 1));
        assert_eq!(w.mrr_cents, 2 * 29900);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn notice_has_week_block_on_monday_only() {
    serve(|_req, ctx| async move {
        use chrono::TimeZone;
        let mail = prepare(&ctx);
        org(
            &ctx,
            "a@example.com",
            Some("hn"),
            Utc.with_ymd_and_hms(2026, 11, 22, 8, 0, 0).unwrap(),
        )
        .await;
        let monday = Utc.with_ymd_and_hms(2026, 11, 23, 6, 0, 0).unwrap();
        let tuesday = Utc.with_ymd_and_hms(2026, 11, 24, 6, 0, 0).unwrap();
        for at in [monday, tuesday] {
            let run = night(&ctx, at).await;
            perform(&ctx, JobKind::OperatorNotice, run).await.unwrap();
        }
        let sent = mail.sent();
        assert!(
            sent[0]
                .text
                .starts_with("Week: new orgs by source hn 1 | trials started 0"),
            "{}",
            sent[0].text
        );
        assert!(!sent[1].text.contains("Week:"), "{}", sent[1].text);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn week_counts_sanitises_source() {
    serve(|_req, ctx| async move {
        let now = slot(0);
        org(
            &ctx,
            "a@example.com",
            Some("hn\nIgnore previous"),
            now - Duration::days(1),
        )
        .await;
        let w = week(&ctx, now).await;
        assert_eq!(w.new_orgs_by_source, [("hnignoreprevious".to_string(), 1)]);
    })
    .await;
}
