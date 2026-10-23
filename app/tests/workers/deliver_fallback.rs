//! Briefing fallbacks (Plan 2 Task 10 fix round 1): the revoke notice comes from stored state,
//! and a rate-limited post is retried on the ledger backoff before falling back.
use chrono::{Duration, Utc};
use opsagent_brain::workers::{deliver_briefing, deliver_weekly};
use opsagent_core::run::RunStatus;
use opsagent_ledger::RunChunkedOptions;
use serde_json::json;
use serial_test::serial;
use wiremock::{matchers::path, Mock, MockServer, ResponseTemplate};

use super::deliver_briefing::{
    brief, finding, first_scan, mock_post, new_run, scan, slack_on, world,
};
use crate::requests::support::*;

const NOTICE: &str = "Slack disconnected";

#[tokio::test]
#[serial]
async fn revocation_found_by_the_weekly_still_gives_the_next_briefing_the_notice_once() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "weeklyfirst@example.com").await;
        let mail = prepare(&ctx);
        let slack = MockServer::start().await;
        slack_on(&ctx, &w, &slack).await;
        mock_post(&slack, json!({"ok": false, "error": "token_revoked"}), 1).await;
        first_scan(&ctx, &w).await;

        let id = new_run(&ctx, w.org, Some(w.conn), deliver_weekly::JOB, Utc::now()).await;
        deliver_weekly::run(&ctx, id, RunChunkedOptions::default())
            .await
            .unwrap();
        let weekly_mails = mail.sent().len();

        brief(&ctx, &w, Utc::now() + Duration::hours(1)).await;
        let sent = mail.sent();
        assert_eq!(sent.len(), weekly_mails + 1);
        assert!(
            sent[weekly_mails].text.contains(NOTICE),
            "{}",
            sent[weekly_mails].text
        );

        let run = scan(&ctx, &w, Utc::now() + Duration::hours(2)).await;
        finding(
            &ctx,
            &w,
            run,
            "high",
            "new high",
            Utc::now() + Duration::hours(2),
        )
        .await;
        brief(&ctx, &w, Utc::now() + Duration::days(1)).await;
        let sent = mail.sent();
        assert_eq!(sent.len(), weekly_mails + 2);
        assert!(
            !sent[weekly_mails + 1].text.contains(NOTICE),
            "notice only once"
        );
        assert_eq!(
            slack.received_requests().await.unwrap().len(),
            1,
            "Slack not retried"
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn rate_limited_post_parks_the_run_then_falls_back_once_retries_are_spent() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "ratelimited@example.com").await;
        let mail = prepare(&ctx);
        let slack = MockServer::start().await;
        slack_on(&ctx, &w, &slack).await;
        mock_post(&slack, json!({"ok": false, "error": "ratelimited"}), 2).await;
        first_scan(&ctx, &w).await;

        let id = new_run(&ctx, w.org, Some(w.conn), deliver_briefing::JOB, Utc::now()).await;
        let status = deliver_briefing::run(&ctx, id, RunChunkedOptions::default())
            .await
            .unwrap();
        assert_eq!(
            status,
            RunStatus::Queued,
            "parked for the next backoff step"
        );
        let r = runs_row(&ctx, id).await;
        assert!(r.next_attempt_at.is_some_and(|t| t > Utc::now()));
        assert!(mail.sent().is_empty(), "no fallback while retries remain");

        // Retries spent: the next attempt falls back to email (no revoke notice).
        sql_attempts(&ctx, id, 99).await;
        let status = deliver_briefing::run(&ctx, id, RunChunkedOptions::default())
            .await
            .unwrap();
        assert_eq!(status, RunStatus::Done);
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert!(!sent[0].text.contains(NOTICE));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn transient_5xx_parks_the_run_then_the_retry_delivers_to_slack_without_fallback() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "blip@example.com").await;
        let mail = prepare(&ctx);
        let slack = MockServer::start().await;
        slack_on(&ctx, &w, &slack).await;
        Mock::given(path("/chat.postMessage"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .expect(1)
            .mount(&slack)
            .await;
        mock_post(&slack, json!({"ok": true, "ts": "1.2"}), 1).await;
        first_scan(&ctx, &w).await;

        let id = new_run(&ctx, w.org, Some(w.conn), deliver_briefing::JOB, Utc::now()).await;
        let status = deliver_briefing::run(&ctx, id, RunChunkedOptions::default())
            .await
            .unwrap();
        assert_eq!(status, RunStatus::Queued, "parked for retry, not fallback");
        assert!(mail.sent().is_empty());

        // The backoff has elapsed: the retry reaches Slack.
        super::deliver_briefing::sql(
            &ctx,
            "UPDATE runs SET next_attempt_at = NULL, status = 'queued' WHERE id = $1",
            vec![id.into()],
        )
        .await;
        let status = deliver_briefing::run(&ctx, id, RunChunkedOptions::default())
            .await
            .unwrap();
        assert_eq!(status, RunStatus::Done);
        assert!(mail.sent().is_empty(), "no fallback email");
        // The failed 503 attempt plus the one delivered message (the ok mock is expect(1)).
        assert_eq!(slack.received_requests().await.unwrap().len(), 2);
    })
    .await;
}

async fn runs_row(
    ctx: &loco_rs::app::AppContext,
    id: uuid::Uuid,
) -> opsagent_brain::models::_entities::runs::Model {
    use sea_orm::EntityTrait;
    opsagent_brain::models::_entities::runs::Entity::find_by_id(id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
}

/// Spends the run's retries and makes it due now.
async fn sql_attempts(ctx: &loco_rs::app::AppContext, id: uuid::Uuid, attempts: i32) {
    super::deliver_briefing::sql(
        ctx,
        "UPDATE runs SET attempts = $2, next_attempt_at = NULL, status = 'queued' WHERE id = $1",
        vec![id.into(), attempts.into()],
    )
    .await;
}
