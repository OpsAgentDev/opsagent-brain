//! `deliver_briefing` (Plan 2 Task 10). Scans, findings and earlier briefings are seeded in
//! the database; Slack is a wiremock server, mail a `CaptureMailer`.
use opsagent_brain::adapters::db::ledger_storage::{stmt, PgStorage};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use loco_rs::{app::AppContext, prelude::*};
use opsagent_brain::{
    adapters::slack::{HttpSlack, Install, SlackClient},
    app::actions,
    models::_entities::{deliveries, integrations, runs, schedules},
};
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_deliver::schedule::next_after;
use opsagent_ledger::{harness, JobKind, RunChunkedOptions, Storage};
use sea_orm::ConnectionTrait;
use serde_json::{json, Value};
use serial_test::serial;
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use crate::requests::support::*;

pub const CHANNEL: &str = "C0123ABCD";

/// A connected connection in its own organisation.
pub struct World {
    pub org: Uuid,
    pub conn: Uuid,
    pub owner: Uuid,
}

pub async fn sql(ctx: &AppContext, q: &str, v: Vec<sea_orm::Value>) {
    ctx.db.execute_raw(stmt(q, v)).await.unwrap();
}

pub async fn world(req: &axum_test::TestServer, ctx: &AppContext, email: &str) -> World {
    let (_, _, conn) = connected(req, ctx, email, "clean").await;
    let row = ctx
        .db
        .query_one_raw(stmt(
            "SELECT c.organisation_id, m.user_id FROM connections c JOIN members m \
             ON m.organisation_id = c.organisation_id WHERE c.id = $1",
            vec![conn.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    World {
        org: row.try_get("", "organisation_id").unwrap(),
        conn,
        owner: row.try_get("", "user_id").unwrap(),
    }
}

/// An active Slack install for the organisation, the app pointed at `server`, and the
/// connection routed to `CHANNEL`.
pub async fn slack_on(ctx: &AppContext, w: &World, server: &MockServer) {
    let install = Install {
        access_token: "xoxb-secret-token".into(),
        team_id: format!("T{}", w.org.simple()),
        team_name: "Acme".into(),
        bot_user_id: "U0BOT".into(),
        scope: "chat:write".into(),
    };
    let finish = &actions(ctx).unwrap().integrations.finish_slack_install;
    finish.save(w.org, w.owner, &install).await.unwrap();
    let c: Arc<dyn SlackClient> = Arc::new(HttpSlack::new(server.uri()).unwrap());
    ctx.shared_store.insert(c);
    // Actions hold the Slack client they were built with.
    opsagent_brain::app::install_actions(ctx).unwrap();
    sql(
        ctx,
        "UPDATE connections SET slack_channel_id = $2 WHERE id = $1",
        vec![w.conn.into(), CHANNEL.into()],
    )
    .await;
}

/// `chat.postMessage` answers `body`, expected `times` times.
pub async fn mock_post(server: &MockServer, body: Value, times: u64) {
    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(times)
        .mount(server)
        .await;
}

/// The `text` of every message posted to Slack.
pub async fn posted(server: &MockServer) -> Vec<String> {
    let mut out = Vec::new();
    for r in server.received_requests().await.unwrap() {
        let b: Value = serde_json::from_slice(&r.body).unwrap();
        out.push(b["text"].as_str().unwrap().to_owned());
    }
    out
}

/// A finished full scan.
pub async fn scan(ctx: &AppContext, w: &World, finished: DateTime<Utc>) -> Uuid {
    let id = Uuid::new_v4();
    sql(
        ctx,
        "INSERT INTO runs (id, organisation_id, connection_id, job_type, scheduled_at, status, \
         finished_at) VALUES ($1, $2, $3, 'full_scan', $4, 'done', $4)",
        vec![id.into(), w.org.into(), w.conn.into(), finished.into()],
    )
    .await;
    id
}

/// An open finding of `severity` opened by `run` at `at`.
pub async fn finding(
    ctx: &AppContext,
    w: &World,
    run: Uuid,
    severity: &str,
    title: &str,
    at: DateTime<Utc>,
) {
    let id = Uuid::new_v4();
    sql(
        ctx,
        "INSERT INTO findings (id, organisation_id, connection_id, check_id, resource_identity, \
         severity, title, first_seen_run_id, last_seen_run_id, created_at) \
         VALUES ($1, $2, $3, '01', $4, $5, $6, $7, $7, $8)",
        vec![
            id.into(),
            w.org.into(),
            w.conn.into(),
            id.to_string().into(),
            severity.into(),
            title.into(),
            run.into(),
            at.into(),
        ],
    )
    .await;
    sql(
        ctx,
        "INSERT INTO finding_events (id, finding_id, run_id, event_type, created_at) \
         VALUES ($1, $2, $3, 'opened', $4)",
        vec![Uuid::new_v4().into(), id.into(), run.into(), at.into()],
    )
    .await;
}

/// A briefing already delivered at `at`.
async fn briefed(ctx: &AppContext, w: &World, at: DateTime<Utc>) {
    sql(
        ctx,
        "INSERT INTO deliveries (id, organisation_id, connection_id, kind, channel, target, \
         status, sent_at) VALUES ($1, $2, $3, 'briefing', 'slack', 'C0', 'sent', $4)",
        vec![
            Uuid::new_v4().into(),
            w.org.into(),
            w.conn.into(),
            at.into(),
        ],
    )
    .await;
}

pub async fn backdate(ctx: &AppContext, w: &World, at: DateTime<Utc>) {
    sql(
        ctx,
        "UPDATE connections SET created_at = $2 WHERE id = $1",
        vec![w.conn.into(), at.into()],
    )
    .await;
}

pub async fn new_run(
    ctx: &AppContext,
    org: Uuid,
    conn: Option<Uuid>,
    job: &str,
    at: DateTime<Utc>,
) -> Uuid {
    PgStorage::new(ctx.db.clone())
        .create_run(RunKey {
            organisation_id: Some(org),
            connection_id: conn,
            job_type: job.into(),
            scheduled_at: at,
        })
        .await
        .unwrap()
        .run
        .id
}

pub async fn brief(ctx: &AppContext, w: &World, at: DateTime<Utc>) -> (Uuid, RunStatus) {
    let id = new_run(
        ctx,
        w.org,
        Some(w.conn),
        JobKind::DeliverBriefing.as_str(),
        at,
    )
    .await;
    let opts = RunChunkedOptions::default();
    (
        id,
        actions(ctx)
            .unwrap()
            .deliveries
            .deliver_briefing
            .run(id, opts)
            .await
            .unwrap(),
    )
}

pub async fn rows(ctx: &AppContext, w: &World) -> Vec<deliveries::Model> {
    deliveries::Entity::find()
        .filter(deliveries::Column::OrganisationId.eq(w.org))
        .order_by_asc(deliveries::Column::Channel)
        .all(&ctx.db)
        .await
        .unwrap()
}

pub async fn stats(ctx: &AppContext, run: Uuid) -> Value {
    let r = runs::Entity::find_by_id(run)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    r.checkpoint["stats"].clone()
}

/// The connection's first scan finished an hour ago with two criticals.
pub async fn first_scan(ctx: &AppContext, w: &World) {
    let now = Utc::now();
    backdate(ctx, w, now - Duration::hours(2)).await;
    let run = scan(ctx, w, now - Duration::hours(1)).await;
    for t in ["TITLE-SECRET-1", "TITLE-SECRET-2"] {
        finding(ctx, w, run, "critical", t, now - Duration::hours(1)).await;
    }
}

#[tokio::test]
#[serial]
async fn nothing_changed_writes_no_row_and_ends_done_skipped() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "quiet@example.com").await;
        let mail = prepare(&ctx);
        let now = Utc::now();
        backdate(&ctx, &w, now - Duration::days(2)).await;
        let run = scan(&ctx, &w, now - Duration::hours(3)).await;
        finding(&ctx, &w, run, "critical", "old", now - Duration::hours(4)).await;
        briefed(&ctx, &w, now - Duration::hours(2)).await;

        let (id, status) = brief(&ctx, &w, now).await;
        assert_eq!(status, RunStatus::Done);
        assert_eq!(stats(&ctx, id).await["skipped"], "nothing_changed");
        assert_eq!(rows(&ctx, &w).await.len(), 1, "only the earlier briefing");
        assert!(mail.sent().is_empty());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn first_scan_posts_counts_and_no_titles() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "first@example.com").await;
        let slack = MockServer::start().await;
        slack_on(&ctx, &w, &slack).await;
        mock_post(&slack, json!({"ok": true, "ts": "1.1"}), 1).await;
        first_scan(&ctx, &w).await;

        let (id, status) = brief(&ctx, &w, Utc::now()).await;
        assert_eq!(status, RunStatus::Done);
        let text = posted(&slack).await.pop().unwrap();
        assert!(text.contains("first scan"), "{text}");
        assert!(text.contains("2 critical"), "{text}");
        assert!(!text.contains("TITLE-SECRET"), "{text}");
        let req = &slack.received_requests().await.unwrap()[0];
        let body: Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["client_msg_id"], format!("{id}:briefing"));
        assert_eq!(body["channel"], CHANNEL);
        let r = rows(&ctx, &w).await;
        assert_eq!(r.len(), 1);
        assert_eq!(
            (
                r[0].channel.as_str(),
                r[0].status.as_str(),
                r[0].target.as_str()
            ),
            ("slack", "sent", CHANNEL)
        );
        assert_eq!(r[0].external_ref.as_deref(), Some("1.1"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn fourteen_new_criticals_post_once_with_ten_items_and_the_total() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "busy@example.com").await;
        let slack = MockServer::start().await;
        slack_on(&ctx, &w, &slack).await;
        mock_post(&slack, json!({"ok": true, "ts": "1.2"}), 1).await;
        let now = Utc::now();
        backdate(&ctx, &w, now - Duration::days(2)).await;
        scan(&ctx, &w, now - Duration::hours(30)).await;
        briefed(&ctx, &w, now - Duration::hours(24)).await;
        let run = scan(&ctx, &w, now - Duration::hours(1)).await;
        for n in 0..14 {
            let t = format!("crit {n}");
            finding(&ctx, &w, run, "critical", &t, now - Duration::hours(1)).await;
        }

        brief(&ctx, &w, now).await;
        let texts = posted(&slack).await;
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].matches("• critical:").count(), 10, "{}", texts[0]);
        assert!(texts[0].contains("(14)"), "{}", texts[0]);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn revoked_token_falls_back_once_and_slack_is_not_retried_next_day() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "revoked@example.com").await;
        let mail = prepare(&ctx);
        let slack = MockServer::start().await;
        slack_on(&ctx, &w, &slack).await;
        mock_post(&slack, json!({"ok": false, "error": "token_revoked"}), 1).await;
        first_scan(&ctx, &w).await;

        let (_, status) = brief(&ctx, &w, Utc::now()).await;
        assert_eq!(status, RunStatus::Done);
        let i = integrations::Entity::find()
            .filter(integrations::Column::OrganisationId.eq(w.org))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(i.status, "revoked");
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "revoked@example.com");
        assert!(
            sent[0].text.contains("Slack disconnected"),
            "{}",
            sent[0].text
        );
        assert!(sent[0].text.contains("first scan"), "{}", sent[0].text);
        let r = rows(&ctx, &w).await;
        let st: Vec<_> = r
            .iter()
            .map(|d| (d.channel.as_str(), d.status.as_str()))
            .collect();
        assert_eq!(st, [("email", "fallback_email"), ("slack", "failed")]);

        // The next day: something new, Slack still revoked, so email only and no notice.
        let run = scan(&ctx, &w, Utc::now()).await;
        finding(&ctx, &w, run, "high", "new high", Utc::now()).await;
        brief(&ctx, &w, Utc::now() + Duration::days(1)).await;
        assert_eq!(slack.received_requests().await.unwrap().len(), 1);
        let sent = mail.sent();
        assert_eq!(sent.len(), 2);
        assert!(
            !sent[1].text.contains("Slack disconnected"),
            "{}",
            sent[1].text
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn no_slack_route_is_an_email_fallback_and_only_unsubscribe_spares_the_owner() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "noslack@example.com").await;
        let mail = prepare(&ctx);
        first_scan(&ctx, &w).await;
        brief(&ctx, &w, Utc::now()).await;
        let r = rows(&ctx, &w).await;
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].channel.as_str(), r[0].status.as_str()), ("email", "fallback_email"));
        assert_eq!(mail.sent().len(), 1);

        // An owner address unsubscribed from another organisation's footer is still mailed.
        let hash = opsagent_brain::actions::recipients::tokens::email_hash("noslack@example.com");
        sql(
            &ctx,
            "INSERT INTO email_suppressions (id, email_hash, reason) VALUES ($1, $2, 'unsubscribed')",
            vec![Uuid::new_v4().into(), hash.clone().into()],
        )
        .await;
        let run = scan(&ctx, &w, Utc::now()).await;
        finding(&ctx, &w, run, "high", "new high", Utc::now()).await;
        brief(&ctx, &w, Utc::now() + Duration::days(1)).await;
        assert_eq!(mail.sent().len(), 2);

        // Any other suppression still blocks the owner.
        sql(
            &ctx,
            "INSERT INTO email_suppressions (id, organisation_id, email_hash, reason, expires_at) \
             VALUES ($1, $2, $3, 'ignored', now() + interval '1 day')",
            vec![Uuid::new_v4().into(), w.org.into(), hash.into()],
        )
        .await;
        let run = scan(&ctx, &w, Utc::now() + Duration::days(1)).await;
        finding(&ctx, &w, run, "high", "another high", Utc::now() + Duration::days(1)).await;
        brief(&ctx, &w, Utc::now() + Duration::days(2)).await;
        assert_eq!(mail.sent().len(), 2);
        let st: Vec<_> = rows(&ctx, &w).await.into_iter().map(|d| d.status).collect();
        assert!(st.contains(&"suppressed".to_owned()), "{st:?}");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn killed_and_resumed_briefing_posts_once() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "kill@example.com").await;
        let slack = MockServer::start().await;
        slack_on(&ctx, &w, &slack).await;
        mock_post(&slack, json!({"ok": true, "ts": "1.3"}), 1).await;
        first_scan(&ctx, &w).await;
        let id = new_run(&ctx, w.org, Some(w.conn), JobKind::DeliverBriefing.as_str(), Utc::now()).await;
        let runs = harness::kill_after_each_checkpoint(|ks| {
            let ctx = ctx.clone();
            async move {
                let opts = RunChunkedOptions {
                    after_checkpoint: Some(ks),
                    ..Default::default()
                };
                actions(&ctx).unwrap().deliveries.deliver_briefing.run(id, opts).await
            }
        })
        .await
        .unwrap();
        assert_eq!(runs, 2);
        // A crash after the post but before the checkpoint: the ledger stops a second post.
        sql(
            &ctx,
            r#"UPDATE runs SET status = 'queued', checkpoint = '{"chunks_done": [], "cursor": null, "stats": {}}' WHERE id = $1"#,
            vec![id.into()],
        )
        .await;
        let status = actions(&ctx).unwrap().deliveries.deliver_briefing.run(id, RunChunkedOptions::default())
            .await
            .unwrap();
        assert_eq!(status, RunStatus::Done);
        assert_eq!(posted(&slack).await.len(), 1);
        assert_eq!(rows(&ctx, &w).await.len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn defaults_and_patch_briefing_time_moves_the_schedule() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) =
            fake_connection(&req, &mail, "sched@example.com", "Sched", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        let conn: Uuid = id.parse().unwrap();
        let find = |job: &'static str| {
            let ctx = ctx.clone();
            async move {
                schedules::Entity::find()
                    .filter(schedules::Column::ConnectionId.eq(conn))
                    .filter(schedules::Column::JobType.eq(job))
                    .one(&ctx.db)
                    .await
                    .unwrap()
                    .unwrap()
            }
        };
        assert_eq!(find("deliver_briefing").await.cron_local, "0 8 * * *");
        let weekly = find("deliver_weekly").await;
        assert_eq!(weekly.cron_local, "0 9 * * 1");
        let org_weekly = schedules::Entity::find()
            .filter(schedules::Column::OrganisationId.eq(weekly.organisation_id))
            .filter(schedules::Column::ConnectionId.is_null())
            .filter(schedules::Column::JobType.eq("deliver_weekly"))
            .count(&ctx.db)
            .await
            .unwrap();
        assert_eq!(org_weekly, 1);

        let res = req
            .patch(&format!("/v1/orgs/{org}/connections/{id}"))
            .add_header("X-CSRF-Token", &t)
            .json(&json!({"briefing_time_local": "07:15"}))
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let s = find("deliver_briefing").await;
        assert_eq!(s.cron_local, "15 7 * * *");
        let due = s.next_due_at.unwrap().with_timezone(&Utc);
        let now = Utc::now();
        assert!(due > now && due - now <= Duration::hours(24), "{due}");
        assert_eq!(next_after("15 7 * * *", &s.timezone, now), Some(due));
    })
    .await;
}
