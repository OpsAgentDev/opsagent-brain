//! `deliver_alert` (urgent-alerts spec): one message per new open critical, caps, roll-up,
//! first-scan baseline, owner email fallback. Findings are seeded in the database or moved
//! through the Pg lifecycle (`upsert_seen`, `resolve_unseen`); Slack is a wiremock server.
use chrono::{Duration, Utc};
use opsagent_brain::models::_entities::{connections, findings, runs};
use opsagent_core::{
    finding::{FindingDraft, FindingKey, Severity},
    run::RunStatus,
};
use opsagent_ledger::{JobKind, RunChunkedOptions};
use sea_orm::entity::prelude::*;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::deliver_briefing::{
    backdate, brief, briefed, finding, mock_post, new_run, posted, rows, scan, slack_on, sql,
    world, World,
};
use super::full_scan::{noisy, scan as full_scan};
use crate::requests::support::*;

const OK: fn() -> serde_json::Value = || json!({"ok": true, "ts": "1.1"});

fn base(ctx: &TestApp) -> String {
    state(ctx)
        .unwrap()
        .config
        .web_base_url
        .trim_end_matches('/')
        .to_owned()
}

/// Runs a new `deliver_alert` run for the connection; returns its id.
async fn alert(ctx: &TestApp, w: &World) -> Uuid {
    let id = new_run(
        ctx,
        w.org,
        Some(w.conn),
        JobKind::DeliverAlert.as_str(),
        Utc::now(),
    )
    .await;
    rerun(ctx, id).await;
    id
}

async fn rerun(ctx: &TestApp, id: Uuid) -> RunStatus {
    let a = actions(ctx).unwrap();
    a.deliveries
        .deliver_alert
        .run(id, RunChunkedOptions::default())
        .await
        .unwrap()
}

/// The connection's first delivery: baselines with no criticals, so nothing is sent.
async fn baselined(ctx: &TestApp, w: &World) {
    alert(ctx, w).await;
}

/// A critical opened now; returns its id.
async fn crit(ctx: &TestApp, w: &World, title: &str) -> Uuid {
    let run = scan(ctx, w, Utc::now()).await;
    finding(ctx, w, run, "critical", title, Utc::now()).await;
    by_title(ctx, w, title).await.id
}

async fn by_title(ctx: &TestApp, w: &World, title: &str) -> findings::Model {
    findings::Entity::find()
        .filter(findings::Column::ConnectionId.eq(w.conn))
        .filter(findings::Column::Title.eq(title))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
}

fn draft(w: &World, severity: Severity) -> FindingDraft {
    FindingDraft {
        key: FindingKey {
            connection_id: w.conn,
            check_id: "03".into(),
            resource_identity: "snap-1".into(),
            variant: "public_snapshot".into(),
        },
        severity,
        title: "Public snapshot".into(),
        summary: "s".into(),
        next_step: "Make it private.".into(),
        cost_monthly_usd: None,
        evidence: vec![],
    }
}

/// A full scan that sees the snapshot finding at `severity`; `None`: it is gone (resolved).
async fn lifecycle(ctx: &TestApp, w: &World, severity: Option<Severity>) {
    let run = scan(ctx, w, Utc::now()).await;
    let f = ctx.state.uow.findings();
    let drafts: Vec<_> = severity.map(|s| draft(w, s)).into_iter().collect();
    f.upsert_seen(w.org, w.conn, run, &drafts, Utc::now())
        .await
        .unwrap();
    if severity.is_none() {
        f.resolve_unseen(w.org, w.conn, run, &[], Utc::now())
            .await
            .unwrap();
    }
}

async fn slack(ctx: &TestApp, w: &World) -> MockServer {
    let s = MockServer::start().await;
    slack_on(ctx, w, &s).await;
    s
}

async fn account(ctx: &TestApp, w: &World) -> String {
    let c = connections::Entity::find_by_id(w.conn)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    c.display_name.or(c.external_account_id).unwrap()
}

#[tokio::test]
#[serial]
async fn new_critical_alerts_once() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "once@example.com").await;
        let s = slack(&ctx, &w).await;
        mock_post(&s, OK(), 1).await;
        baselined(&ctx, &w).await;
        let id = crit(&ctx, &w, "Public <snapshot>").await;
        sql(&ctx, "UPDATE findings SET next_step = 'Make it private.' WHERE id = $1", vec![id.into()]).await;
        sql(
            &ctx,
            "INSERT INTO resources (id, organisation_id, connection_id, kind, identity, name, region) \
             VALUES ($1, $2, $3, 'storage', $4, 'nightly-db', 'eu-west-1')",
            vec![Uuid::new_v4().into(), w.org.into(), w.conn.into(), id.to_string().into()],
        )
        .await;
        let run = alert(&ctx, &w).await;
        let acct = account(&ctx, &w).await;
        let text = format!(
            "🔴 Urgent: Public &lt;snapshot&gt;\nnightly-db · {acct} · eu-west-1\nMake it private.\n\
             View finding: {}/findings/{id}",
            base(&ctx)
        );
        assert_eq!(posted(&s).await, vec![text]);
        assert!(by_title(&ctx, &w, "Public <snapshot>").await.alerted_at.is_some());
        let r = rows(&ctx, &w).await;
        assert_eq!((r.len(), r[0].kind.as_str(), r[0].status.as_str()), (1, "alert", "sent"));

        // Rerun of the finished run, a fresh run, and a crash after the post but before the
        // ledger and `alerted_at` were written: no second post.
        rerun(&ctx, run).await;
        alert(&ctx, &w).await;
        sql(&ctx, "UPDATE findings SET alerted_at = NULL WHERE id = $1", vec![id.into()]).await;
        sql(
            &ctx,
            "DELETE FROM side_effects WHERE run_id = $1 AND effect_key = $2",
            vec![run.into(), format!("alert:{id}").into()],
        )
        .await;
        sql(
            &ctx,
            r#"UPDATE runs SET status = 'queued', checkpoint = '{"chunks_done": [], "cursor": null, "stats": {}}' WHERE id = $1"#,
            vec![run.into()],
        )
        .await;
        assert_eq!(rerun(&ctx, run).await, RunStatus::Done);
        assert_eq!(posted(&s).await.len(), 1);
        assert!(by_title(&ctx, &w, "Public <snapshot>").await.alerted_at.is_some());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn no_alert_for_high_accepted_snoozed_flapping_or_switch_off() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "none@example.com").await;
        let s = slack(&ctx, &w).await;
        mock_post(&s, OK(), 0).await;
        baselined(&ctx, &w).await;
        let run = scan(&ctx, &w, Utc::now()).await;
        finding(&ctx, &w, run, "high", "a high", Utc::now()).await;
        for st in ["accepted", "snoozed", "flapping"] {
            let id = crit(&ctx, &w, st).await;
            sql(
                &ctx,
                "UPDATE findings SET status = $2 WHERE id = $1",
                vec![id.into(), st.into()],
            )
            .await;
        }
        alert(&ctx, &w).await;
        crit(&ctx, &w, "switched off").await;
        sql(
            &ctx,
            "UPDATE connections SET urgent_alerts = false WHERE id = $1",
            vec![w.conn.into()],
        )
        .await;
        let run = alert(&ctx, &w).await;
        assert!(posted(&s).await.is_empty());
        assert!(rows(&ctx, &w).await.is_empty());
        assert!(by_title(&ctx, &w, "switched off")
            .await
            .alerted_at
            .is_none());
        let r = runs::Entity::find_by_id(run)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.checkpoint["stats"]["skipped"], "not_eligible");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn escalate_deescalate_escalate_alerts_once() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "flip@example.com").await;
        let s = slack(&ctx, &w).await;
        mock_post(&s, OK(), 1).await;
        baselined(&ctx, &w).await;
        for sev in [
            Severity::High,
            Severity::Critical,
            Severity::High,
            Severity::Critical,
        ] {
            lifecycle(&ctx, &w, Some(sev)).await;
            alert(&ctx, &w).await;
        }
        assert_eq!(posted(&s).await.len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn flapping_then_settled_alerts_once() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "flap@example.com").await;
        let s = slack(&ctx, &w).await;
        mock_post(&s, OK(), 1).await;
        baselined(&ctx, &w).await;
        lifecycle(&ctx, &w, Some(Severity::Critical)).await;
        // Flapping one run short of settling (STABLE_RUNS).
        sql(
            &ctx,
            "UPDATE findings SET status = 'flapping', stable_runs = 6 WHERE connection_id = $1",
            vec![w.conn.into()],
        )
        .await;
        alert(&ctx, &w).await;
        assert!(posted(&s).await.is_empty());
        lifecycle(&ctx, &w, Some(Severity::Critical)).await;
        assert_eq!(by_title(&ctx, &w, "Public snapshot").await.status, "open");
        alert(&ctx, &w).await;
        lifecycle(&ctx, &w, Some(Severity::Critical)).await;
        alert(&ctx, &w).await;
        assert_eq!(posted(&s).await.len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn reopen_after_resolve_alerts_again() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "reopen@example.com").await;
        let s = slack(&ctx, &w).await;
        mock_post(&s, OK(), 2).await;
        baselined(&ctx, &w).await;
        lifecycle(&ctx, &w, Some(Severity::Critical)).await;
        alert(&ctx, &w).await;
        lifecycle(&ctx, &w, None).await;
        assert!(by_title(&ctx, &w, "Public snapshot")
            .await
            .alerted_at
            .is_none());
        lifecycle(&ctx, &w, Some(Severity::Critical)).await;
        alert(&ctx, &w).await;
        assert_eq!(posted(&s).await.len(), 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn first_full_scan_baselines_with_one_summary() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "baseline@example.com").await;
        let s = slack(&ctx, &w).await;
        mock_post(&s, OK(), 1).await;
        crit(&ctx, &w, "c1").await;
        crit(&ctx, &w, "c2").await;
        alert(&ctx, &w).await;
        let text = format!(
            "First scan: 2 critical findings. See the dashboard: {}/findings",
            base(&ctx)
        );
        assert_eq!(posted(&s).await, vec![text]);
        assert!(by_title(&ctx, &w, "c2").await.alerted_at.is_some());
        alert(&ctx, &w).await;
        assert_eq!(posted(&s).await.len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn each_scan_enqueues_one_delivery_that_the_worker_runs() {
    serve(|req, ctx| async move {
        let conn = connected(&req, &ctx, "enqueue@example.com", "noisy")
            .await
            .2;
        let mail = prepare(&ctx);
        let deliveries = || async {
            runs::Entity::find()
                .filter(runs::Column::ConnectionId.eq(conn))
                .filter(runs::Column::JobType.eq("deliver_alert"))
                .all(&ctx.db)
                .await
                .unwrap()
        };
        let scan_run = full_scan(&ctx, conn, 0, &noisy()).await;
        let d = deliveries().await;
        assert_eq!(d.len(), 1);
        let s = runs::Entity::find_by_id(scan_run)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(d[0].scheduled_at, s.scheduled_at);
        perform(&ctx, JobKind::DeliverAlert, d[0].id).await.unwrap();
        // No Slack: the baseline summary goes to the owner.
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert!(
            sent[0].subject.starts_with("First scan: "),
            "{}",
            sent[0].subject
        );
        // A second full scan finds nothing new but still gets its (empty) delivery.
        full_scan(&ctx, conn, 1, &noisy()).await;
        assert_eq!(deliveries().await.len(), 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn no_slack_falls_back_to_owner_email() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "fallback@example.com").await;
        let mail = prepare(&ctx);
        baselined(&ctx, &w).await;
        let id = crit(&ctx, &w, "Root keys").await;
        alert(&ctx, &w).await;
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "fallback@example.com");
        assert_eq!(
            sent[0].subject,
            format!("Urgent: Root keys ({})", account(&ctx, &w).await)
        );
        assert!(
            sent[0].text.starts_with("🔴 Urgent: Root keys\n"),
            "{}",
            sent[0].text
        );
        assert!(
            sent[0].text.ends_with(&format!("/findings/{id}")),
            "{}",
            sent[0].text
        );
        let r = rows(&ctx, &w).await;
        assert_eq!(
            (r[0].kind.as_str(), r[0].status.as_str()),
            ("alert", "fallback_email")
        );

        // Through `may_deliver`: a suppressed owner gets nothing; the finding is still marked.
        let hash = opsagent_brain::actions::recipients::tokens::email_hash("fallback@example.com");
        sql(
            &ctx,
            "INSERT INTO email_suppressions (id, organisation_id, email_hash, reason, expires_at) \
             VALUES ($1, $2, $3, 'ignored', now() + interval '1 day')",
            vec![Uuid::new_v4().into(), w.org.into(), hash.into()],
        )
        .await;
        crit(&ctx, &w, "Second").await;
        alert(&ctx, &w).await;
        assert_eq!(mail.sent().len(), 1);
        assert!(by_title(&ctx, &w, "Second").await.alerted_at.is_some());
        let st: Vec<_> = rows(&ctx, &w).await.into_iter().map(|d| d.status).collect();
        assert!(st.contains(&"suppressed".to_owned()), "{st:?}");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn slack_revoked_mid_run_falls_back_and_keeps_caps() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "revoked@example.com").await;
        let mail = prepare(&ctx);
        let s = slack(&ctx, &w).await;
        Mock::given(method("POST"))
            .and(path("/chat.postMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(OK()))
            .up_to_n_times(1)
            .mount(&s)
            .await;
        mock_post(&s, json!({"ok": false, "error": "token_revoked"}), 1).await;
        baselined(&ctx, &w).await;
        for i in 0..7 {
            crit(&ctx, &w, &format!("c{i}")).await;
        }
        let run = alert(&ctx, &w).await;
        assert_eq!(
            posted(&s).await.len(),
            2,
            "Slack not tried after the revoke"
        );
        let subjects: Vec<_> = mail.sent().into_iter().map(|m| m.subject).collect();
        assert_eq!(subjects.len(), 5, "{subjects:?}");
        assert!(subjects[3].starts_with("Urgent: c4 "), "{subjects:?}");
        assert!(
            subjects[4].starts_with("Urgent: 2 more urgent findings "),
            "{subjects:?}"
        );
        assert!(mail.sent()[4].text.ends_with("/findings"));
        let open = findings::Entity::find()
            .filter(findings::Column::ConnectionId.eq(w.conn))
            .filter(findings::Column::AlertedAt.is_null())
            .all(&ctx.db)
            .await
            .unwrap();
        assert!(open.is_empty(), "all seven marked");
        let t = ctx.state.uow.deliveries().alert_tally(
            w.org,
            w.conn,
            run,
            Utc::now() - Duration::hours(24),
        );
        assert_eq!(t.await.unwrap().since, 5);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn backlog_from_crashed_delivery_sent_by_next_run() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "backlog@example.com").await;
        let s = slack(&ctx, &w).await;
        mock_post(&s, OK(), 1).await;
        baselined(&ctx, &w).await;
        crit(&ctx, &w, "missed").await;
        // The scan's delivery died before it sent anything.
        let dead = new_run(&ctx, w.org, Some(w.conn), "deliver_alert", Utc::now()).await;
        sql(
            &ctx,
            "UPDATE runs SET status = 'failed' WHERE id = $1",
            vec![dead.into()],
        )
        .await;
        assert_eq!(rerun(&ctx, dead).await, RunStatus::Failed);
        assert!(posted(&s).await.is_empty());
        alert(&ctx, &w).await;
        assert_eq!(posted(&s).await.len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn briefing_marks_alerted_items() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "marked@example.com").await;
        let s = slack(&ctx, &w).await;
        mock_post(&s, OK(), 2).await;
        // Scanned and briefed before, so the briefing is a daily one with titles.
        backdate(&ctx, &w, Utc::now() - Duration::hours(3)).await;
        scan(&ctx, &w, Utc::now() - Duration::hours(2)).await;
        briefed(&ctx, &w, Utc::now() - Duration::hours(1)).await;
        baselined(&ctx, &w).await;
        crit(&ctx, &w, "alerted one").await;
        alert(&ctx, &w).await;
        brief(&ctx, &w, Utc::now() + Duration::minutes(1)).await;
        let p = posted(&s).await;
        assert_eq!(p.len(), 2);
        assert!(p[1].contains("alerted one (alerted "), "{}", p[1]);
    })
    .await;
}
