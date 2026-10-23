//! `deliver_weekly` (Plan 2 Task 10): idempotent effects, owner summary, unsubscribe footer.
use chrono::Utc;
use loco_rs::app::AppContext;
use opsagent_brain::{
    actions::recipients::tokens::{email_hash, unsubscribe_token, unsubscribe_url},
    adapters::db::Pg,
    app::actions,
};
use opsagent_core::org::{OrganisationsRepo, Role};
use opsagent_core::run::RunStatus;
use opsagent_ledger::{harness, JobKind, RunChunkedOptions};
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;
use wiremock::MockServer;

use super::deliver_briefing::{
    mock_post, new_run, posted, rows, scan, slack_on, sql, stats, world, World,
};
use crate::requests::support::*;

async fn user(ctx: &AppContext, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sql(
        ctx,
        "INSERT INTO users (id, email) VALUES ($1, $2)",
        vec![id.into(), email.into()],
    )
    .await;
    id
}

/// An active organisation-level recipient; `member_id` set makes it a member recipient.
async fn recipient(ctx: &AppContext, w: &World, email: &str, member_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sql(
        ctx,
        "INSERT INTO recipients (id, organisation_id, email, member_id, status) \
         VALUES ($1, $2, $3, $4, 'active')",
        vec![id.into(), w.org.into(), email.into(), member_id.into()],
    )
    .await;
    id
}

async fn weekly(ctx: &AppContext, w: &World, conn: Option<Uuid>) -> (Uuid, RunStatus) {
    let id = new_run(
        ctx,
        w.org,
        conn,
        JobKind::DeliverWeekly.as_str(),
        Utc::now(),
    )
    .await;
    let status = actions(ctx)
        .unwrap()
        .deliveries
        .deliver_weekly
        .run(id, RunChunkedOptions::default())
        .await
        .unwrap();
    (id, status)
}

#[tokio::test]
#[serial]
async fn killed_after_the_email_and_resumed_sends_one_email_and_one_post() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "weekly@example.com").await;
        let mail = prepare(&ctx);
        let slack = MockServer::start().await;
        slack_on(&ctx, &w, &slack).await;
        mock_post(&slack, json!({"ok": true, "ts": "9.9"}), 1).await;
        scan(&ctx, &w, Utc::now()).await;
        let id = new_run(&ctx, w.org, Some(w.conn), JobKind::DeliverWeekly.as_str(), Utc::now()).await;
        // Killed after each chunk's checkpoint: after `email`, then after `slack`.
        let runs = harness::kill_after_each_checkpoint(|ks| {
            let ctx = ctx.clone();
            async move {
                let opts = RunChunkedOptions {
                    after_checkpoint: Some(ks),
                    ..Default::default()
                };
                actions(&ctx).unwrap().deliveries.deliver_weekly.run(id, opts).await
            }
        })
        .await
        .unwrap();
        assert_eq!(runs, 3);
        // A crash after both effects but before any checkpoint: the ledger stops repeats.
        sql(
            &ctx,
            r#"UPDATE runs SET status = 'queued', checkpoint = '{"chunks_done": [], "cursor": null, "stats": {}}' WHERE id = $1"#,
            vec![id.into()],
        )
        .await;
        let status = actions(&ctx).unwrap().deliveries.deliver_weekly.run(id, RunChunkedOptions::default())
            .await
            .unwrap();
        assert_eq!(status, RunStatus::Done);

        let sent = mail.sent();
        assert_eq!(sent.len(), 1, "owners are the default recipients");
        assert_eq!(sent[0].to, "weekly@example.com");
        assert_eq!(
            sent[0].idempotency_key.as_deref(),
            Some(format!("{id}:weekly:{}", w.owner).as_str())
        );
        assert!(sent[0].html.as_deref().unwrap().contains("<html"));
        assert!(!sent[0].text.contains("Unsubscribe"), "an owner is a member");
        let texts = posted(&slack).await;
        assert_eq!(texts.len(), 1);
        assert!(texts[0].contains("OpsAgent weekly report"), "{}", texts[0]);
        let st: Vec<_> = rows(&ctx, &w)
            .await
            .into_iter()
            .map(|d| (d.kind, d.channel, d.status))
            .collect();
        let want = |c: &str| ("weekly".to_owned(), c.to_owned(), "sent".to_owned());
        assert_eq!(st, [want("email"), want("slack")]);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn organisation_summary_goes_only_to_owners() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "boss@example.com").await;
        let mail = prepare(&ctx);
        let u = user(&ctx, "member@example.com").await;
        let m = Pg::new(&ctx.db).add_member(w.org, u, Role::Member)
            .await
            .unwrap();
        recipient(&ctx, &w, "member@example.com", Some(m.id)).await;
        recipient(&ctx, &w, "optin@example.com", None).await;
        scan(&ctx, &w, Utc::now()).await;

        // One connection: its own weekly already says it all, so no summary.
        let (one, status) = weekly(&ctx, &w, None).await;
        assert_eq!(status, RunStatus::Done);
        assert!(mail.sent().is_empty(), "summary skipped for a single connection");
        assert_eq!(stats(&ctx, one).await["skipped"], "single_connection");

        sql(
            &ctx,
            "INSERT INTO connections (id, organisation_id, provider, external_account_id, status, display_name, \
             recipients) \
             VALUES ($1, $2, 'aws', $1::text, 'connected', 'second', '[]')",
            vec![Uuid::new_v4().into(), w.org.into()],
        )
        .await;
        let (_, status) = weekly(&ctx, &w, None).await;
        assert_eq!(status, RunStatus::Done);
        let sent = mail.sent();
        let to: Vec<_> = sent.iter().map(|m| m.to.as_str()).collect();
        assert_eq!(to, ["boss@example.com"]);
        assert!(
            sent[0].subject.contains("weekly summary"),
            "{}",
            sent[0].subject
        );
        assert!(
            sent[0].text.contains("OpsAgent weekly report"),
            "{}",
            sent[0].text
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn non_member_mail_has_the_unsubscribe_link_and_members_do_not() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "lead@example.com").await;
        let mail = prepare(&ctx);
        let u = user(&ctx, "dev@example.com").await;
        let m = Pg::new(&ctx.db).add_member(w.org, u, Role::Member).await.unwrap();
        recipient(&ctx, &w, "dev@example.com", Some(m.id)).await;
        let outside = recipient(&ctx, &w, "client@example.com", None).await;
        recipient(&ctx, &w, "gone@example.com", None).await;
        sql(
            &ctx,
            "INSERT INTO email_suppressions (id, email_hash, reason) VALUES ($1, $2, 'unsubscribed')",
            vec![Uuid::new_v4().into(), email_hash("gone@example.com").into()],
        )
        .await;
        scan(&ctx, &w, Utc::now()).await;

        weekly(&ctx, &w, Some(w.conn)).await;
        let sent = mail.sent();
        let to: Vec<_> = sent.iter().map(|m| m.to.as_str()).collect();
        assert_eq!(to, ["dev@example.com", "client@example.com"]);
        let s = opsagent_brain::app::state(&ctx).unwrap().config.clone();
        let url = unsubscribe_url(&s.web_base_url, s.unsubscribe_key(), outside);
        assert!(sent[1].text.contains(&url), "{}", sent[1].text);
        assert!(sent[1].html.as_deref().unwrap().contains(&url));
        assert!(!sent[0].text.contains("nsubscribe"), "{}", sent[0].text);
        assert!(!sent[0].html.as_deref().unwrap().contains("nsubscribe"));
        let st: Vec<_> = rows(&ctx, &w)
            .await
            .into_iter()
            .map(|d| (d.target, d.status))
            .collect();
        assert!(
            st.contains(&("gone@example.com".into(), "suppressed".into())),
            "{st:?}"
        );
    })
    .await;
}

/// Org A's footer unsubscribes the address (a global `unsubscribed` row); it is a member of
/// org B (`w`), so B's member weekly and owner summary still reach it.
#[tokio::test]
#[serial]
async fn member_mail_ignores_an_unsubscribe_from_another_organisation() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "lead@example.com").await;
        let mail = prepare(&ctx);
        let a = Uuid::new_v4();
        sql(
            &ctx,
            "INSERT INTO organisations (id, name, slug) VALUES ($1, 'A', $2)",
            vec![a.into(), format!("a-{}", a.simple()).into()],
        )
        .await;
        let in_a = Uuid::new_v4();
        sql(
            &ctx,
            "INSERT INTO recipients (id, organisation_id, email, status) \
             VALUES ($1, $2, 'dev@example.com', 'active')",
            vec![in_a.into(), a.into()],
        )
        .await;
        let s = opsagent_brain::app::state(&ctx).unwrap().config.clone();
        let token = unsubscribe_token(s.unsubscribe_key(), in_a);
        let unsubscribe = &actions(&ctx).unwrap().recipients.unsubscribe;
        unsubscribe.run(&token).await.unwrap();
        let u = user(&ctx, "dev@example.com").await;
        let m = Pg::new(&ctx.db)
            .add_member(w.org, u, Role::Member)
            .await
            .unwrap();
        recipient(&ctx, &w, "dev@example.com", Some(m.id)).await;
        scan(&ctx, &w, Utc::now()).await;

        weekly(&ctx, &w, Some(w.conn)).await;
        let to: Vec<_> = mail.sent().iter().map(|m| m.to.clone()).collect();
        assert_eq!(to, ["dev@example.com"]);
    })
    .await;
}

/// Only `unsubscribed` is waived for members: any other suppression still blocks them.
#[tokio::test]
#[serial]
async fn other_suppressions_still_block_a_member() {
    serve(|req, ctx| async move {
        let w = world(&req, &ctx, "lead@example.com").await;
        let mail = prepare(&ctx);
        let u = user(&ctx, "dev@example.com").await;
        let m = Pg::new(&ctx.db)
            .add_member(w.org, u, Role::Member)
            .await
            .unwrap();
        recipient(&ctx, &w, "dev@example.com", Some(m.id)).await;
        // shortcut: no bounce reason exists yet (CHECK allows unsubscribed/ignored/confirm_blocked),
        // so `ignored` stands in; add a bounce case when bounces are recorded.
        sql(
            &ctx,
            "INSERT INTO email_suppressions (id, organisation_id, email_hash, reason, expires_at) \
             VALUES ($1, $2, $3, 'ignored', now() + interval '1 day')",
            vec![
                Uuid::new_v4().into(),
                w.org.into(),
                email_hash("dev@example.com").into(),
            ],
        )
        .await;
        scan(&ctx, &w, Utc::now()).await;

        weekly(&ctx, &w, Some(w.conn)).await;
        assert!(mail.sent().is_empty());
        let st: Vec<_> = rows(&ctx, &w)
            .await
            .into_iter()
            .map(|d| (d.target, d.status))
            .collect();
        assert!(
            st.contains(&("dev@example.com".into(), "suppressed".into())),
            "{st:?}"
        );
    })
    .await;
}
