//! Three failed nightly scans mark a connection degraded and mail its owners once (launch
//! readiness K3).
use chrono::{DateTime, Duration, Utc};
use opsagent_brain::{
    adapters::db::{ledger_storage::PgStorage, Pg},
    mailers::{CaptureMailer, Mail},
    models::_entities::{connections, runs},
};
use opsagent_connectors::Connector;
use opsagent_core::{
    org::{OrganisationsRepo, Role},
    run::RunKey,
};
use opsagent_ledger::{RunChunkedOptions, Storage};
use sea_orm::entity::prelude::*;
use serde_json::Value;
use serial_test::serial;
use uuid::Uuid;

use super::{
    deliver_briefing::sql,
    full_scan::{full_scan, noisy, rigged, Fault, Shared},
};
use crate::requests::support::*;

const SUBJECT: &str = "OpsAgent could not finish its last three nightly scans";

/// 02:00 on night `n`: a schedule slot, as the scheduler keys a nightly scan.
fn night(n: i64) -> DateTime<Utc> {
    "2026-11-01T02:00:00Z".parse::<DateTime<Utc>>().unwrap() + Duration::days(n)
}

/// A scan asked for by hand on day `n`: keyed at that instant, never on a slot.
fn manual(n: i64) -> DateTime<Utc> {
    night(n) + Duration::hours(9) + Duration::microseconds(1_234_567)
}

async fn conn(ctx: &TestApp, id: Uuid) -> connections::Model {
    let c = connections::Entity::find_by_id(id).one(&ctx.db).await;
    c.unwrap().unwrap()
}

/// Runs a full scan of `id` scheduled at `at` with connector `k`; the run's final status.
async fn scan_at(ctx: &TestApp, id: Uuid, at: DateTime<Utc>, k: &impl Shared) -> String {
    let key = RunKey {
        organisation_id: Some(conn(ctx, id).await.organisation_id),
        connection_id: Some(id),
        job_type: "full_scan".into(),
        scheduled_at: at,
    };
    let run = PgStorage::new(ctx.db.clone()).create_run(key).await;
    let run = run.unwrap().run.id;
    let scan = full_scan(ctx, k);
    let opts = RunChunkedOptions::default();
    scan.run(run, opts).await.unwrap();
    let row = runs::Entity::find_by_id(run).one(&ctx.db).await;
    row.unwrap().unwrap().status
}

/// A scan that ends `failed` at once (a non-retryable discovery error).
fn failing() -> impl Connector + Clone + 'static {
    rigged(Some(Fault::Discovery("ValidationError")))
}

fn state(c: &connections::Model) -> (&str, Option<&str>) {
    (c.status.as_str(), c.status_reason.as_deref())
}

fn notices(mail: &CaptureMailer) -> Vec<Mail> {
    let sent = mail.sent().into_iter();
    sent.filter(|m| m.subject == SUBJECT).collect()
}

#[tokio::test]
#[serial]
async fn three_failed_nights_degrade_and_mail_each_owner_once() {
    serve(|req, ctx| async move {
        let (_, org, id) = connected(&req, &ctx, "o@example.com", "noisy").await;
        // A second owner: each owner gets the mail.
        let second = Uuid::new_v4();
        let user = "INSERT INTO users (id, email) VALUES ($1, 'p@example.com')";
        sql(&ctx, user, vec![second.into()]).await;
        let org_id = conn(&ctx, id).await.organisation_id;
        let orgs = Pg::new(&ctx.db);
        let added = orgs.add_member(org_id, second, Role::Owner).await;
        added.unwrap();
        let mail = prepare(&ctx);

        // Two failures do nothing.
        for n in 0..2 {
            assert_eq!(scan_at(&ctx, id, night(n), &failing()).await, "failed");
            assert_eq!(state(&conn(&ctx, id).await), ("connected", None), "night {n}");
        }
        ctx.drain_jobs().await;
        assert!(notices(&mail).is_empty());

        // The third degrades the connection and mails each owner once.
        assert_eq!(scan_at(&ctx, id, night(2), &failing()).await, "failed");
        let c = conn(&ctx, id).await;
        assert_eq!(state(&c), ("degraded", Some("scans_failing")));
        ctx.drain_jobs().await;
        let sent = notices(&mail);
        let mut to: Vec<_> = sent.iter().map(|m| m.to.as_str()).collect();
        to.sort_unstable();
        assert_eq!(to, ["o@example.com", "p@example.com"]);
        let link = format!("/o/{org}/connections/{id}");
        let name = c.display_name.clone().unwrap();
        let text = format!(
            "OpsAgent could not finish its last three nightly scans of {name}. Your findings \
             may be out of date. We are looking into it; you do not need to do anything."
        );
        for m in &sent {
            assert!(m.text.starts_with(&text), "{}", m.text);
            assert!(m.text.ends_with(&link), "{}", m.text);
            // The button to the connection.
            let html = m.html.as_deref().unwrap();
            assert!(html.contains(&link) && html.contains("Open connection"), "{html}");
        }
        // The API reports the state the dashboard explains.
        let got = req.get(&format!("/v1/orgs/{org}/connections/{id}")).await;
        let got = got.json::<Value>();
        assert_eq!((&got["status"], &got["status_reason"]), (&"degraded".into(), &"scans_failing".into()));

        // A fourth failure sends nothing more: one notice run for the streak.
        assert_eq!(scan_at(&ctx, id, night(3), &failing()).await, "failed");
        ctx.drain_jobs().await;
        assert_eq!(notices(&mail).len(), 2);
        assert_eq!(state(&conn(&ctx, id).await), ("degraded", Some("scans_failing")));
        let runs = runs::Entity::find()
            .filter(runs::Column::JobType.eq("deliver_scans_failing_notice"))
            .all(&ctx.db)
            .await
            .unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, "done");
        // A replayed notice run mails nobody: each owner's mail is one ledger effect.
        let again = "UPDATE runs SET status = 'queued', \
                     checkpoint = '{\"chunks_done\": [], \"cursor\": null, \"stats\": {}}' WHERE id = $1";
        sql(&ctx, again, vec![runs[0].id.into()]).await;
        let notice = &actions(&ctx).unwrap().runs.deliver_revoked_notice;
        let replay = notice.run(runs[0].id, RunChunkedOptions::default());
        replay.await.unwrap();
        assert_eq!(notices(&mail).len(), 2);
        // The notice run stays out of the organisation's run history.
        let history = req.get(&format!("/v1/orgs/{org}/runs")).await.text();
        assert!(!history.contains("deliver_scans_failing_notice"), "{history}");

        // A done manual scan does not restore it; the next done night does, clearing the reason.
        assert_eq!(scan_at(&ctx, id, manual(4), &noisy()).await, "done");
        assert_eq!(state(&conn(&ctx, id).await), ("degraded", Some("scans_failing")));
        assert_eq!(scan_at(&ctx, id, night(4), &noisy()).await, "done");
        assert_eq!(state(&conn(&ctx, id).await), ("connected", None));
        ctx.drain_jobs().await;
        assert_eq!(notices(&mail).len(), 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn manual_and_skipped_runs_do_not_count() {
    serve(|req, ctx| async move {
        let (_, _, id) = connected(&req, &ctx, "o@example.com", "noisy").await;
        let mail = prepare(&ctx);
        assert_eq!(scan_at(&ctx, id, night(0), &failing()).await, "failed");
        assert_eq!(scan_at(&ctx, id, night(1), &failing()).await, "failed");
        // Failed manual scans do not make it three.
        assert_eq!(scan_at(&ctx, id, manual(1), &failing()).await, "failed");
        assert_eq!(scan_at(&ctx, id, manual(2), &failing()).await, "failed");
        // Nor does a skipped night (the connection was blocked that night).
        let set = "UPDATE connections SET status = $2 WHERE id = $1";
        sql(&ctx, set, vec![id.into(), "blocked".into()]).await;
        assert_eq!(scan_at(&ctx, id, night(2), &failing()).await, "skipped");
        sql(&ctx, set, vec![id.into(), "connected".into()]).await;
        assert_eq!(state(&conn(&ctx, id).await), ("connected", None));
        // A done manual scan does not break the streak: the next failed night is the third.
        assert_eq!(scan_at(&ctx, id, manual(3), &noisy()).await, "done");
        assert_eq!(scan_at(&ctx, id, night(3), &failing()).await, "failed");
        assert_eq!(
            state(&conn(&ctx, id).await),
            ("degraded", Some("scans_failing"))
        );
        ctx.drain_jobs().await;
        assert_eq!(notices(&mail).len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn a_revoked_connection_is_left_alone() {
    serve(|req, ctx| async move {
        let (_, _, id) = connected(&req, &ctx, "o@example.com", "noisy").await;
        let mail = prepare(&ctx);
        assert_eq!(scan_at(&ctx, id, night(0), &failing()).await, "failed");
        assert_eq!(scan_at(&ctx, id, night(1), &failing()).await, "failed");
        let revoke = "UPDATE connections SET status = 'revoked', status_reason = 'access_denied' \
                      WHERE id = $1";
        sql(&ctx, revoke, vec![id.into()]).await;
        // Its scans are skipped, so no third failure is counted and nothing about it changes.
        assert_eq!(scan_at(&ctx, id, night(2), &failing()).await, "skipped");
        assert_eq!(
            state(&conn(&ctx, id).await),
            ("revoked", Some("access_denied"))
        );
        ctx.drain_jobs().await;
        assert!(notices(&mail).is_empty());
    })
    .await;
}
