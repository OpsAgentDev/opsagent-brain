//! A scan that finds the role gone starts the verification, so the denial rule (PRD 7.2: three
//! denials over at least an hour) runs its course without waiting for the weekly verify.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Duration, Utc};
use opsagent_brain::{
    actions::Actions,
    adapters::db::ledger_storage::{stmt, PgStorage},
    boot,
    models::_entities::{connections, runs},
};
use opsagent_core::{repo::Clock, run::RunKey};
use opsagent_ledger::{retry::backoff, RunChunkedOptions, Storage};
use sea_orm::{entity::prelude::*, ConnectionTrait, QueryOrder};
use serial_test::serial;
use uuid::Uuid;

use super::{
    full_scan::{noisy, rigged, scan, Fault},
    verify::set_fixture,
};
use crate::requests::support::*;

/// A clock the test moves.
struct Stepped(Mutex<DateTime<Utc>>);

impl Clock for Stepped {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

/// 10:15: three more watch scans fall in this hour, the fourth opens the next.
fn start() -> DateTime<Utc> {
    "2030-01-01T10:15:00Z".parse().unwrap()
}

/// The app's actions on a clock at `start()`. Their jobs are due in 2030, so the test's
/// worker never takes one: the test runs each action itself.
fn stepped(ctx: &TestApp) -> (Actions, Arc<Stepped>) {
    let clock = Arc::new(Stepped(Mutex::new(start())));
    let mut deps = ctx.state.deps.clone();
    deps.clock = clock.clone();
    (boot::build_actions(&deps, &ctx.state.oauth_urls), clock)
}

async fn status(ctx: &TestApp, conn: Uuid) -> String {
    let c = connections::Entity::find_by_id(conn).one(&ctx.db).await;
    c.unwrap().unwrap().status
}

/// The connection's runs of `job`, oldest slot first.
async fn runs_of(ctx: &TestApp, conn: Uuid, job: &str) -> Vec<runs::Model> {
    runs::Entity::find()
        .filter(runs::Column::ConnectionId.eq(conn))
        .filter(runs::Column::JobType.eq(job))
        .order_by_asc(runs::Column::ScheduledAt)
        .all(&ctx.db)
        .await
        .unwrap()
}

/// Runs one `job` scan (slot `at`) against a role that `fault`s; returns (status, reason).
async fn scan_at(
    ctx: &TestApp,
    acts: &Actions,
    conn: Uuid,
    (job, fault): (&str, Fault),
    at: DateTime<Utc>,
) -> (String, Option<String>) {
    let c = connections::Entity::find_by_id(conn).one(&ctx.db).await;
    let key = RunKey {
        organisation_id: Some(c.unwrap().unwrap().organisation_id),
        connection_id: Some(conn),
        job_type: job.into(),
        scheduled_at: at,
    };
    let run = PgStorage::new(ctx.db.clone()).create_run(key).await;
    let run = run.unwrap().run.id;
    let fs = match job {
        "watch_scan" => acts.runs.watch_scan.clone(),
        _ => acts.runs.full_scan.clone(),
    };
    fs.with_connector(Arc::new(rigged(Some(fault))))
        .run(run, RunChunkedOptions::default())
        .await
        .unwrap();
    let r = runs::Entity::find_by_id(run).one(&ctx.db).await;
    let r = r.unwrap().unwrap();
    (r.status, r.partial_reason)
}

async fn jobs_for(ctx: &TestApp, run: Uuid) -> i64 {
    let q = stmt(
        "SELECT count(*) AS n FROM jobs WHERE run_id = $1",
        vec![run.into()],
    );
    let row = ctx.db.query_one_raw(q).await.unwrap().unwrap();
    row.try_get("", "n").unwrap()
}

#[tokio::test]
#[serial]
async fn scans_that_end_revoked_queue_one_verify() {
    serve(|req, ctx| async move {
        let conn = connected(&req, &ctx, "o@example.com", "noisy").await.2;
        // The baseline full scan a watch scan waits for.
        scan(&ctx, conn, 0, &noisy()).await;
        assert!(runs_of(&ctx, conn, "verify").await.is_empty());
        let (acts, _) = stepped(&ctx);
        let revoked = ("partial".to_owned(), Some("revoked".to_owned()));
        // Refused at discovery (watch and full), then in the middle of a full scan.
        let scans = [
            (("watch_scan", Fault::Gone), 0),
            (("full_scan", Fault::Gone), 1),
            (("full_scan", Fault::Denied), 2),
            (("watch_scan", Fault::Gone), 15),
        ];
        for (which, mins) in scans {
            let at = start() + Duration::minutes(mins);
            assert_eq!(scan_at(&ctx, &acts, conn, which, at).await, revoked);
            let verifies = runs_of(&ctx, conn, "verify").await;
            assert_eq!(verifies.len(), 1, "{} +{mins}", which.0);
            assert_eq!(verifies[0].status, "queued");
            assert_eq!(jobs_for(&ctx, verifies[0].id).await, 1);
        }
        assert_eq!(status(&ctx, conn).await, "connected");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn role_gone_is_revoked_after_three_denials_over_an_hour() {
    serve(|req, ctx| async move {
        let conn = connected(&req, &ctx, "o@example.com", "noisy").await.2;
        scan(&ctx, conn, 0, &noisy()).await;
        // The customer deletes the stack: scans and verifications are refused from now on.
        set_fixture(&ctx, conn, "denied").await;
        let (acts, clock) = stepped(&ctx);
        // Minute by minute as production does it: a watch scan every 15 minutes, and each
        // verify run retried on the ledger's backoff (1, 5, 15, 60 minutes).
        let (mut retry_at, mut revoked_at) = (HashMap::new(), None);
        for min in 0..=120 {
            let now = start() + Duration::minutes(min);
            *clock.0.lock().unwrap() = now;
            if min % 15 == 0 {
                let (st, reason) =
                    scan_at(&ctx, &acts, conn, ("watch_scan", Fault::Gone), now).await;
                match revoked_at {
                    None => assert_eq!(
                        (st.as_str(), reason.as_deref()),
                        ("partial", Some("revoked"))
                    ),
                    Some(_) => assert_eq!(
                        (st.as_str(), reason.as_deref()),
                        ("skipped", Some("status:revoked"))
                    ),
                }
            }
            for v in runs_of(&ctx, conn, "verify").await {
                if v.status != "queued" || retry_at.get(&v.id).is_some_and(|at| *at > min) {
                    continue;
                }
                acts.runs.verify_connection.run(v.id).await.unwrap();
                let after = runs::Entity::find_by_id(v.id).one(&ctx.db).await;
                let after = after.unwrap().unwrap();
                if after.status == "queued" {
                    let wait = backoff(after.attempts as u32 - 1).unwrap().as_secs() / 60;
                    retry_at.insert(v.id, min + wait as i64);
                }
            }
            let revoked = status(&ctx, conn).await == "revoked";
            assert!(!revoked || min >= 60, "revoked after {min} minutes");
            if revoked && revoked_at.is_none() {
                revoked_at = Some(min);
            }
        }
        // 10:15 denials at +0, +1, +6, +21; the 11:00 scan's verify at +45, +46, +51 and +66,
        // the first denial an hour after the first.
        assert_eq!(revoked_at, Some(66));
        let verifies = runs_of(&ctx, conn, "verify").await;
        assert_eq!(verifies.len(), 2, "one verify per hour of failing scans");
        assert!(verifies.iter().all(|v| v.status == "done"), "{verifies:?}");
        // Owners are told once.
        assert_eq!(runs_of(&ctx, conn, "deliver_revoked_notice").await.len(), 1);
    })
    .await;
}
