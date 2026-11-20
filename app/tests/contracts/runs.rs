use chrono::{DateTime, Duration, TimeZone, Utc};
use opsagent_brain::actions::uow::Repos;
use opsagent_core::{
    repo::PageRequest,
    run::{RunFilter, RunKey, RunStatus},
};
use uuid::Uuid;

use super::{
    connections::{connection, org},
    contract_suite,
};

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 22, 3, 0, 0).unwrap()
}

fn key(o: Uuid, c: Uuid, job: &str, at: DateTime<Utc>) -> RunKey {
    RunKey {
        organisation_id: Some(o),
        connection_id: Some(c),
        job_type: job.into(),
        scheduled_at: at,
    }
}

async fn run(s: &dyn Repos, k: RunKey) -> Uuid {
    s.ledger().create_run(k).await.unwrap().run.id
}

fn page(limit: u64) -> PageRequest {
    PageRequest { after: None, limit }
}

contract_suite! {
    async fn hold_fence_only_at_the_current_fence(s) {
        let o = org(s).await;
        let c = connection(s, o, "Prod").await;
        let id = run(s, key(o, c.id, "full_scan", t0())).await;
        let fence = s.ledger().bump_fence(id).await.unwrap();
        s.ledger().hold_fence(id, fence).await.unwrap();
        let err = s.ledger().hold_fence(id, fence - 1).await.unwrap_err();
        assert!(matches!(err, opsagent_ledger::LedgerError::StaleFence), "{err:?}");
    }

    async fn audit_recorded_for_run_matches_org_action_and_run(s) {
        use opsagent_core::audit::AuditEntry;
        let (o, other) = (org(s).await, org(s).await);
        let run_id = Uuid::new_v4();
        let action = "connection.scan_started";
        assert!(!s.audit().recorded_for_run(o, action, run_id).await.unwrap());
        let e = AuditEntry::system(o, action, ("connection", "c".into()), "success")
            .with_meta(serde_json::json!({ "run_id": run_id }));
        s.audit().record(e).await.unwrap();
        assert!(s.audit().recorded_for_run(o, action, run_id).await.unwrap());
        assert!(!s.audit().recorded_for_run(other, action, run_id).await.unwrap());
        assert!(!s.audit().recorded_for_run(o, "other", run_id).await.unwrap());
        assert!(!s.audit().recorded_for_run(o, action, Uuid::new_v4()).await.unwrap());
    }

    async fn audit_list_pages_one_organisation_newest_first(s) {
        use opsagent_core::audit::{Actor, AuditEntry};
        let (o, other) = (org(s).await, org(s).await);
        let user = Uuid::new_v4();
        let first = AuditEntry::member(Some(o), user, "a.first", Some(("connection", "c1".into())));
        s.audit().record(first).await.unwrap();
        s.audit().record(AuditEntry::member(Some(other), user, "theirs", None)).await.unwrap();
        s.audit().record(AuditEntry::member(None, user, "global", None)).await.unwrap();
        let second = AuditEntry::system(o, "a.second", ("run", "r".into()), "failed")
            .with_meta(serde_json::json!({ "code": "x" }));
        s.audit().record(second).await.unwrap();
        let grant = Uuid::new_v4();
        s.audit().record(AuditEntry::mcp_client(o, grant, "a.third", "success")).await.unwrap();

        let all = s.audit().list(o, page(50)).await.unwrap();
        let actions: Vec<_> = all.items.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(actions, ["a.third", "a.second", "a.first"]);
        assert!(all.next.is_none());
        assert_eq!(all.items[0].actor, Actor::McpClient(grant));
        assert_eq!(all.items[0].target, None);
        assert_eq!(all.items[1].actor, Actor::System);
        assert_eq!(all.items[1].outcome.as_deref(), Some("failed"));
        assert_eq!(all.items[1].meta, serde_json::json!({ "code": "x" }));
        assert_eq!(all.items[2].actor, Actor::Member(user));
        assert_eq!(all.items[2].target, Some(("connection".into(), "c1".into())));

        let one = s.audit().list(o, page(2)).await.unwrap();
        assert_eq!(one.items.len(), 2);
        let rest = PageRequest { after: one.next, limit: 2 };
        let two = s.audit().list(o, rest).await.unwrap();
        let got: Vec<_> = two.items.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(got, ["a.first"]);
        assert!(two.next.is_none());
    }

    async fn list_pages_newest_first_with_cursor(s) {
        let o = org(s).await;
        let c = connection(s, o, "Prod").await.id;
        let mut ids = Vec::new();
        for h in 0..3 {
            ids.push(run(s, key(o, c, "full_scan", t0() + Duration::hours(h))).await);
        }
        let first = s.runs().list(o, RunFilter::default(), page(2)).await.unwrap();
        let got: Vec<_> = first.items.iter().map(|r| r.id).collect();
        assert_eq!(got, [ids[2], ids[1]]);
        let after = PageRequest { after: first.next, limit: 2 };
        assert!(after.after.is_some());
        let second = s.runs().list(o, RunFilter::default(), after).await.unwrap();
        assert_eq!(second.items.iter().map(|r| r.id).collect::<Vec<_>>(), [ids[0]]);
        assert!(second.next.is_none());
        let r = s.runs().get(o, ids[0]).await.unwrap().unwrap();
        assert_eq!((r.status, r.attempts, r.scheduled_at), (RunStatus::Queued, 0, t0()));
        assert_eq!((r.connection_id, r.job_type.as_str()), (Some(c), "full_scan"));
        assert!(r.started_at.is_none() && r.finished_at.is_none());
        assert!(s.runs().get(org(s).await, ids[0]).await.unwrap().is_none());
    }

    async fn runs_list_filters_by_connection_and_job_type(s) {
        let o = org(s).await;
        let (c1, c2) = (connection(s, o, "A").await.id, connection(s, o, "B").await.id);
        let scan1 = run(s, key(o, c1, "full_scan", t0())).await;
        let verify1 = run(s, key(o, c1, "verify", t0())).await;
        run(s, key(o, c2, "full_scan", t0())).await;
        let ids = |f: RunFilter| async move {
            let mut v: Vec<_> = s.runs().list(o, f, page(10)).await.unwrap()
                .items.into_iter().map(|r| r.id).collect();
            v.sort();
            v
        };
        let mut both = vec![scan1, verify1];
        both.sort();
        let by_conn = RunFilter { connection_id: Some(c1), job_type: None };
        assert_eq!(ids(by_conn).await, both);
        let by_job = RunFilter { connection_id: None, job_type: Some("verify".into()) };
        assert_eq!(ids(by_job).await, [verify1]);
        let by_both = RunFilter { connection_id: Some(c1), job_type: Some("full_scan".into()) };
        assert_eq!(ids(by_both).await, [scan1]);
        assert_eq!(ids(RunFilter::default()).await.len(), 3);
        let other = s.runs().list(org(s).await, RunFilter::default(), page(10)).await.unwrap();
        assert!(other.items.is_empty());
    }

    async fn completed_full_scan_needs_a_done_or_partial_full_scan(s) {
        let o = org(s).await;
        let (c1, c2) = (connection(s, o, "A").await.id, connection(s, o, "B").await.id);
        let end = |id: Uuid, status: RunStatus| async move {
            let fence = s.ledger().bump_fence(id).await.unwrap();
            s.ledger().set_status(id, fence, status, None).await.unwrap();
        };
        let failed = run(s, key(o, c1, "full_scan", t0())).await;
        end(failed, RunStatus::Failed).await;
        end(run(s, key(o, c1, "watch_scan", t0())).await, RunStatus::Done).await;
        end(run(s, key(o, c2, "full_scan", t0())).await, RunStatus::Done).await;
        run(s, key(o, c1, "full_scan", t0() + Duration::hours(1))).await; // still queued
        assert!(!s.runs().completed_full_scan(o, c1).await.unwrap());
        end(run(s, key(o, c1, "full_scan", t0() + Duration::hours(2))).await, RunStatus::Partial).await;
        assert!(s.runs().completed_full_scan(o, c1).await.unwrap());
        assert!(!s.runs().completed_full_scan(org(s).await, c1).await.unwrap());
    }

    async fn failed_scan_streak_counts_failed_nightly_full_scans_since_the_last_ended_one(s) {
        let o = org(s).await;
        let (c1, c2) = (connection(s, o, "A").await.id, connection(s, o, "B").await.id);
        let end = |job: &'static str, c: Uuid, at: DateTime<Utc>, status: RunStatus| async move {
            let id = run(s, key(o, c, job, at)).await;
            let fence = s.ledger().bump_fence(id).await.unwrap();
            s.ledger().set_status(id, fence, status, None).await.unwrap();
        };
        let night = |n: i64| t0() + Duration::days(n);
        // Asked for by hand: never on a whole minute.
        let manual = |n: i64| night(n) + Duration::microseconds(41_000_001);
        let streak = || async { s.runs().failed_scan_streak(o, c1).await.unwrap() };
        assert_eq!(streak().await, None);
        end("full_scan", c1, night(0), RunStatus::Done).await;
        assert_eq!(streak().await, None);
        end("full_scan", c1, night(1), RunStatus::Failed).await;
        assert_eq!(streak().await, Some((1, night(1))));
        // Not this connection's nightly full scans: manual, skipped, queued, other job, other connection.
        end("full_scan", c1, manual(1), RunStatus::Failed).await;
        end("full_scan", c1, manual(2), RunStatus::Done).await;
        end("full_scan", c1, night(2), RunStatus::Skipped).await;
        run(s, key(o, c1, "full_scan", night(3))).await;
        end("watch_scan", c1, night(4), RunStatus::Done).await;
        end("full_scan", c2, night(4), RunStatus::Done).await;
        assert_eq!(streak().await, Some((1, night(1))));
        end("full_scan", c1, night(5), RunStatus::Failed).await;
        end("full_scan", c1, night(6), RunStatus::Failed).await;
        assert_eq!(streak().await, Some((3, night(1))));
        assert_eq!(s.runs().failed_scan_streak(org(s).await, c1).await.unwrap(), None);
        assert_eq!(s.runs().failed_scan_streak(o, c2).await.unwrap(), None);
        // A partial night ends the streak, as a done one does.
        end("full_scan", c1, night(7), RunStatus::Partial).await;
        assert_eq!(streak().await, None);
        end("full_scan", c1, night(8), RunStatus::Failed).await;
        assert_eq!(streak().await, Some((1, night(8))));
    }

    async fn last_manual_scan_counts_only_this_connections_full_scans(s) {
        let o = org(s).await;
        let (c1, c2) = (connection(s, o, "A").await.id, connection(s, o, "B").await.id);
        assert_eq!(s.runs().last_manual_scan(o, c1).await.unwrap(), None);
        run(s, key(o, c1, "verify", t0() + Duration::hours(5))).await;
        run(s, key(o, c2, "full_scan", t0() + Duration::hours(5))).await;
        assert_eq!(s.runs().last_manual_scan(o, c1).await.unwrap(), None);
        run(s, key(o, c1, "full_scan", t0())).await;
        run(s, key(o, c1, "full_scan", t0() + Duration::hours(1))).await;
        let last = s.runs().last_manual_scan(o, c1).await.unwrap();
        assert_eq!(last, Some(t0() + Duration::hours(1)));
        assert_eq!(s.runs().last_manual_scan(org(s).await, c1).await.unwrap(), None);
    }

    async fn ledger_create_run_on_tx_invisible_until_commit(s) {
        let o = org(s).await;
        let c = connection(s, o, "Prod").await.id;
        let tx = s.begin().await.unwrap();
        let dropped = run(tx.as_ref(), key(o, c, "full_scan", t0())).await;
        assert!(tx.runs().get(o, dropped).await.unwrap().is_some());
        drop(tx);
        assert!(s.runs().get(o, dropped).await.unwrap().is_none());
        let tx = s.begin().await.unwrap();
        let kept = run(tx.as_ref(), key(o, c, "full_scan", t0())).await;
        tx.commit().await.unwrap();
        assert!(s.runs().get(o, kept).await.unwrap().is_some());
    }
}
