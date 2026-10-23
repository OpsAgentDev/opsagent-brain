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
