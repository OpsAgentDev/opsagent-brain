use chrono::{DateTime, Duration, Utc};
use opsagent_brain::actions::uow::Repos;
use opsagent_core::{
    connection::{NewConnection, SealedCreds},
    finding::{Evidence, FindingDraft, FindingKey, Severity},
    repo::{PageRequest, RepoError},
    run::{RunKey, RunStatus},
};
use opsagent_deliver::{
    model::{EventKind, FindingStatus},
    repo::{DeliveryFilter, NewDelivery, BRIEFING, FAILED, SENT, WEEKLY},
};
use uuid::Uuid;

use super::{contract_suite, org_id};

async fn connection(s: &dyn Repos, org: Uuid) -> Uuid {
    let new = NewConnection {
        organisation_id: org,
        provider: "aws".into(),
        display_name: "Prod".into(),
        template_version: None,
        credential_kind: "aws_role".into(),
    };
    let creds = SealedCreds {
        ciphertext: vec![1; 8],
        nonce: vec![1; 12],
        kek_version: 1,
    };
    s.connections().insert(new, creds).await.unwrap().id
}

/// A full-scan run that ended `status`.
async fn scan_run(
    s: &dyn Repos,
    org: Uuid,
    conn: Uuid,
    at: DateTime<Utc>,
    status: RunStatus,
) -> Uuid {
    let key = RunKey {
        organisation_id: Some(org),
        connection_id: Some(conn),
        job_type: "full_scan".into(),
        scheduled_at: at,
    };
    let id = s.ledger().create_run(key).await.unwrap().run.id;
    let fence = s.ledger().bump_fence(id).await.unwrap();
    let reason = (status == RunStatus::Partial).then(|| "some_service".to_owned());
    s.ledger()
        .set_status(id, fence, status, reason)
        .await
        .unwrap();
    id
}

fn draft(conn: Uuid, check: &str, severity: Severity) -> FindingDraft {
    FindingDraft {
        key: FindingKey {
            connection_id: conn,
            check_id: check.into(),
            resource_identity: "r".into(),
            variant: String::new(),
        },
        severity,
        title: format!("{check} title"),
        summary: "s".into(),
        next_step: "n".into(),
        cost_monthly_usd: None,
        evidence: vec![Evidence {
            source: "src".into(),
            excerpt: "ex".into(),
        }],
    }
}

const PAGE: PageRequest = PageRequest {
    after: None,
    limit: 10,
};

fn row<'a>(
    conn: Option<Uuid>,
    run: Uuid,
    key: &'a str,
    kind: &'a str,
    status: &'a str,
) -> NewDelivery<'a> {
    NewDelivery {
        connection_id: conn,
        run_id: run,
        key,
        kind,
        channel: "email",
        target: "a@example.com",
        status,
        external_ref: None,
    }
}

contract_suite! {
    async fn snapshots_count_open_score_scans_and_window_events(s) {
        let o = org_id(s, "acme").await;
        let c = connection(s, o).await;
        let now = Utc::now();
        let (t0, since) = (now - Duration::days(2), now - Duration::days(1));
        let (open, early, late) = (
            draft(c, "open_high", Severity::High),
            draft(c, "resolved_early", Severity::Medium),
            draft(c, "resolved_late", Severity::Critical),
        );
        let f = s.findings();
        let r1 = scan_run(s, o, c, t0, RunStatus::Done).await;
        f.upsert_seen(o, c, r1, &[open.clone(), early, late.clone()], t0).await.unwrap();
        // Resolved before the window: no event since `since`.
        let r2 = scan_run(s, o, c, t0 + Duration::hours(1), RunStatus::Done).await;
        f.upsert_seen(o, c, r2, &[open.clone(), late], t0 + Duration::hours(1)).await.unwrap();
        f.resolve_unseen(o, c, r2, &[], t0 + Duration::hours(1)).await.unwrap();
        // Resolved inside the window, by the last (partial) scan.
        let r3 = scan_run(s, o, c, now, RunStatus::Partial).await;
        f.upsert_seen(o, c, r3, &[open], now).await.unwrap();
        f.resolve_unseen(o, c, r3, &[], now).await.unwrap();

        let d = s.deliveries();
        let snap = d.connection_snapshot(o, c).await.unwrap();
        assert_eq!((snap.id, snap.display_name.as_str()), (c, "Prod"));
        let counts = snap.counts_by_severity;
        assert_eq!((counts.critical, counts.high, counts.medium), (0, 1, 0));
        assert_eq!(snap.posture_score, Some(f64::from(100.0 - Severity::High.weight())));
        let (first, last) = (snap.first_scan_at.unwrap(), snap.last_scan_at.unwrap());
        assert!(first <= last, "{first} > {last}");
        assert!(snap.partial, "the latest scan ended partial");

        let mut got = d.finding_snapshots(o, c, since).await.unwrap();
        got.sort_by(|a, b| a.key.check_id.cmp(&b.key.check_id));
        let ids: Vec<_> = got.iter().map(|f| (f.key.check_id.as_str(), f.status)).collect();
        assert_eq!(
            ids,
            [("open_high", FindingStatus::Open), ("resolved_late", FindingStatus::Resolved)]
        );
        assert!(got[1].events_since.contains(&EventKind::Resolved), "{:?}", got[1].events_since);
        assert!(!got[0].events_since.contains(&EventKind::Resolved));

        let other = org_id(s, "other").await;
        let err = d.connection_snapshot(other, c).await.unwrap_err();
        assert!(matches!(err, RepoError::NotFound), "{err:?}");
        assert!(d.finding_snapshots(other, c, since).await.unwrap().is_empty());
    }

    async fn delivery_record_is_idempotent_on_run_and_key(s) {
        let o = org_id(s, "acme").await;
        let (d, run) = (s.deliveries(), Uuid::new_v4());
        d.record(o, row(None, run, "weekly:1", WEEKLY, FAILED)).await.unwrap();
        let first = d.list(o, DeliveryFilter::default(), PAGE).await.unwrap().items;
        assert_eq!((first.len(), first[0].status.as_str(), first[0].sent_at), (1, FAILED, None));
        d.record(o, row(None, run, "weekly:1", WEEKLY, SENT)).await.unwrap();
        let got = d.list(o, DeliveryFilter::default(), PAGE).await.unwrap().items;
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].id, got[0].status.as_str(), got[0].attempts), (first[0].id, SENT, 2));
        let sent = got[0].sent_at.expect("sent_at set");
        // A later rewrite keeps the first send time.
        d.record(o, row(None, run, "weekly:1", WEEKLY, SENT)).await.unwrap();
        assert_eq!(d.get(o, got[0].id).await.unwrap().unwrap().sent_at, Some(sent));
        d.record(o, row(None, run, "weekly:2", WEEKLY, SENT)).await.unwrap();
        d.record(o, row(None, Uuid::new_v4(), "weekly:1", WEEKLY, SENT)).await.unwrap();
        assert_eq!(d.list(o, DeliveryFilter::default(), PAGE).await.unwrap().items.len(), 3);
    }

    async fn deliveries_cross_org_get_is_none(s) {
        let (a, b) = (org_id(s, "a").await, org_id(s, "b").await);
        let d = s.deliveries();
        let run = Uuid::new_v4();
        d.record(a, row(None, run, "k", WEEKLY, SENT)).await.unwrap();
        let id = d.list(a, DeliveryFilter::default(), PAGE).await.unwrap().items[0].id;
        // Another organisation cannot rewrite the row of the same (run, key).
        d.record(b, row(None, run, "k", WEEKLY, FAILED)).await.unwrap();
        let kept = d.get(a, id).await.unwrap().unwrap();
        assert_eq!((kept.status.as_str(), kept.attempts), (SENT, 1));
        assert!(d.get(a, id).await.unwrap().is_some());
        assert!(d.get(b, id).await.unwrap().is_none());
        assert!(d.list(b, DeliveryFilter::default(), PAGE).await.unwrap().items.is_empty());
        let briefings = DeliveryFilter { kind: Some(BRIEFING.into()), ..Default::default() };
        assert!(d.list(a, briefings, PAGE).await.unwrap().items.is_empty());
    }

    async fn last_success_at_respects_before(s, seed) {
        let o = org_id(s, "acme").await;
        let c = seed.connection(o).await;
        let d = s.deliveries();
        let later = Utc::now() + Duration::hours(1);
        d.record(o, row(Some(c), Uuid::new_v4(), "briefing", BRIEFING, FAILED)).await.unwrap();
        d.record(o, row(Some(c), Uuid::new_v4(), "weekly", WEEKLY, SENT)).await.unwrap();
        assert_eq!(d.last_success_at(o, c, BRIEFING, later).await.unwrap(), None);
        d.record(o, row(Some(c), Uuid::new_v4(), "briefing", BRIEFING, SENT)).await.unwrap();
        let t = d.last_success_at(o, c, BRIEFING, later).await.unwrap().expect("sent");
        assert_eq!(d.last_success_at(o, c, BRIEFING, t).await.unwrap(), None);
        let other = org_id(s, "other").await;
        assert_eq!(d.last_success_at(other, c, BRIEFING, later).await.unwrap(), None);
        let mine = DeliveryFilter { connection_id: Some(c), kind: Some(BRIEFING.into()) };
        assert_eq!(d.list(o, mine, PAGE).await.unwrap().items.len(), 2);
    }

    async fn alert_tally_counts_individual_alerts_rollups_and_the_baseline(s) {
        let o = org_id(s, "acme").await;
        let c = connection(s, o).await;
        let l = s.ledger();
        let run = |at: DateTime<Utc>, job: &str| RunKey {
            organisation_id: Some(o),
            connection_id: Some(c),
            job_type: job.into(),
            scheduled_at: at,
        };
        let now = Utc::now();
        let done = |r: Uuid, key: String| async move {
            l.effect_begin(r, &key).await.unwrap();
            l.effect_done(r, &key, None).await.unwrap();
        };
        let a = l.create_run(run(now, "deliver_alert")).await.unwrap().run.id;
        let b = l.create_run(run(now + Duration::seconds(1), "deliver_alert")).await.unwrap().run.id;
        let (f1, f2) = (Uuid::new_v4(), Uuid::new_v4());
        done(a, format!("alert:{f1}")).await;
        done(a, format!("alert:{f2}")).await;
        done(b, format!("alert:{}", Uuid::new_v4())).await;
        done(a, format!("alert:rollup:{a}")).await;
        // Started only, an inner send, and another job's effect don't count.
        l.effect_begin(a, &format!("alert:{}", Uuid::new_v4())).await.unwrap();
        done(a, format!("alert:{f1}:{}", Uuid::new_v4())).await;
        let brief = l.create_run(run(now, "deliver_briefing")).await.unwrap().run.id;
        done(brief, format!("alert:{f1}")).await;
        done(brief, "alert:baseline".into()).await;

        let d = s.deliveries();
        let since = now - Duration::hours(24);
        let t = d.alert_tally(o, c, a, since).await.unwrap();
        assert_eq!((t.since, t.this_run, t.baselined), (3, 2, false));
        assert!(t.last_rollup_at.is_some_and(|at| at >= since));
        done(b, "alert:baseline".into()).await;
        let later = Utc::now() + Duration::hours(1);
        let t = d.alert_tally(o, c, b, later).await.unwrap();
        assert_eq!((t.since, t.this_run, t.last_rollup_at, t.baselined), (0, 1, None, true));
        let other = org_id(s, "other").await;
        assert_eq!(d.alert_tally(other, c, a, since).await.unwrap(), Default::default());
    }
}
