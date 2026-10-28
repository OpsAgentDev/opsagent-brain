use chrono::{DateTime, Duration, Utc};
use opsagent_brain::actions::uow::Repos;
use opsagent_core::{
    finding::{
        Evidence, FindingDraft, FindingEvent, FindingFilter, FindingKey, PostureRow, Severity,
        StatusChange,
    },
    org::NewOrganisation,
    repo::{PageRequest, RepoError},
    resource::{Provider, Resource, ResourceKind},
};
use uuid::Uuid;

use super::{contract_suite, Seed};

/// An organisation with one connection.
async fn world(s: &dyn Repos, seed: &dyn Seed) -> (Uuid, Uuid) {
    let id = Uuid::new_v4();
    s.orgs()
        .insert(NewOrganisation {
            id,
            slug: format!("org-{}", id.simple()),
            name: "Org".into(),
            timezone: "UTC".into(),
            kek_version: 1,
            wrapped_dek: vec![1],
        })
        .await
        .unwrap();
    (id, seed.connection(id).await)
}

fn draft(conn: Uuid, check: &str, identity: &str, severity: Severity) -> FindingDraft {
    FindingDraft {
        key: FindingKey {
            connection_id: conn,
            check_id: check.into(),
            resource_identity: identity.into(),
            variant: String::new(),
        },
        severity,
        title: format!("{check} on {identity}"),
        summary: "s".into(),
        next_step: "n".into(),
        cost_monthly_usd: None,
        evidence: vec![Evidence {
            source: "src".into(),
            excerpt: "ex".into(),
        }],
    }
}

fn all() -> PageRequest {
    PageRequest {
        after: None,
        limit: 50,
    }
}

fn t(h: i64) -> DateTime<Utc> {
    "2026-10-22T12:00:00Z".parse::<DateTime<Utc>>().unwrap() + Duration::hours(h)
}

async fn scan(s: &dyn Repos, seed: &dyn Seed, org: Uuid, conn: Uuid, d: &[FindingDraft]) -> Uuid {
    let run = seed.run(org, conn).await;
    s.findings()
        .upsert_seen(org, conn, run, d, t(0))
        .await
        .unwrap();
    run
}

fn snooze(id: Uuid, from: &str) -> StatusChange {
    StatusChange {
        from_status: from.into(),
        status: "snoozed".into(),
        accepted_reason: None,
        accepted_until: None,
        snoozed_until: Some(t(48)),
        event: FindingEvent {
            finding_id: id,
            kind: "snoozed".into(),
            run_id: None,
            from_severity: Some(Severity::High),
            to_severity: Some(Severity::High),
            at: t(1),
        },
    }
}

contract_suite! {
    async fn alert_candidates_are_open_unalerted_criticals(s, seed) {
        let (org, conn) = world(s, seed).await;
        let other = seed.connection(org).await;
        let crit = |id: &str| draft(conn, "c", id, Severity::Critical);
        scan(s, seed, org, conn, &[
            crit("keep"), crit("accepted"), crit("snoozed"), crit("flapping"), crit("alerted"),
            draft(conn, "c", "high", Severity::High),
        ]).await;
        scan(s, seed, org, other, &[draft(other, "c", "elsewhere", Severity::Critical)]).await;
        let list = || async {
            s.findings().list(org, FindingFilter { connection_id: Some(conn), ..Default::default() }, all()).await.unwrap().items
        };
        let id_of = |items: &[opsagent_core::finding::Finding], name: &str| {
            items.iter().find(|f| f.key.resource_identity == name).unwrap().id
        };
        let items = list().await;
        for (name, status) in [("accepted", "accepted"), ("snoozed", "snoozed")] {
            let id = id_of(&items, name);
            let mut c = snooze(id, "open");
            c.status = status.into();
            s.findings().change_status(org, id, c).await.unwrap();
        }
        let id = id_of(&items, "flapping");
        let mut c = snooze(id, "open");
        c.status = "flapping".into();
        s.findings().change_status(org, id, c).await.unwrap();
        s.findings().mark_alerted(org, &[id_of(&items, "alerted")], t(0)).await.unwrap();
        let got = s.findings().alert_candidates(org, conn).await.unwrap();
        assert_eq!(got.iter().map(|f| f.key.resource_identity.as_str()).collect::<Vec<_>>(), ["keep"]);
        assert!(got[0].alerted_at.is_none());
    }

    async fn mark_alerted_is_org_scoped(s, seed) {
        let (org, conn) = world(s, seed).await;
        let (other_org, _) = world(s, seed).await;
        scan(s, seed, org, conn, &[draft(conn, "c", "a", Severity::Critical)]).await;
        let id = s.findings().alert_candidates(org, conn).await.unwrap()[0].id;
        s.findings().mark_alerted(other_org, &[id], t(5)).await.unwrap();
        assert_eq!(s.findings().get(org, id).await.unwrap().unwrap().alerted_at, None);
        s.findings().mark_alerted(org, &[id], t(5)).await.unwrap();
        assert_eq!(s.findings().get(org, id).await.unwrap().unwrap().alerted_at, Some(t(5)));
        assert!(s.findings().alert_candidates(org, conn).await.unwrap().is_empty());
    }

    async fn resolve_clears_alerted_at(s, seed) {
        let (org, conn) = world(s, seed).await;
        scan(s, seed, org, conn, &[draft(conn, "c", "a", Severity::Critical)]).await;
        let id = s.findings().alert_candidates(org, conn).await.unwrap()[0].id;
        s.findings().mark_alerted(org, &[id], t(0)).await.unwrap();
        let r2 = scan(s, seed, org, conn, &[]).await;
        s.findings().resolve_unseen(org, conn, r2, &[], t(1)).await.unwrap();
        let f = s.findings().get(org, id).await.unwrap().unwrap();
        assert_eq!((f.status.as_str(), f.alerted_at), ("resolved", None));
    }
    async fn upsert_seen_twice_keeps_one_row_and_bumps_last_seen(s, seed) {
        let (org, conn) = world(s, seed).await;
        let d = [draft(conn, "no_mfa", "user/a", Severity::High)];
        let r1 = scan(s, seed, org, conn, &d).await;
        let r2 = scan(s, seed, org, conn, &d).await;
        let page = s.findings().list(org, FindingFilter::default(), all()).await.unwrap();
        assert_eq!(page.items.len(), 1);
        let f = &page.items[0];
        assert_eq!((f.first_seen_run_id, f.last_seen_run_id), (Some(r1), Some(r2)));
        assert_eq!((f.status.as_str(), f.severity, f.key.clone()), ("open", Severity::High, d[0].key.clone()));
        let kinds: Vec<_> = s.findings().events(org, f.id).await.unwrap().into_iter().map(|e| (e.kind, e.run_id)).collect();
        assert_eq!(kinds, [("seen".to_string(), Some(r2)), ("opened".to_string(), Some(r1))]);
        let ev = s.findings().evidence(org, f.id).await.unwrap();
        assert_eq!(ev.len(), 2, "one evidence row per run");
        // Re-applying the same run changes nothing.
        s.findings().upsert_seen(org, conn, r2, &d, t(0)).await.unwrap();
        assert_eq!(s.findings().events(org, f.id).await.unwrap().len(), 2);
    }

    async fn resolve_unseen_only_named_checks_and_only_this_connection(s, seed) {
        let (org, a) = world(s, seed).await;
        let b = seed.connection(org).await;
        scan(s, seed, org, a, &[draft(a, "no_mfa", "u", Severity::High), draft(a, "old_key", "u", Severity::Low)]).await;
        scan(s, seed, org, b, &[draft(b, "no_mfa", "u", Severity::High)]).await;
        let r2 = scan(s, seed, org, a, &[]).await;
        // `old_key`'s capability was partial: it is exempt.
        let n = s.findings().resolve_unseen(org, a, r2, &["old_key".into()], t(1)).await.unwrap();
        assert_eq!(n, 1);
        let status = |conn: Uuid, check: &str| {
            let f = FindingFilter { connection_id: Some(conn), check_id: Some(check.into()), ..Default::default() };
            async move { s.findings().list(org, f, all()).await.unwrap().items.remove(0) }
        };
        let gone = status(a, "no_mfa").await;
        assert_eq!((gone.status.as_str(), gone.resolved_at), ("resolved", Some(t(1))));
        assert_eq!(status(a, "old_key").await.status, "open");
        assert_eq!(status(b, "no_mfa").await.status, "open");
        assert_eq!(s.findings().events(org, gone.id).await.unwrap()[0].kind, "resolved");
        // Already resolved: nothing more to do.
        assert_eq!(s.findings().resolve_unseen(org, a, r2, &["old_key".into()], t(1)).await.unwrap(), 0);
    }

    async fn upsert_seen_dedupes_drafts_by_key(s, seed) {
        let (org, conn) = world(s, seed).await;
        let low = draft(conn, "no_mfa", "u", Severity::Low);
        let mut high = draft(conn, "no_mfa", "u", Severity::High);
        high.evidence[0].excerpt = "second".into();
        scan(s, seed, org, conn, &[low, high]).await;
        let items = s.findings().list(org, FindingFilter::default(), all()).await.unwrap().items;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].severity, Severity::High);
        let mut ev: Vec<_> = s.findings().evidence(org, items[0].id).await.unwrap().into_iter().map(|e| e.excerpt).collect();
        ev.sort();
        assert_eq!(ev, ["ex", "second"]);
    }

    async fn resolve_unseen_resolves_removed_check_findings(s, seed) {
        let (org, conn) = world(s, seed).await;
        // Check "99" is not in any registry; a later full run must still resolve it.
        scan(s, seed, org, conn, &[draft(conn, "99", "u", Severity::Medium)]).await;
        let seen_now = [draft(conn, "no_mfa", "u", Severity::High)];
        let r2 = scan(s, seed, org, conn, &seen_now).await;
        assert_eq!(s.findings().resolve_unseen(org, conn, r2, &[], t(1)).await.unwrap(), 1);
        let one = |check: &str| {
            let f = FindingFilter { check_id: Some(check.into()), ..Default::default() };
            async move { s.findings().list(org, f, all()).await.unwrap().items.remove(0) }
        };
        assert_eq!(one("99").await.status, "resolved");
        assert_eq!(one("no_mfa").await.status, "open");
    }

    async fn change_status_writes_one_event(s, seed) {
        let (org, conn) = world(s, seed).await;
        scan(s, seed, org, conn, &[draft(conn, "no_mfa", "u", Severity::High)]).await;
        let id = s.findings().list(org, FindingFilter::default(), all()).await.unwrap().items[0].id;
        let f = s.findings().change_status(org, id, snooze(id, "open")).await.unwrap();
        assert_eq!((f.status.as_str(), f.snoozed_until), ("snoozed", Some(t(48))));
        assert_eq!(s.findings().get(org, id).await.unwrap(), Some(f));
        let events = s.findings().events(org, id).await.unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!((events[0].kind.as_str(), events[0].run_id), ("snoozed", None));
        let stale = s.findings().change_status(org, id, snooze(id, "open")).await.unwrap_err();
        assert!(matches!(stale, RepoError::Conflict("finding_state_changed")), "{stale:?}");
        assert_eq!(s.findings().events(org, id).await.unwrap().len(), 2);
    }

    async fn list_filters_and_pages(s, seed) {
        let (org, a) = world(s, seed).await;
        let b = seed.connection(org).await;
        scan(s, seed, org, a, &[draft(a, "no_mfa", "u1", Severity::High), draft(a, "no_mfa", "u2", Severity::Low)]).await;
        scan(s, seed, org, b, &[draft(b, "old_key", "u1", Severity::High)]).await;
        let count = |f: FindingFilter| async move { s.findings().list(org, f, all()).await.unwrap().items.len() };
        assert_eq!(count(FindingFilter::default()).await, 3);
        assert_eq!(count(FindingFilter { connection_id: Some(b), ..Default::default() }).await, 1);
        assert_eq!(count(FindingFilter { severity: Some(Severity::High), ..Default::default() }).await, 2);
        assert_eq!(count(FindingFilter { check_id: Some("no_mfa".into()), ..Default::default() }).await, 2);
        assert_eq!(count(FindingFilter { status: Some("resolved".into()), ..Default::default() }).await, 0);
        let mut seen = vec![];
        let mut p = PageRequest { after: None, limit: 2 };
        loop {
            let page = s.findings().list(org, FindingFilter::default(), p).await.unwrap();
            seen.extend(page.items.iter().map(|f| f.id));
            match page.next {
                Some(c) => p.after = Some(c),
                None => break,
            }
        }
        assert_eq!(seen.len(), 3);
        assert_eq!(seen.iter().collect::<std::collections::HashSet<_>>().len(), 3);
    }

    async fn filter_by_variant_and_last_seen_since(s, seed) {
        let (org, conn) = world(s, seed).await;
        let mut anomaly = draft(conn, "01", "cost", Severity::High);
        anomaly.key.variant = "cost_anomaly".into();
        let run = seed.run(org, conn).await;
        let now = Utc::now();
        s.findings().upsert_seen(org, conn, run, &[anomaly, draft(conn, "01", "other", Severity::Low)], now).await.unwrap();
        let count = |f: FindingFilter| async move { s.findings().list(org, f, all()).await.unwrap().items.len() };
        let variant = |v: &str| FindingFilter { variant: Some(v.into()), ..Default::default() };
        assert_eq!(count(variant("cost_anomaly")).await, 1);
        assert_eq!(count(variant("nope")).await, 0);
        let since = |h| FindingFilter { last_seen_since: Some(now + Duration::hours(h)), ..Default::default() };
        assert_eq!(count(since(-1)).await, 2);
        assert_eq!(count(since(1)).await, 0);
    }

    async fn seen_again_in_a_later_run_stays_in_last_seen_since(s, seed) {
        let (org, conn) = world(s, seed).await;
        let d = [draft(conn, "01", "x", Severity::High)];
        let t0 = Utc::now();
        let first = seed.run(org, conn).await;
        s.findings().upsert_seen(org, conn, first, &d, t0).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let second = seed.run(org, conn).await;
        let t1 = Utc::now();
        s.findings().upsert_seen(org, conn, second, &d, t1).await.unwrap();
        let since = |t| FindingFilter { last_seen_since: Some(t), ..Default::default() };
        let count = |f: FindingFilter| async move { s.findings().list(org, f, all()).await.unwrap().items.len() };
        // Just after the first sighting: the second one keeps it in.
        assert_eq!(count(since(t0 + Duration::milliseconds(100))).await, 1);
        assert_eq!(count(since(t1 + Duration::hours(1))).await, 0);
    }

    async fn other_org_finding_invisible(s, seed) {
        let (org, conn) = world(s, seed).await;
        let (other, _) = world(s, seed).await;
        scan(s, seed, org, conn, &[draft(conn, "no_mfa", "u", Severity::High)]).await;
        let id = s.findings().list(org, FindingFilter::default(), all()).await.unwrap().items[0].id;
        assert!(s.findings().get(other, id).await.unwrap().is_none());
        assert!(s.findings().list(other, FindingFilter::default(), all()).await.unwrap().items.is_empty());
        assert!(s.findings().events(other, id).await.unwrap().is_empty());
        assert!(s.findings().evidence(other, id).await.unwrap().is_empty());
        assert!(s.findings().posture_rows(other, conn).await.unwrap().is_empty());
        let e = s.findings().change_status(other, id, snooze(id, "open")).await.unwrap_err();
        assert!(matches!(e, RepoError::NotFound), "{e:?}");
        assert_eq!(s.findings().get(org, id).await.unwrap().unwrap().status, "open");
    }

    async fn view_fields_and_stored_evidence_round_trip(s, seed) {
        let (org, conn) = world(s, seed).await;
        let mut d = draft(conn, "no_mfa", "u", Severity::High);
        d.cost_monthly_usd = Some(12.34);
        d.evidence[0].excerpt = "Authorization: Bearer abc.def".into();
        let run = scan(s, seed, org, conn, &[d]).await;
        let id = s.findings().list(org, FindingFilter::default(), all()).await.unwrap().items[0].id;
        let f = s.findings().get(org, id).await.unwrap().unwrap();
        assert_eq!((f.summary.as_deref(), f.next_step.as_deref()), (Some("s"), Some("n")));
        assert_eq!(f.cost_monthly_usd.map(|c| c.to_string()).as_deref(), Some("12.34"));
        assert_eq!(f.resolved_reason, None);
        let ev = s.findings().evidence(org, id).await.unwrap();
        assert_eq!((ev[0].run_id, ev[0].redacted), (run, true));
        assert_eq!(ev[0].excerpt, "Authorization: Bearer [redacted:token]");
        assert_eq!(ev[0].source, "src");
        let r2 = scan(s, seed, org, conn, &[]).await;
        s.findings().resolve_unseen(org, conn, r2, &[], t(1)).await.unwrap();
        let f = s.findings().get(org, id).await.unwrap().unwrap();
        assert_eq!(f.resolved_reason.as_deref(), Some("check_passed"));
    }

    async fn resolve_unseen_of_a_gone_resource_says_resource_gone(s, seed) {
        let (org, conn) = world(s, seed).await;
        let run = scan(s, seed, org, conn, &[draft(conn, "no_mfa", "u", Severity::High)]).await;
        let resource = Resource {
            provider: Provider::Fake,
            account: "1".into(),
            region: "eu-west-1".into(),
            kind: ResourceKind::Identity,
            identity: "u".into(),
            name: "u".into(),
            tags: Default::default(),
            attributes: serde_json::json!({}),
            observed_at: t(0),
        };
        s.resources().upsert_chunk(org, conn, run, &[resource], t(0)).await.unwrap();
        seed.resource_gone(org, "u").await;
        let r2 = scan(s, seed, org, conn, &[]).await;
        assert_eq!(s.findings().resolve_unseen(org, conn, r2, &[], t(1)).await.unwrap(), 1);
        let f = s.findings().list(org, FindingFilter::default(), all()).await.unwrap().items.remove(0);
        assert_eq!((f.status.as_str(), f.resolved_reason.as_deref()), ("resolved", Some("resource_gone")));
    }

    async fn posture_rows_counts_open_only(s, seed) {
        let (org, conn) = world(s, seed).await;
        scan(s, seed, org, conn, &[
            draft(conn, "no_mfa", "u1", Severity::High),
            draft(conn, "no_mfa", "u2", Severity::High),
            draft(conn, "old_key", "u1", Severity::Low),
        ]).await;
        let id = s.findings().list(org, FindingFilter { check_id: Some("old_key".into()), ..Default::default() }, all())
            .await.unwrap().items[0].id;
        s.findings().change_status(org, id, snooze(id, "open")).await.unwrap();
        let rows = s.findings().posture_rows(org, conn).await.unwrap();
        assert_eq!(rows, [PostureRow { check_id: "no_mfa".into(), severity: Severity::High, open: 2 }]);
    }
}
