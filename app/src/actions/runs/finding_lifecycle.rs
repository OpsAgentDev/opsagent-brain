//! Finding lifecycle per `full_scan` (PRD 7.4): the repository upserts what the run saw and
//! resolves what it did not; this holds the rule of which findings may resolve.
use std::collections::{BTreeSet, HashSet};

use chrono::{DateTime, Utc};
use opsagent_core::{
    connection::Connection,
    finding::{FindingDraft, FindingFilter, FindingKey},
    repo::{PageRequest, RepoResult},
    resource::ResourceFilter,
};
use uuid::Uuid;

use super::watch_scan;
use crate::actions::uow::Repos;

/// Applies one run's drafts. Every unseen finding resolves, except those of checks whose
/// capability was partial: a partial scan resolves nothing for a partial capability. `partial`
/// is run-wide today (no check reports which capability it lacked), so every check counts as
/// partial and a partial run resolves nothing. Nor do the findings of `failed` checks (one
/// that panicked or could not read its input): a check that did not run says nothing.
pub(super) async fn apply(
    repos: &dyn Repos,
    c: &Connection,
    run_id: Uuid,
    drafts: &[FindingDraft],
    failed: &[&str],
    now: DateTime<Utc>,
    partial: bool,
) -> RepoResult<()> {
    let (org, conn, findings) = (c.organisation_id, c.id, repos.findings());
    findings.upsert_seen(org, conn, run_id, drafts, now).await?;
    if partial {
        return Ok(());
    }
    let failed: Vec<String> = failed.iter().map(|id| (*id).to_owned()).collect();
    let resolve = findings.resolve_unseen(org, conn, run_id, &failed, now);
    resolve.await?;
    Ok(())
}

/// Applies one watch run's drafts: opens new findings, reopens resolved ones, and resolves an
/// open finding of a watch variant that no draft matches when its resource was read this run
/// (`was_read`), as the full scan would; a later draft then reopens it and alerts again.
/// `ran` is the checks that ran without error: any other check says nothing. Findings still
/// matched are left to the full scan, so a 15-minute run neither settles flapping faster
/// (`STABLE_RUNS` counts seen runs) nor writes a `seen` event and evidence each time.
/// shortcut: lists every finding of the checks, resolved ones too (`FindingFilter` has no
/// status-not filter); bounded by the (resource, variant) pairs ever seen for 03/06.
pub(super) async fn apply_watch(
    repos: &dyn Repos,
    c: &Connection,
    run_id: Uuid,
    drafts: &[FindingDraft],
    ran: &[&str],
    failed_reads: &BTreeSet<String>,
    now: DateTime<Utc>,
) -> RepoResult<()> {
    let (org, conn, findings) = (c.organisation_id, c.id, repos.findings());
    let matched: HashSet<&FindingKey> = drafts.iter().map(|d| &d.key).collect();
    let mut tracked: HashSet<FindingKey> = HashSet::new();
    let mut fixed = vec![];
    for check_id in ran {
        let filter = FindingFilter {
            connection_id: Some(conn),
            check_id: Some((*check_id).into()),
            ..Default::default()
        };
        let mut page = PageRequest {
            after: None,
            limit: 500,
        };
        loop {
            let got = findings.list(org, filter.clone(), page).await?;
            for f in got.items {
                if f.status == "open"
                    && !matched.contains(&f.key)
                    && was_read(repos, c, &f.key, failed_reads).await?
                {
                    fixed.push(f.id);
                }
                if f.status != "resolved" {
                    tracked.insert(f.key);
                }
            }
            match got.next {
                Some(after) => {
                    page = PageRequest {
                        after: Some(after),
                        ..page
                    }
                }
                None => break,
            }
        }
    }
    findings.resolve(org, conn, run_id, &fixed, now).await?;
    let fresh: Vec<FindingDraft> = drafts
        .iter()
        .filter(|d| !tracked.contains(&d.key))
        .cloned()
        .collect();
    findings.upsert_seen(org, conn, run_id, &fresh, now).await
}

/// True when this watch run read the finding's resource: a watch variant whose stored
/// resource has a region, and that region's read of its service did not fail
/// (`failed_reads` holds each failed `service@region`). A watch scan that ends at its time
/// cap never gets here. Check 06's trail findings name the account (`cloudtrail:<account>`),
/// not a stored resource, so they never resolve here: they stay the full scan's.
async fn was_read(
    repos: &dyn Repos,
    c: &Connection,
    key: &FindingKey,
    failed_reads: &BTreeSet<String>,
) -> RepoResult<bool> {
    let Some(service) = watch_scan::service(key) else {
        return Ok(false);
    };
    let filter = ResourceFilter {
        connection_id: Some(c.id),
        identity: Some(key.resource_identity.clone()),
        ..Default::default()
    };
    let one = PageRequest {
        after: None,
        limit: 1,
    };
    let rows = repos.resources().list(c.organisation_id, filter, one);
    let region = rows.await?.items.into_iter().next().and_then(|r| r.region);
    Ok(region.is_some_and(|r| !failed_reads.contains(&format!("{service}@{r}"))))
}

#[cfg(test)]
mod tests {
    use opsagent_core::finding::{FindingKey, Severity};

    use super::*;
    use crate::{
        actions::{findings::test_support::page, runs::test_support::connected},
        adapters::memory::MemStore,
    };

    fn draft(c: &Connection, check_id: &str) -> FindingDraft {
        FindingDraft {
            key: FindingKey {
                connection_id: c.id,
                check_id: check_id.into(),
                resource_identity: "user/a".into(),
                variant: String::new(),
            },
            severity: Severity::High,
            title: "t".into(),
            summary: "s".into(),
            next_step: "n".into(),
            cost_monthly_usd: None,
            evidence: vec![],
        }
    }

    async fn status(store: &MemStore, c: &Connection) -> String {
        let all = store
            .findings()
            .list(c.organisation_id, Default::default(), page());
        all.await.unwrap().items[0].status.clone()
    }

    #[tokio::test]
    async fn partial_capability_resolves_nothing_for_that_check() {
        let store = MemStore::default();
        let c = connected(&store, Uuid::new_v4()).await;
        let now = Utc::now();
        let seen = [draft(&c, "no_mfa")];
        apply(&store, &c, Uuid::new_v4(), &seen, &[], now, false)
            .await
            .unwrap();
        assert_eq!(status(&store, &c).await, "open");
        // The check could not be fed this run: its unseen finding stays open.
        apply(&store, &c, Uuid::new_v4(), &[], &[], now, true)
            .await
            .unwrap();
        assert_eq!(status(&store, &c).await, "open");
        // A complete run that does not see it resolves it.
        apply(&store, &c, Uuid::new_v4(), &[], &[], now, false)
            .await
            .unwrap();
        assert_eq!(status(&store, &c).await, "resolved");
    }

    #[tokio::test]
    async fn a_failed_check_resolves_nothing_and_writes_no_seen() {
        let store = MemStore::default();
        let c = connected(&store, Uuid::new_v4()).await;
        let now = Utc::now();
        let seen = [draft(&c, "no_mfa"), draft(&c, "other")];
        let first = Uuid::new_v4();
        apply(&store, &c, first, &seen, &[], now, false)
            .await
            .unwrap();
        // `no_mfa` panicked this run and reported nothing; `other` ran and saw nothing.
        apply(&store, &c, Uuid::new_v4(), &[], &["no_mfa"], now, false)
            .await
            .unwrap();
        let all = store
            .findings()
            .list(c.organisation_id, Default::default(), page());
        for f in all.await.unwrap().items {
            let held = f.key.check_id == "no_mfa";
            assert_eq!(f.status, if held { "open" } else { "resolved" });
            assert_eq!(f.last_seen_run_id, Some(first));
        }
    }

    /// A critical open-admin-port draft (a watch variant) for security group `identity`,
    /// whose resource is stored in `region`.
    async fn exposed(
        store: &MemStore,
        c: &Connection,
        identity: &str,
        region: &str,
    ) -> FindingDraft {
        use opsagent_core::resource::{Provider, Resource, ResourceKind};
        let sg = Resource {
            provider: Provider::Fake,
            account: "a".into(),
            region: region.into(),
            kind: ResourceKind::Network,
            identity: identity.into(),
            name: identity.into(),
            tags: Default::default(),
            attributes: serde_json::json!({ "service": "sg" }),
            observed_at: Utc::now(),
        };
        let (org, run, sg) = (c.organisation_id, Uuid::new_v4(), [sg]);
        let stored = store
            .resources()
            .upsert_chunk(org, c.id, run, &sg, Utc::now());
        stored.await.unwrap();
        let mut d = draft(c, "03");
        d.key.resource_identity = identity.into();
        d.key.variant = "sg_open_admin_port".into();
        d.severity = Severity::Critical;
        d
    }

    async fn watch(store: &MemStore, c: &Connection, drafts: &[FindingDraft], failed: &[&str]) {
        let failed: BTreeSet<String> = failed.iter().map(|s| (*s).to_owned()).collect();
        apply_watch(
            store,
            c,
            Uuid::new_v4(),
            drafts,
            &["03"],
            &failed,
            Utc::now(),
        )
        .await
        .unwrap();
    }

    async fn status_of(store: &MemStore, c: &Connection, identity: &str) -> String {
        let all = store
            .findings()
            .list(c.organisation_id, Default::default(), page());
        let mut all = all.await.unwrap().items.into_iter();
        let f = all.find(|f| f.key.resource_identity == identity);
        f.unwrap().status
    }

    #[tokio::test]
    async fn a_watch_resolves_what_it_read_as_fixed_and_a_reopen_alerts_again() {
        let store = MemStore::default();
        let c = connected(&store, Uuid::new_v4()).await;
        let d = exposed(&store, &c, "sg-1", "eu-1").await;
        let unalerted = || store.findings().alert_candidates(c.organisation_id, c.id);
        watch(&store, &c, std::slice::from_ref(&d), &[]).await;
        let ids: Vec<Uuid> = unalerted().await.unwrap().iter().map(|f| f.id).collect();
        assert_eq!(ids.len(), 1);
        let alerted = store
            .findings()
            .mark_alerted(c.organisation_id, &ids, Utc::now());
        alerted.await.unwrap();
        // Still exposed: left alone, and not alerted a second time.
        watch(&store, &c, std::slice::from_ref(&d), &[]).await;
        assert!(unalerted().await.unwrap().is_empty());
        // Fixed at noon, exposed again at three: resolved, then reopened and due an alert.
        watch(&store, &c, &[], &[]).await;
        assert_eq!(status_of(&store, &c, "sg-1").await, "resolved");
        watch(&store, &c, std::slice::from_ref(&d), &[]).await;
        assert_eq!(status_of(&store, &c, "sg-1").await, "open");
        assert_eq!(unalerted().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_watch_resolves_nothing_it_did_not_read() {
        let store = MemStore::default();
        let c = connected(&store, Uuid::new_v4()).await;
        let down = exposed(&store, &c, "sg-down", "eu-1").await;
        let read = exposed(&store, &c, "sg-read", "us-1").await;
        // Not a watch variant: the full scan's to resolve.
        let other = draft(&c, "03");
        let (org, run, open) = (c.organisation_id, Uuid::new_v4(), [down, read, other]);
        let seen = store
            .findings()
            .upsert_seen(org, c.id, run, &open, Utc::now());
        seen.await.unwrap();
        // The check did not run (it failed, or its service was unavailable): nothing resolves.
        let none = BTreeSet::new();
        apply_watch(&store, &c, Uuid::new_v4(), &[], &[], &none, Utc::now())
            .await
            .unwrap();
        assert_eq!(status_of(&store, &c, "sg-read").await, "open");
        // `sg` failed in one region, `rds` in the other: only the group that was read resolves.
        watch(&store, &c, &[], &["sg@eu-1", "rds@us-1"]).await;
        assert_eq!(status_of(&store, &c, "sg-down").await, "open");
        assert_eq!(status_of(&store, &c, "sg-read").await, "resolved");
        assert_eq!(status_of(&store, &c, "user/a").await, "open");
    }
}
