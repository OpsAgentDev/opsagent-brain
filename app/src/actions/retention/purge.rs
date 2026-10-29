//! Purge step: organisations deleted more than 30 days ago, one transaction each, then purge
//! records older than a year (retention.md, goal 5).
use chrono::{DateTime, Duration, Utc};
use tokio::time::Instant;

use opsagent_core::repo::RepoResult;

use super::RetentionStats;
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// An organisation is purged this long after its deletion.
const PURGE_AFTER_DAYS: i64 = 30;
/// A running run younger than this means a worker may still hold the organisation.
const BUSY_HOURS: i64 = 24;
/// Purge records are kept this long.
const RECORD_DAYS: i64 = 365;

/// Purges every due organisation, each in its own transaction, recording how many as
/// `organisations` (the per-table counts are in each purge record), how many waited on a
/// run as `organisations_busy` and how many failed (rolled back, logged, retried next
/// night) as `organisations_failed`; then old purge records as `purge_records`. Stops with
/// `time_capped` at `deadline`.
pub(super) async fn run(
    uow: &dyn UnitOfWork,
    now: DateTime<Utc>,
    deadline: Instant,
    stats: &mut RetentionStats,
) -> AppResult<()> {
    let cutoff = now - Duration::days(PURGE_AFTER_DAYS);
    let busy_since = now - Duration::hours(BUSY_HOURS);
    let due = uow.retention().due_orgs(cutoff, busy_since).await?;
    let (mut purged, mut busy, mut failed) = (0, 0, 0);
    for org in due {
        if Instant::now() >= deadline {
            stats.time_capped = true;
            break;
        }
        if org.busy {
            busy += 1;
            continue;
        }
        let purge = async {
            let tx = uow.begin().await?;
            let done = tx
                .retention()
                .purge_org(org.id, cutoff, busy_since, now)
                .await?;
            tx.commit().await?;
            RepoResult::Ok(done)
        };
        // A dropped transaction rolls back, so a failed purge leaves the organisation whole.
        match purge.await {
            Ok(Some(_)) => purged += 1,
            // Busy since it was listed (or purged by another run, which the lease rules out).
            Ok(None) => busy += 1,
            Err(e) => {
                failed += 1;
                tracing::warn!(organisation_id = %org.id, error = %e, "organisation purge failed");
            }
        }
    }
    stats.counts.insert("organisations", purged);
    stats.counts.insert("organisations_busy", busy);
    stats.counts.insert("organisations_failed", failed);
    if stats.time_capped {
        return Ok(());
    }
    let tx = uow.begin().await?;
    let old = now - Duration::days(RECORD_DAYS);
    let n = tx.retention().delete_old_purge_records(old).await?;
    tx.commit().await?;
    stats.counts.insert("purge_records", n);
    Ok(())
}

#[cfg(test)]
mod tests {
    use opsagent_core::{
        org::{NewOrganisation, OrganisationsRepo},
        retention::RetentionRepo,
    };
    use uuid::Uuid;

    use super::*;
    use crate::adapters::memory::MemStore;

    async fn org(store: &MemStore, deleted: Option<DateTime<Utc>>) -> Uuid {
        let new = NewOrganisation {
            id: Uuid::new_v4(),
            slug: Uuid::new_v4().to_string(),
            name: "o".into(),
            timezone: "UTC".into(),
            kek_version: 1,
            wrapped_dek: vec![],
        };
        let id = store.insert(new).await.unwrap().id;
        if let Some(at) = deleted {
            store.soft_delete(id, at).await.unwrap();
        }
        id
    }

    #[tokio::test]
    async fn purges_due_orgs_then_old_records() {
        let store = MemStore::default();
        let now = Utc::now();
        let old = org(&store, Some(now - Duration::days(800))).await;
        let far = Instant::now() + std::time::Duration::from_secs(60);
        // Purged long ago: its record is past the year by the second run.
        run(
            &store,
            now - Duration::days(400),
            far,
            &mut RetentionStats::default(),
        )
        .await
        .unwrap();
        org(&store, Some(now - Duration::days(31))).await;
        org(&store, Some(now - Duration::days(29))).await;
        let live = org(&store, None).await;
        let mut stats = RetentionStats::default();
        run(&store, now, far, &mut stats).await.unwrap();
        assert_eq!(stats.counts["organisations"], 1);
        assert_eq!(stats.counts["purge_records"], 1);
        assert!(!stats.time_capped);
        assert!(store.get(old).await.unwrap().is_none());
        assert!(store.get(live).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn one_failed_org_does_not_stop_the_others() {
        let store = MemStore::default();
        let now = Utc::now();
        let bad = org(&store, Some(now - Duration::days(40))).await;
        let good = org(&store, Some(now - Duration::days(35))).await;
        store.fail_purge_of(bad);
        let mut stats = RetentionStats::default();
        let far = Instant::now() + std::time::Duration::from_secs(60);
        run(&store, now, far, &mut stats).await.unwrap();
        assert_eq!(stats.counts["organisations"], 1);
        assert_eq!(stats.counts["organisations_failed"], 1);
        assert_eq!(stats.counts["purge_records"], 0);
        // Rolled back whole: still listed for the next night, the other one gone.
        let left = store.due_orgs(now, now).await.unwrap();
        assert_eq!(left.iter().map(|o| o.id).collect::<Vec<_>>(), vec![bad]);
        assert!(!left.iter().any(|o| o.id == good));
    }

    #[tokio::test]
    async fn busy_orgs_wait_and_are_counted() {
        let store = MemStore::default();
        let now = Utc::now();
        let busy = org(&store, Some(now - Duration::days(40))).await;
        let key = opsagent_core::run::RunKey {
            organisation_id: Some(busy),
            connection_id: None,
            job_type: "full_scan".into(),
            scheduled_at: now,
        };
        store
            .seed_run(key, opsagent_core::run::RunStatus::Queued)
            .await;
        org(&store, Some(now - Duration::days(10))).await; // not due: not counted
        let mut stats = RetentionStats::default();
        let far = Instant::now() + std::time::Duration::from_secs(60);
        run(&store, now, far, &mut stats).await.unwrap();
        assert_eq!(stats.counts["organisations"], 0);
        assert_eq!(stats.counts["organisations_busy"], 1);
        assert_eq!(stats.counts["organisations_failed"], 0);
    }

    #[tokio::test]
    async fn purge_stops_at_the_deadline() {
        let store = MemStore::default();
        let now = Utc::now();
        let due = org(&store, Some(now - Duration::days(31))).await;
        let mut stats = RetentionStats::default();
        run(&store, now, Instant::now(), &mut stats).await.unwrap();
        assert!(stats.time_capped);
        assert_eq!(stats.counts["organisations"], 0);
        assert!(!stats.counts.contains_key("purge_records"));
        assert!(store.get(due).await.unwrap().is_some());
    }
}
