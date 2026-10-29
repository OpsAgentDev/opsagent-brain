//! Purge step: organisations deleted more than 30 days ago, one transaction each, then purge
//! records older than a year (retention.md, goal 5).
use chrono::{DateTime, Duration, Utc};
use tokio::time::Instant;

use super::RetentionStats;
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// An organisation is purged this long after its deletion.
const PURGE_AFTER_DAYS: i64 = 30;
/// A running run younger than this means a worker may still hold the organisation.
const BUSY_HOURS: i64 = 24;
/// Purge records are kept this long.
const RECORD_DAYS: i64 = 365;

/// Purges every due organisation, recording how many as `organisations` (the per-table
/// counts are in each purge record), then old purge records as `purge_records`; stops with
/// `time_capped` at `deadline`.
pub(super) async fn run(
    uow: &dyn UnitOfWork,
    now: DateTime<Utc>,
    deadline: Instant,
    stats: &mut RetentionStats,
) -> AppResult<()> {
    let due = uow
        .retention()
        .purgeable_orgs(
            now - Duration::days(PURGE_AFTER_DAYS),
            now - Duration::hours(BUSY_HOURS),
        )
        .await?;
    let mut purged = 0;
    for org in due {
        if Instant::now() >= deadline {
            stats.time_capped = true;
            break;
        }
        let tx = uow.begin().await?;
        let done = tx.retention().purge_org(org, now).await?;
        tx.commit().await?;
        purged += u64::from(done.is_some());
    }
    stats.counts.insert("organisations", purged);
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
    use opsagent_core::org::{NewOrganisation, OrganisationsRepo};
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
