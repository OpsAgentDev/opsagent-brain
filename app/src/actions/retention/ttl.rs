//! TTL step: expired rows of every `TtlTable`, by age alone (retention.md, goals 2 and 4).
use chrono::{DateTime, Duration, Utc};
use opsagent_core::retention::{RetentionRepo, TtlTable};
use tokio::time::Instant;

use super::{batched, RetentionStats};
use crate::error::AppResult;

/// Rows of `t` expiring (or observed) before this instant are deleted.
pub(super) fn cutoff(t: TtlTable, now: DateTime<Utc>) -> DateTime<Utc> {
    let days = match t {
        TtlTable::ResourceHistory | TtlTable::ApiCallsRaw => 90,
        TtlTable::Evidence | TtlTable::EmailSuppressions => 0,
        TtlTable::Sessions => 1,
        TtlTable::MagicLinks | TtlTable::OauthConsentRequests | TtlTable::OauthAccessTokens => 7,
        TtlTable::OauthRefreshTokens | TtlTable::Invites => 30,
    };
    now - Duration::days(days)
}

/// Deletes every table's expired rows in batches of `batch`, recording each table's count;
/// stops with `time_capped` at `deadline`.
pub(super) async fn run(
    repo: &dyn RetentionRepo,
    now: DateTime<Utc>,
    batch: u64,
    deadline: Instant,
    stats: &mut RetentionStats,
) -> AppResult<()> {
    for t in TtlTable::ALL {
        let step = || repo.delete_expired(t, cutoff(t, now), batch);
        let n = batched(batch, deadline, stats, step).await?;
        stats.counts.insert(t.name(), n);
        if stats.time_capped {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::memory::MemStore;

    #[tokio::test]
    async fn ttl_loops_batches_until_every_expired_row_is_gone() {
        let store = MemStore::default();
        let now = Utc::now();
        for _ in 0..5 {
            store.seed_expiring(TtlTable::Sessions, now - Duration::days(2));
        }
        store.seed_expiring(TtlTable::Sessions, now);
        let mut stats = RetentionStats::default();
        let far = Instant::now() + std::time::Duration::from_secs(60);
        run(&store, now, 2, far, &mut stats).await.unwrap();
        assert_eq!(stats.counts["sessions"], 5);
        assert_eq!(stats.counts.len(), TtlTable::ALL.len());
        assert!(!stats.time_capped);
        assert_eq!(store.expiring_left(TtlTable::Sessions), 1);
    }

    #[tokio::test]
    async fn ttl_stops_at_the_deadline() {
        let store = MemStore::default();
        let now = Utc::now();
        store.seed_expiring(TtlTable::Sessions, now - Duration::days(2));
        let mut stats = RetentionStats::default();
        run(&store, now, 2, Instant::now(), &mut stats)
            .await
            .unwrap();
        assert!(stats.time_capped);
        assert_eq!(store.expiring_left(TtlTable::Sessions), 1);
    }

    #[test]
    fn cutoffs_follow_the_spec() {
        let now = Utc::now();
        let days = |t| (now - cutoff(t, now)).num_days();
        assert_eq!(days(TtlTable::ResourceHistory), 90);
        assert_eq!(days(TtlTable::Evidence), 0);
        assert_eq!(days(TtlTable::Sessions), 1);
        assert_eq!(days(TtlTable::OauthAccessTokens), 7);
        assert_eq!(days(TtlTable::OauthRefreshTokens), 30);
        assert_eq!(days(TtlTable::EmailSuppressions), 0);
    }
}
