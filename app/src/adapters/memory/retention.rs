use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::RepoResult,
    retention::{RetentionRepo, TtlTable},
};

use super::MemStore;

// shortcut: expiring rows are modelled apart from the typed rows (magic links, invites, ...),
// as one expiry instant per row; model them on the typed rows if a test needs both.
impl MemStore {
    /// Adds one `table` row expiring (or observed) at `at`.
    pub fn seed_expiring(&self, table: TtlTable, at: DateTime<Utc>) {
        self.state().expiring.push((table, at));
    }

    /// How many `table` rows are left.
    pub fn expiring_left(&self, table: TtlTable) -> u64 {
        self.state()
            .expiring
            .iter()
            .filter(|r| r.0 == table)
            .count() as u64
    }
}

#[async_trait]
impl RetentionRepo for MemStore {
    async fn delete_expired(
        &self,
        table: TtlTable,
        cutoff: DateTime<Utc>,
        batch: u64,
    ) -> RepoResult<u64> {
        let mut s = self.state();
        let mut left = batch;
        s.expiring.retain(|&(t, at)| {
            let drop = left > 0 && t == table && at < cutoff;
            left -= u64::from(drop);
            !drop
        });
        Ok(batch - left)
    }
}
