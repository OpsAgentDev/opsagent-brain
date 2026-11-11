//! The public status page's numbers (status-page.md). Global aggregates only: no organisation
//! data and no per-organisation counts.
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use opsagent_core::repo::Clock;

use crate::error::AppResult;

/// What the status page shows, counted at `checked_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemStatus {
    /// Jobs due now and not locked.
    pub scans_waiting: i64,
    /// Age of the oldest due, unlocked job; 0 when none.
    pub oldest_wait_seconds: i64,
    pub sent_24h: i64,
    pub failed_24h: i64,
    pub checked_at: DateTime<Utc>,
}

/// Storage port for the status counts.
#[async_trait]
pub trait StatusStore: Send + Sync {
    /// Counts at `now`; deliveries created after `since`.
    async fn counts(&self, now: DateTime<Utc>, since: DateTime<Utc>) -> AppResult<SystemStatus>;
}

pub struct GetStatus {
    store: Arc<dyn StatusStore>,
    clock: Arc<dyn Clock>,
}

impl GetStatus {
    pub fn new(store: Arc<dyn StatusStore>, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }

    pub async fn run(&self) -> AppResult<SystemStatus> {
        let now = self.clock.now();
        self.store.counts(now, now - Duration::hours(24)).await
    }
}
