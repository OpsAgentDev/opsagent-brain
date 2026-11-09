//! The daily ceiling on OpsAgent's own model key across every organisation: a Redis tally of
//! credits, read before a call and added to where usage is metered. BYOK never touches it.
use std::sync::Arc;

use async_trait::async_trait;
use opsagent_core::repo::Clock;
use sea_orm::prelude::Decimal;

use crate::{
    actions::{RateLimiter, DAY_SECS},
    error::AppResult,
};

/// Running credit totals per key.
#[async_trait]
pub trait CreditTally: Send + Sync {
    /// The total at `key`; zero when it does not exist.
    async fn total(&self, key: &str) -> AppResult<Decimal>;
    /// Adds `credits` at `key`, which expires `window_secs` after its first add.
    async fn add(&self, key: &str, credits: Decimal, window_secs: i64) -> AppResult<()>;
}

pub struct DailyLimit {
    tally: Arc<dyn CreditTally>,
    limiter: Arc<dyn RateLimiter>,
    clock: Arc<dyn Clock>,
    limit: Decimal,
}

impl DailyLimit {
    pub fn new(
        tally: Arc<dyn CreditTally>,
        limiter: Arc<dyn RateLimiter>,
        clock: Arc<dyn Clock>,
        limit: i64,
    ) -> Self {
        Self {
            tally,
            limiter,
            clock,
            limit: Decimal::from(limit),
        }
    }

    /// Today's (UTC) tally.
    fn key(&self) -> String {
        let day = self.clock.now().format("%Y-%m-%d");
        format!("ai:opsagent_credits:{day}")
    }

    /// `true` once today's spend reaches the limit, or when it cannot be read: fails closed,
    /// as every other limiter does, since this one guards money.
    pub(super) async fn reached(&self) -> bool {
        let key = self.key();
        let spent = match self.tally.total(&key).await {
            Ok(spent) => spent,
            Err(e) => {
                tracing::warn!(error = %e, "ai daily credit tally unavailable, refusing");
                return true;
            }
        };
        if spent < self.limit {
            return false;
        }
        // The first caller past the limit in any process; if that cannot be told, log anyway.
        let logged = format!("{key}:logged");
        let once = self.limiter.hit(&logged, 1, DAY_SECS);
        if once.await.unwrap_or(true) {
            tracing::error!(
                error_code = "ai_daily_limit_reached",
                limit = %self.limit,
                "OpsAgent-key AI daily credit limit reached"
            );
        }
        true
    }

    /// Adds a metered call's credits. The call is answered and billed already, so a failure
    /// is logged and not returned.
    pub(super) async fn add(&self, credits: Decimal) {
        // Two days, so a tally begun at 00:00 still exists at 23:59.
        if let Err(e) = self.tally.add(&self.key(), credits, 2 * DAY_SECS).await {
            tracing::warn!(error = %e, "ai daily credit tally not updated");
        }
    }
}
