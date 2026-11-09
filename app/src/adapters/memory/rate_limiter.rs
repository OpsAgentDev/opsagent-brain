use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use async_trait::async_trait;
use sea_orm::prelude::Decimal;

use crate::{
    actions::{ai::CreditTally, RateLimiter},
    error::AppResult,
};

/// In-memory `RateLimiter`.
// shortcut: windows never expire; tests that need expiry use Redis.
#[derive(Default)]
pub struct MemRateLimiter {
    counts: Mutex<HashMap<String, i64>>,
    sets: Mutex<HashMap<String, HashSet<String>>>,
    credits: Mutex<HashMap<String, Decimal>>,
}

#[async_trait]
impl CreditTally for MemRateLimiter {
    async fn total(&self, key: &str) -> AppResult<Decimal> {
        let credits = self.credits.lock().unwrap_or_else(|p| p.into_inner());
        Ok(credits.get(key).copied().unwrap_or_default())
    }

    async fn add(&self, key: &str, credits: Decimal, _window_secs: i64) -> AppResult<()> {
        let mut all = self.credits.lock().unwrap_or_else(|p| p.into_inner());
        *all.entry(key.into()).or_default() += credits;
        Ok(())
    }
}

#[async_trait]
impl RateLimiter for MemRateLimiter {
    async fn hit(&self, key: &str, cap: i64, _window_secs: i64) -> AppResult<bool> {
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let n = counts.entry(key.into()).or_default();
        *n += 1;
        Ok(*n <= cap)
    }

    async fn distinct(&self, key: &str, member: &str, _window_secs: i64) -> AppResult<i64> {
        let mut sets = self.sets.lock().unwrap_or_else(|p| p.into_inner());
        let set = sets.entry(key.into()).or_default();
        set.insert(member.into());
        Ok(set.len() as i64)
    }

    async fn clear(&self, key: &str) -> AppResult<()> {
        self.counts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(key);
        self.sets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(key);
        Ok(())
    }

    async fn forget(&self, key: &str, member: &str) -> AppResult<()> {
        let mut sets = self.sets.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(set) = sets.get_mut(key) {
            set.remove(member);
        }
        Ok(())
    }
}
