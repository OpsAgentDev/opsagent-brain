use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use async_trait::async_trait;

use crate::{actions::RateLimiter, error::AppResult};

/// In-memory `RateLimiter`.
// shortcut: windows never expire; tests that need expiry use Redis.
#[derive(Default)]
pub struct MemRateLimiter {
    counts: Mutex<HashMap<String, i64>>,
    sets: Mutex<HashMap<String, HashSet<String>>>,
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
}
