//! `RateLimiter` on Redis fixed-window counters.
use async_trait::async_trait;
use opsagent_ledger::redis::{self, aio::ConnectionManager, Script};
use tokio::sync::OnceCell;

use crate::{
    actions::RateLimiter,
    error::{AppError, AppResult},
};

/// `INCR`, with the window's `EXPIRE` set by the first hit (or on a counter left without a
/// TTL by older code), in one atomic step: a counter can never outlive its window.
const COUNT: &str = r#"local n = redis.call('INCR', KEYS[1]) if n == 1 or redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end return n"#;

/// `SADD` plus `SCARD`, with the window's `EXPIRE` set when the set is new, atomically.
const DISTINCT: &str = r#"redis.call('SADD', KEYS[1], ARGV[1]) if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end return redis.call('SCARD', KEYS[1])"#;

/// One `ConnectionManager` (multiplexed, reconnecting) shared by every call. It is opened on
/// first use, not at boot: modes that never count (tasks) do not need Redis, and an outage
/// fails the call (callers fail closed) and is retried on the next one.
pub struct RedisRateLimiter {
    client: redis::Client,
    conn: OnceCell<ConnectionManager>,
}

impl RedisRateLimiter {
    pub fn new(client: redis::Client) -> Self {
        Self {
            client,
            conn: OnceCell::new(),
        }
    }

    async fn conn(&self) -> AppResult<ConnectionManager> {
        let open = || ConnectionManager::new(self.client.clone());
        let c = self.conn.get_or_try_init(open).await.map_err(unavailable)?;
        Ok(c.clone())
    }
}

fn unavailable(e: redis::RedisError) -> AppError {
    AppError::Internal(format!("rate limiter: {e}"))
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn hit(&self, key: &str, cap: i64, window_secs: i64) -> AppResult<bool> {
        let n: i64 = Script::new(COUNT)
            .key(key)
            .arg(window_secs)
            .invoke_async(&mut self.conn().await?)
            .await
            .map_err(unavailable)?;
        Ok(n <= cap)
    }

    async fn distinct(&self, key: &str, member: &str, window_secs: i64) -> AppResult<i64> {
        Script::new(DISTINCT)
            .key(key)
            .arg(member)
            .arg(window_secs)
            .invoke_async(&mut self.conn().await?)
            .await
            .map_err(unavailable)
    }

    async fn clear(&self, key: &str) -> AppResult<()> {
        let mut c = self.conn().await?;
        redis::cmd("DEL")
            .arg(key)
            .query_async(&mut c)
            .await
            .map_err(unavailable)
    }

    async fn forget(&self, key: &str, member: &str) -> AppResult<()> {
        let mut c = self.conn().await?;
        redis::cmd("SREM")
            .arg(key)
            .arg(member)
            .query_async(&mut c)
            .await
            .map_err(unavailable)
    }
}
