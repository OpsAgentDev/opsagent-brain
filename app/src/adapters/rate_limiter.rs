//! `RateLimiter` on Redis fixed-window counters.
use async_trait::async_trait;
use opsagent_ledger::redis::{self, Script};

use crate::{
    actions::RateLimiter,
    error::{AppError, AppResult},
};

/// `INCR`, with the window's `EXPIRE` set by the first hit (or on a counter left without a
/// TTL by older code), in one atomic step: a counter can never outlive its window.
const COUNT: &str = r#"local n = redis.call('INCR', KEYS[1]) if n == 1 or redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end return n"#;

/// `SADD` plus `SCARD`, with the window's `EXPIRE` set when the set is new, atomically.
const DISTINCT: &str = r#"redis.call('SADD', KEYS[1], ARGV[1]) if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end return redis.call('SCARD', KEYS[1])"#;

pub struct RedisRateLimiter(pub redis::Client);

fn unavailable(e: redis::RedisError) -> AppError {
    AppError::Internal(format!("rate limiter: {e}"))
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn hit(&self, key: &str, cap: i64, window_secs: i64) -> AppResult<bool> {
        let mut c = self
            .0
            .get_multiplexed_async_connection()
            .await
            .map_err(unavailable)?;
        let n: i64 = Script::new(COUNT)
            .key(key)
            .arg(window_secs)
            .invoke_async(&mut c)
            .await
            .map_err(unavailable)?;
        Ok(n <= cap)
    }

    async fn distinct(&self, key: &str, member: &str, window_secs: i64) -> AppResult<i64> {
        let mut c = self
            .0
            .get_multiplexed_async_connection()
            .await
            .map_err(unavailable)?;
        Script::new(DISTINCT)
            .key(key)
            .arg(member)
            .arg(window_secs)
            .invoke_async(&mut c)
            .await
            .map_err(unavailable)
    }
}
