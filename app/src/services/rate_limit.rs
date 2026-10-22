//! Fixed-window counters in Redis, shared by every rate limit.
use opsagent_ledger::redis::{self, Script};

pub const HOUR_SECS: i64 = 3600;
pub const DAY_SECS: i64 = 86_400;

/// `INCR`, with the window's `EXPIRE` set by the first hit, in one atomic step: a counter
/// can never be left without a TTL.
const COUNT: &str = r#"local n = redis.call('INCR', KEYS[1]) if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end return n"#;

/// Counts one hit on `key`; `true` while the window's count is within `cap`.
pub async fn hit(
    c: &mut redis::aio::MultiplexedConnection,
    key: &str,
    cap: i64,
    window_secs: i64,
) -> redis::RedisResult<bool> {
    let n: i64 = Script::new(COUNT)
        .key(key)
        .arg(window_secs)
        .invoke_async(c)
        .await?;
    Ok(n <= cap)
}
