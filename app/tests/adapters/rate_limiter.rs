//! `CreditTally` on real Redis.
use opsagent_brain::{actions::ai::CreditTally, adapters::rate_limiter::RedisRateLimiter};
use opsagent_ledger::redis;
use sea_orm::prelude::Decimal;
use uuid::Uuid;

#[tokio::test]
async fn tally_adds_decimals_and_expires() {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".into());
    let client = redis::Client::open(url).unwrap();
    let tally = RedisRateLimiter::new(client.clone());
    let key = format!("test:credits:{}", Uuid::new_v4());
    assert_eq!(tally.total(&key).await.unwrap(), Decimal::ZERO);
    tally.add(&key, Decimal::new(125, 2), 60).await.unwrap();
    tally.add(&key, Decimal::new(275, 2), 60).await.unwrap();
    assert_eq!(tally.total(&key).await.unwrap(), Decimal::new(4, 0));
    let mut c = client.get_connection().unwrap();
    let ttl: i64 = redis::cmd("TTL").arg(&key).query(&mut c).unwrap();
    assert!((1..=60).contains(&ttl), "{ttl}");
}
