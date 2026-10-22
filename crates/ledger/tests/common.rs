#![allow(dead_code)]
use chrono::Utc;
use opsagent_core::run::RunKey;

pub fn redis() -> redis::Client {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:56379".into());
    redis::Client::open(url).unwrap()
}

pub fn key() -> RunKey {
    RunKey {
        organisation_id: None,
        connection_id: Some(uuid::Uuid::now_v7()),
        job_type: "t".into(),
        scheduled_at: Utc::now(),
    }
}
