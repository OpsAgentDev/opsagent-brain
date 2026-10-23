//! Use cases over repository traits (engineering principles, Layers).
pub mod auth;
pub mod connections;
pub mod findings;
pub mod integrations;
pub mod recipients;
pub mod resources;
pub mod runs;
pub mod uow;

use async_trait::async_trait;

use crate::error::AppResult;

/// Every action, built once by `boot::build_actions`.
pub struct Actions {
    pub auth: auth::Auth,
    pub findings: findings::Findings,
    pub resources: resources::Resources,
    pub connections: connections::Connections,
    pub runs: runs::Runs,
    pub recipients: recipients::Recipients,
    pub integrations: integrations::Integrations,
}

/// Fixed-window counters shared by every rate limit.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Counts one hit on `key`; `true` while the window's count is within `cap`.
    async fn hit(&self, key: &str, cap: i64, window_secs: i64) -> AppResult<bool>;
    /// Adds `member` to the window's set at `key`; how many distinct members it holds.
    async fn distinct(&self, key: &str, member: &str, window_secs: i64) -> AppResult<i64>;
    /// Drops the counter or set at `key`.
    async fn clear(&self, key: &str) -> AppResult<()>;
    /// Removes `member` from the set at `key`.
    async fn forget(&self, key: &str, member: &str) -> AppResult<()>;
}

pub const HOUR_SECS: i64 = 3600;
pub const DAY_SECS: i64 = 86_400;
