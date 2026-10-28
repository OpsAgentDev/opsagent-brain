//! Use cases over repository traits (engineering principles, Layers).
pub mod auth;
pub mod connections;
pub mod contact;
pub mod deliveries;
pub mod findings;
pub mod integrations;
pub mod members;
pub mod oauth;
pub mod orgs;
pub mod recipients;
pub mod resources;
pub mod retention;
pub mod runs;
pub mod uow;
pub mod waitlist;

use std::sync::Arc;

use async_trait::async_trait;
use opsagent_connectors::{Connector, ConnectorError, Registry};

use crate::error::AppResult;

/// Every action, built once by `boot::build_actions`.
pub struct Actions {
    pub auth: auth::Auth,
    pub findings: findings::Findings,
    pub resources: resources::Resources,
    pub connections: connections::Connections,
    pub runs: runs::Runs,
    pub orgs: orgs::Orgs,
    pub members: members::Members,
    pub recipients: recipients::Recipients,
    pub integrations: integrations::Integrations,
    pub deliveries: deliveries::Deliveries,
    pub oauth: oauth::OAuth,
    pub waitlist: waitlist::Waitlist,
    pub contact: contact::Contact,
    pub retention: retention::Retention,
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

/// A rate-limit bucket for one client: an IPv6 client owns at least a /64.
pub fn ip_bucket(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip.to_canonical() {
        std::net::IpAddr::V6(v6) => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64)))
        }
        v4 => v4,
    }
}

/// A rate-limit bucket for one network: IPv4 /24, IPv6 /48.
pub fn net_bucket(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip.to_canonical() {
        std::net::IpAddr::V6(v6) => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & (u128::MAX << 80)))
        }
        std::net::IpAddr::V4(v4) => {
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & 0xffff_ff00))
        }
    }
}

/// Counts one hit for the client at `ip` under `name`; `true` while within `cap`. `unknown`
/// only without X-Forwarded-For: behind Railway's edge every request carries one.
pub async fn hit_ip(
    limiter: &dyn RateLimiter,
    name: &str,
    ip: Option<std::net::IpAddr>,
    cap: i64,
    window_secs: i64,
) -> AppResult<bool> {
    let who = ip.map_or_else(|| "unknown".to_owned(), |ip| ip_bucket(ip).to_string());
    limiter
        .hit(&format!("{name}:ip:{who}"), cap, window_secs)
        .await
}

pub const HOUR_SECS: i64 = 3600;
pub const DAY_SECS: i64 = 86_400;

/// The connector for a provider.
pub trait ConnectorSource: Send + Sync {
    fn connector(&self, provider: &str) -> Result<Arc<dyn Connector>, ConnectorError>;
}

impl ConnectorSource for Registry {
    fn connector(&self, provider: &str) -> Result<Arc<dyn Connector>, ConnectorError> {
        Registry::connector(self, provider).map(Arc::from)
    }
}

/// A Client ID Metadata Document as fetched.
pub struct FetchedDocument {
    pub body: serde_json::Value,
    /// From `Cache-Control: max-age`; `None` when absent.
    pub max_age_secs: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct MetadataError(pub String);

/// Fetches the document a metadata-document `client_id` URL names.
#[async_trait]
pub trait ClientMetadataSource: Send + Sync {
    async fn fetch(&self, url: &str) -> Result<FetchedDocument, MetadataError>;
}

#[cfg(test)]
mod bucket_tests {
    use super::*;

    #[test]
    fn mapped_ipv4_shares_the_ipv4_buckets() {
        let mapped: std::net::IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        let v4: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(ip_bucket(mapped), v4);
        assert_eq!(
            net_bucket(mapped),
            "203.0.113.0".parse::<std::net::IpAddr>().unwrap()
        );
        let a: std::net::IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: std::net::IpAddr = "2001:db8:1:ffff::9".parse().unwrap();
        assert_ne!(ip_bucket(a), ip_bucket(b));
        assert_eq!(net_bucket(a), net_bucket(b));
    }
}
