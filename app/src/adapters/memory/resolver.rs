use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use async_trait::async_trait;
use opsagent_core::endpoint::{EndpointRefusal, HostResolver};

/// A resolver with a fixed name table; IP literals resolve to themselves.
pub struct FixedResolver(HashMap<String, Vec<IpAddr>>);

impl FixedResolver {
    pub fn new(map: HashMap<String, Vec<IpAddr>>) -> Self {
        Self(map)
    }
}

#[async_trait]
impl HostResolver for FixedResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EndpointRefusal> {
        let ips = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self.0.get(host).cloned().unwrap_or_default(),
        };
        if ips.is_empty() {
            return Err(EndpointRefusal::Unreachable);
        }
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}
