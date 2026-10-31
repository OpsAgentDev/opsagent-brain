//! System DNS behind the `HostResolver` port.
use std::net::SocketAddr;

use async_trait::async_trait;
use opsagent_core::endpoint::{EndpointRefusal, HostResolver};

pub struct SystemResolver;

#[async_trait]
impl HostResolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EndpointRefusal> {
        let addrs: Vec<_> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| EndpointRefusal::Unreachable)?
            .collect();
        if addrs.is_empty() {
            return Err(EndpointRefusal::Unreachable);
        }
        Ok(addrs)
    }
}
