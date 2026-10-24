//! Fetches Client ID Metadata Documents with an SSRF guard: https only, public addresses only
//! (checked after DNS resolution, and the connection is pinned to the vetted address), no
//! redirects, 5 s timeout, 64 KB cap.
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use async_trait::async_trait;
use reqwest::{header, redirect::Policy, Url};

use crate::actions::{ClientMetadataSource, FetchedDocument, MetadataError};

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BYTES: usize = 65_536;

pub struct HttpClientMetadata;

fn err(msg: &str) -> MetadataError {
    MetadataError(msg.into())
}

fn v4_allowed(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        // 100.64.0.0/10 carrier-grade NAT
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 240.0.0.0/4 reserved
        || o[0] >= 240)
}

/// True for a globally routable address.
pub fn address_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_allowed(v4),
        IpAddr::V6(v6) => {
            // ::ffff:a.b.c.d and ::a.b.c.d are judged as the IPv4 address they carry.
            if let Some(v4) = v6.to_ipv4() {
                return v4_allowed(v4);
            }
            let s = v6.segments();
            // 64:ff9b::/96 (NAT64) carries an IPv4 address in its last 32 bits.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [a, b] = s[6].to_be_bytes();
                let [c, d] = s[7].to_be_bytes();
                return v4_allowed(Ipv4Addr::new(a, b, c, d));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique local
                || (s[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn max_age(h: &header::HeaderMap) -> Option<u64> {
    let cc = h.get(header::CACHE_CONTROL)?.to_str().ok()?;
    cc.split(',').find_map(|d| {
        let d = d.trim().to_ascii_lowercase();
        if d == "no-store" || d == "no-cache" {
            return Some(0);
        }
        d.strip_prefix("max-age=")?.trim().parse().ok()
    })
}

#[async_trait]
impl ClientMetadataSource for HttpClientMetadata {
    async fn fetch(&self, url: &str) -> Result<FetchedDocument, MetadataError> {
        let url = Url::parse(url).map_err(|_| err("not a URL"))?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err(err("only plain https URLs are fetched"));
        }
        let host = url.host_str().ok_or_else(|| err("no host"))?.to_owned();
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| err("host did not resolve"))?
            .collect();
        // One private answer among public ones is still refused (DNS-rebinding mixes).
        if addrs.is_empty() || !addrs.iter().all(|a| address_allowed(a.ip())) {
            return Err(err("host resolves to a non-public address"));
        }
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(TIMEOUT)
            .https_only(true)
            // Pins the connection to the vetted addresses; no second lookup happens.
            .resolve_to_addrs(&host, &addrs)
            .build()
            .map_err(|_| err("client could not be built"))?;
        let mut res = client
            .get(url)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| err("request failed"))?;
        if !res.status().is_success() {
            return Err(err("non-success status"));
        }
        if res.content_length().is_some_and(|n| n > MAX_BYTES as u64) {
            return Err(err("document too large"));
        }
        let max_age_secs = max_age(res.headers());
        let mut body = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|_| err("read failed"))? {
            if body.len() + chunk.len() > MAX_BYTES {
                return Err(err("document too large"));
            }
            body.extend_from_slice(&chunk);
        }
        let body = serde_json::from_slice(&body).map_err(|_| err("not JSON"))?;
        Ok(FetchedDocument { body, max_age_secs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_allowed_rejects_private() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
        ] {
            assert!(!address_allowed(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"] {
            assert!(address_allowed(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn max_age_parses_cache_control() {
        let h = |v: &str| {
            let mut m = header::HeaderMap::new();
            m.insert(header::CACHE_CONTROL, v.parse().unwrap());
            max_age(&m)
        };
        assert_eq!(h("public, max-age=300"), Some(300));
        assert_eq!(h("no-store"), Some(0));
        assert_eq!(h("public"), None);
    }
}
