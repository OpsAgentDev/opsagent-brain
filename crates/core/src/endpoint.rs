//! Endpoint safety for customer-supplied AI base URLs: URL shape rules, the public-address
//! test, and the resolver port whose answers get pinned into the request client.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use async_trait::async_trait;
use url::{Host, Url};

/// How strictly a base URL is judged. `Public` is BYOK custom URLs, `Trusted` is OpsAgent's
/// own env URLs (https, no user info/query/fragment, port 443 or none; any host), `Local` is
/// dev/test (`AI_ENDPOINT_ALLOW_PRIVATE`; http allowed, any port).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlPolicy {
    Public,
    Trusted,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EndpointRefusal {
    #[error("scheme")]
    Scheme,
    #[error("form")]
    Form,
    #[error("host")]
    Host,
    #[error("unreachable")]
    Unreachable,
}

impl EndpointRefusal {
    /// The text shown to the owner.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Scheme => "Use an https URL.",
            Self::Form => "Use an https URL with no user name, port, query or fragment.",
            Self::Host => "Use the provider's DNS name, not an IP address or local name.",
            Self::Unreachable => "That address is not reachable from OpsAgent.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedUrl {
    /// No trailing `/`.
    pub base: String,
    pub host: String,
    pub port: u16,
}

/// Judge `raw` under `policy`.
pub fn check_url(raw: &str, policy: UrlPolicy) -> Result<CheckedUrl, EndpointRefusal> {
    let u = Url::parse(raw.trim()).map_err(|_| EndpointRefusal::Form)?;
    let scheme_ok = match policy {
        UrlPolicy::Local => matches!(u.scheme(), "http" | "https"),
        _ => u.scheme() == "https",
    };
    if !scheme_ok {
        return Err(EndpointRefusal::Scheme);
    }
    let user_info = !u.username().is_empty() || u.password().is_some();
    let bad_port = policy != UrlPolicy::Local && u.port().is_some();
    if user_info || u.query().is_some() || u.fragment().is_some() || bad_port {
        return Err(EndpointRefusal::Form);
    }
    let host = match u.host().ok_or(EndpointRefusal::Form)? {
        Host::Domain(d) => {
            let d = d.strip_suffix('.').unwrap_or(d).to_ascii_lowercase();
            if policy == UrlPolicy::Public && is_local_name(&d) {
                return Err(EndpointRefusal::Host);
            }
            d
        }
        Host::Ipv4(_) | Host::Ipv6(_) if policy == UrlPolicy::Public => {
            return Err(EndpointRefusal::Host)
        }
        Host::Ipv4(a) => a.to_string(),
        Host::Ipv6(a) => a.to_string(),
    };
    Ok(CheckedUrl {
        base: u.as_str().trim_end_matches('/').to_string(),
        host,
        port: u.port_or_known_default().ok_or(EndpointRefusal::Scheme)?,
    })
}

fn is_local_name(d: &str) -> bool {
    d == "localhost"
        || [".local", ".internal", ".localhost"]
            .iter()
            .any(|s| d.ends_with(s))
}

/// True when `ip` is a globally routable address. IPv4-mapped IPv6 is judged as its IPv4.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => public_v4(a),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => public_v4(v4),
            None => public_v6(a),
        },
    }
}

fn public_v4(a: Ipv4Addr) -> bool {
    let [o0, o1, o2, _] = a.octets();
    let cgnat = o0 == 100 && (64..128).contains(&o1);
    let benchmark = o0 == 198 && (o1 == 18 || o1 == 19);
    let documentation = matches!(
        (o0, o1, o2),
        (192, 0, 0) | (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    );
    !(o0 == 0 // 0/8 incl. unspecified
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_multicast()
        || a.is_broadcast()
        || o0 >= 240 // reserved
        || cgnat
        || benchmark
        || documentation)
}

fn public_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || s[0] & 0xffc0 == 0xfe80 // fe80::/10
        || s[0] & 0xfe00 == 0xfc00 // fc00::/7
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || s[0] == 0x2002 // 6to4
        || (s[..2] == [0x64, 0xff9b] && (s[2..6] == [0; 4] || s[2] == 1)) // NAT64, 64:ff9b:1::/48
        || (s[..4] == [0; 4] && s[4] == 0xffff && s[5] == 0) // ::ffff:0:0/96 IPv4-translated
        || (s[0] == 0x2001 && (s[1] == 0 || (s[1] == 2 && s[2] == 0))) // Teredo, benchmarking
        // IPv4-compatible ::a.b.c.d is judged as its IPv4
        || (s[..6] == [0; 6] && !public_v4(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8))))
}

/// Port to resolve a host name; failure or no answer is `Unreachable`.
#[async_trait]
pub trait HostResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EndpointRefusal>;
}

/// The addresses a `Public` request may connect to. Any non-public answer refuses the whole
/// name. Other policies use system DNS and pin nothing.
pub async fn pin(
    r: &dyn HostResolver,
    u: &CheckedUrl,
    policy: UrlPolicy,
) -> Result<Vec<SocketAddr>, EndpointRefusal> {
    if policy != UrlPolicy::Public {
        return Ok(vec![]);
    }
    let addrs = r.resolve(&u.host, u.port).await?;
    if addrs.is_empty() || addrs.iter().any(|a| !is_public(a.ip())) {
        return Err(EndpointRefusal::Unreachable);
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn check(u: &str) -> Result<CheckedUrl, EndpointRefusal> {
        check_url(u, UrlPolicy::Public)
    }

    #[test]
    fn check_url_refuses_each_form() {
        assert_eq!(check("http://a.com"), Err(EndpointRefusal::Scheme));
        for u in [
            "https://u:p@a.com",
            "https://a.com?x=1",
            "https://a.com#f",
            "https://a.com:8443",
        ] {
            assert_eq!(check(u), Err(EndpointRefusal::Form), "{u}");
        }
        for u in [
            "https://10.0.0.1",
            "https://[::1]",
            "https://localhost",
            "https://x.local",
            "https://x.internal",
            "https://x.localhost",
        ] {
            assert_eq!(check(u), Err(EndpointRefusal::Host), "{u}");
        }
        let ok = check("https://api.groq.com/openai/v1/").unwrap();
        assert_eq!(ok.base, "https://api.groq.com/openai/v1");
        assert_eq!((ok.host.as_str(), ok.port), ("api.groq.com", 443));
    }

    #[test]
    fn check_url_normalises_case_and_trailing_dot() {
        assert_eq!(check("https://LOCALHOST./v1"), Err(EndpointRefusal::Host));
        assert_eq!(
            check("https://metadata.internal."),
            Err(EndpointRefusal::Host)
        );
    }

    #[test]
    fn check_url_trusted_allows_ip_and_local_but_needs_https() {
        let t = |u| check_url(u, UrlPolicy::Trusted);
        assert_eq!(t("https://10.0.0.1/v1").unwrap().port, 443);
        for u in ["https://u@a.com", "https://a.com?x=1", "https://a.com:8443"] {
            assert_eq!(t(u), Err(EndpointRefusal::Form), "{u}");
        }
        assert_eq!(t("https://localhost/v1").unwrap().host, "localhost");
        assert_eq!(t("http://api.example.com"), Err(EndpointRefusal::Scheme));
    }

    #[test]
    fn check_url_local_allows_http_loopback() {
        let c = check_url("http://127.0.0.1:9999/v1", UrlPolicy::Local).unwrap();
        assert_eq!(
            (c.base.as_str(), c.port),
            ("http://127.0.0.1:9999/v1", 9999)
        );
        assert_eq!(
            check_url("http://u@127.0.0.1", UrlPolicy::Local),
            Err(EndpointRefusal::Form)
        );
    }

    #[test]
    fn is_public_by_class() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "2002:a00:1::1",
            "192.0.0.8",
            "::ffff:0:a9fe:a9fe",
            "2001::1",
            "2001:2::1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "2606:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    struct Table(HashMap<String, Vec<IpAddr>>);

    #[async_trait]
    impl HostResolver for Table {
        async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EndpointRefusal> {
            let ips = self.0.get(host).ok_or(EndpointRefusal::Unreachable)?;
            Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
        }
    }

    fn table(ips: &[&str]) -> Table {
        let ips = ips.iter().map(|i| i.parse().unwrap()).collect();
        Table(HashMap::from([("a.test".to_string(), ips)]))
    }

    fn url(host: &str) -> CheckedUrl {
        check(&format!("https://{host}")).unwrap()
    }

    #[tokio::test]
    async fn pin_refuses_mixed_public_and_private() {
        let r = table(&["1.1.1.1", "10.0.0.1"]);
        let got = pin(&r, &url("a.test"), UrlPolicy::Public).await;
        assert_eq!(got, Err(EndpointRefusal::Unreachable));
    }

    #[tokio::test]
    async fn pin_returns_checked_addresses() {
        let got = pin(&table(&["1.1.1.1"]), &url("a.test"), UrlPolicy::Public).await;
        assert_eq!(got, Ok(vec!["1.1.1.1:443".parse().unwrap()]));
    }

    #[tokio::test]
    async fn pin_skips_lookup_off_public() {
        // The name is unknown to the table: a lookup would fail.
        let r = table(&[]);
        for p in [UrlPolicy::Trusted, UrlPolicy::Local] {
            assert_eq!(pin(&r, &url("nope.test"), p).await, Ok(vec![]));
        }
    }
}
