//! The client address for rate limits: the rightmost `X-Forwarded-For` value, which the single
//! trusted proxy in front of the app (Railway's edge) appends. Same as the pre-switch
//! `RemoteIP::Forwarded` with `RightmostXForwardedFor`; the socket address is never used.
use std::{convert::Infallible, net::IpAddr};

use axum::{extract::FromRequestParts, http::request::Parts};

pub struct ClientIp(pub Option<IpAddr>);

impl ClientIp {
    fn from_headers(headers: &axum::http::HeaderMap) -> Self {
        let ip = headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok());
        Self(ip)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Infallible;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Infallible> {
        Ok(Self::from_headers(&parts.headers))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::ClientIp;

    fn ip(values: &[&str]) -> Option<String> {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        ClientIp::from_headers(&h).0.map(|i| i.to_string())
    }

    #[test]
    fn client_ip_takes_rightmost_xff_verbatim() {
        // No private or "trusted" hop is skipped: the last value wins as is.
        assert_eq!(
            ip(&["51.50.51.50,10.0.0.1, 192.168.1.1"]).as_deref(),
            Some("192.168.1.1")
        );
        assert_eq!(ip(&["51.50.51.50"]).as_deref(), Some("51.50.51.50"));
        // Only the last header counts.
        assert_eq!(
            ip(&["1.1.1.1", "2001:db8::1"]).as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(ip(&[]), None);
        assert_eq!(ip(&["1.1.1.1, not-an-ip"]), None);
    }
}
