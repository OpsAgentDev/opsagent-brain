//! The client address for rate limits. Behind Cloudflare the rightmost `X-Forwarded-For` value
//! is a Cloudflare edge, which would put every caller in one bucket. So when
//! `TRUSTED_PROXY_SECRET` is set and the request carries it in `X-Origin-Auth` (Cloudflare adds
//! the header, so only its traffic has it), `CF-Connecting-IP` is the client. Otherwise it is
//! the rightmost `X-Forwarded-For` value, which the single trusted proxy in front of the app
//! (Railway's edge) appends. The socket address is never used.
use std::{convert::Infallible, net::IpAddr};

use axum::{extract::FromRequestParts, http::request::Parts};
use subtle::ConstantTimeEq;

use crate::state::AppState;

pub struct ClientIp(pub Option<IpAddr>);

impl ClientIp {
    fn from_headers(headers: &axum::http::HeaderMap, trusted_secret: Option<&str>) -> Self {
        let trusted = trusted_secret.is_some_and(|secret| {
            headers
                .get("x-origin-auth")
                .is_some_and(|v| v.as_bytes().ct_eq(secret.as_bytes()).into())
        });
        if trusted {
            let cf = headers
                .get("cf-connecting-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok());
            if cf.is_some() {
                return Self(cf);
            }
        }
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

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = Infallible;
    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, Infallible> {
        let secret = s.config.trusted_proxy_secret.as_deref();
        Ok(Self::from_headers(&parts.headers, secret))
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
        ClientIp::from_headers(&h, None).0.map(|i| i.to_string())
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

    fn cf(secret: Option<&str>, auth: Option<&str>, cf_ip: &str) -> Option<String> {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("172.70.0.1"));
        h.insert("cf-connecting-ip", HeaderValue::from_str(cf_ip).unwrap());
        if let Some(a) = auth {
            h.insert("x-origin-auth", HeaderValue::from_str(a).unwrap());
        }
        ClientIp::from_headers(&h, secret).0.map(|i| i.to_string())
    }

    #[test]
    fn cf_connecting_ip_is_used_only_with_the_matching_origin_secret() {
        let edge = Some("172.70.0.1".to_owned());
        let user = Some("203.0.113.7".to_owned());
        // Unset secret: the header is ignored even if the request claims to be trusted.
        assert_eq!(cf(None, Some("s3cret"), "203.0.113.7"), edge);
        // Set and correct.
        assert_eq!(cf(Some("s3cret"), Some("s3cret"), "203.0.113.7"), user);
        // Set but wrong or missing: an attacker cannot spoof.
        assert_eq!(cf(Some("s3cret"), Some("wrong"), "203.0.113.7"), edge);
        assert_eq!(cf(Some("s3cret"), None, "203.0.113.7"), edge);
        // Trusted but garbage: falls back to X-Forwarded-For.
        assert_eq!(cf(Some("s3cret"), Some("s3cret"), "not-an-ip"), edge);
    }
}
