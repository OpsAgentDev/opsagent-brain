//! Magic-link requests, capped per address and per client IP. The caller always answers 202,
//! so a capped request looks exactly like a sent one (no enumeration).
use std::net::{IpAddr, Ipv6Addr};

use opsagent_ledger::redis::{self, Script};
use sea_orm::DatabaseConnection;
use sha2::{Digest, Sha256};

use crate::{
    api_error::ApiError,
    mailers::{magic_link as mail, Mailer},
    models::{magic_links, users as user_model},
};

/// Links per address per hour.
pub const PER_EMAIL: i64 = 5;
/// Requests per client IP (IPv6: per /64) per hour.
pub const PER_IP: i64 = 30;
const WINDOW_SECS: i64 = 3600;

/// `INCR`, with the window's `EXPIRE` set by the first hit, in one atomic step: a counter
/// can never be left without a TTL.
const COUNT: &str = r#"local n = redis.call('INCR', KEYS[1]) if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end return n"#;

/// Counts one hit on `key`; `true` while the hour's count is within `cap`.
async fn hit(
    c: &mut redis::aio::MultiplexedConnection,
    key: &str,
    cap: i64,
) -> redis::RedisResult<bool> {
    let n: i64 = Script::new(COUNT)
        .key(key)
        .arg(WINDOW_SECS)
        .invoke_async(c)
        .await?;
    Ok(n <= cap)
}

/// The IP cap's bucket: an IPv6 client owns at least a /64, so the /64 is one client.
fn ip_bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        v4 => v4,
    }
}

/// Counts this request against `ip` (when known), then against the normalised `email`.
/// `false` once either hour's cap is passed.
pub async fn rate_limit(
    redis: &redis::Client,
    email: &str,
    ip: Option<IpAddr>,
) -> redis::RedisResult<bool> {
    let mut c = redis.get_multiplexed_async_connection().await?;
    if let Some(ip) = ip {
        let key = format!("ratelimit:magic_link:ip:{}", ip_bucket(ip));
        if !hit(&mut c, &key, PER_IP).await? {
            return Ok(false);
        }
    }
    let key = format!("ratelimit:magic_link:email:{:x}", Sha256::digest(email));
    hit(&mut c, &key, PER_EMAIL).await
}

/// Sends a sign-in link to `raw_email` unless the address is invalid or either cap is passed.
/// `ip`: the client address as reported by the trusted proxy, when there is one.
pub async fn request_link(
    db: &DatabaseConnection,
    redis: &redis::Client,
    mailer: &dyn Mailer,
    web_base_url: &str,
    raw_email: &str,
    ip: Option<IpAddr>,
) -> Result<(), ApiError> {
    let Some(email) = user_model::normalize_email(raw_email) else {
        return Ok(());
    };
    match rate_limit(redis, &email, ip).await {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        // Fail closed: no mail rather than an unlimited one.
        Err(e) => {
            tracing::warn!(error = %e, "magic link rate limit unavailable, not sending");
            return Ok(());
        }
    }
    let user = user_model::find_or_create_by_email(db, &email).await?;
    let token = magic_links::issue(db, user.id, &email).await?;
    // The web page POSTs the token to `/auth/magic-link/redeem` after a click (login-CSRF safe).
    let link = format!(
        "{}/auth/callback?token={token}",
        web_base_url.trim_end_matches('/')
    );
    if let Err(e) = mailer.send(mail::magic_link(&email, &link)).await {
        tracing::error!(error = %e, "magic link mail failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_buckets_by_64_and_ipv4_as_is() {
        let b = |s: &str| ip_bucket(s.parse().unwrap()).to_string();
        assert_eq!(b("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::");
        assert_eq!(b("2001:db8:1:2:ffff::1"), "2001:db8:1:2::");
        assert_eq!(b("203.0.113.7"), "203.0.113.7");
        // IPv4-mapped IPv6 is the IPv4 client, not the shared `::` bucket.
        assert_eq!(b("::ffff:203.0.113.7"), "203.0.113.7");
    }
}
