//! Magic-link requests, capped per address and per client IP. The caller always answers 202,
//! so a capped request looks exactly like a sent one (no enumeration).
use std::net::IpAddr;

use chrono::{Duration, Utc};
use opsagent_ledger::redis::{self, AsyncCommands};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter};

use crate::{
    api_error::ApiError,
    mailers::{magic_link as mail, Mailer},
    models::{_entities::magic_links as links, magic_links, users as user_model},
};

/// Links per address per hour.
pub const PER_EMAIL: u64 = 5;
/// Requests per client IP per hour.
pub const PER_IP: i64 = 30;
const WINDOW_SECS: i64 = 3600;

/// Counts this request against `ip`; `false` once the hour's cap is passed. Redis trouble
/// counts as over the cap: no mail is sent rather than an unlimited one.
async fn ip_allowed(redis: &redis::Client, ip: IpAddr) -> bool {
    let key = format!("ratelimit:magic_link:ip:{ip}");
    let counted: redis::RedisResult<i64> = async {
        let mut c = redis.get_multiplexed_async_connection().await?;
        let n: i64 = c.incr(&key, 1).await?;
        if n == 1 {
            let _: bool = c.expire(&key, WINDOW_SECS).await?;
        }
        Ok(n)
    }
    .await;
    match counted {
        Ok(n) => n <= PER_IP,
        Err(e) => {
            tracing::error!(error = %e, "magic link rate limit unavailable, not sending");
            false
        }
    }
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
    if let Some(ip) = ip {
        if !ip_allowed(redis, ip).await {
            return Ok(());
        }
    }
    let Some(email) = user_model::normalize_email(raw_email) else {
        return Ok(());
    };
    let recent = links::Entity::find()
        .filter(links::Column::Email.eq(&email))
        .filter(links::Column::CreatedAt.gt(Utc::now() - Duration::seconds(WINDOW_SECS)))
        .count(db)
        .await?;
    if recent >= PER_EMAIL {
        return Ok(());
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
