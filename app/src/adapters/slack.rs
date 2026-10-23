//! The Slack Web API port and its `reqwest` adapter. The bot token is passed on every call and
//! never held by the client; tokens, channel lists and provider text are never logged.
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{header::RETRY_AFTER, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

pub const API_BASE: &str = "https://slack.com/api";
pub const AUTHORIZE_URL: &str = "https://slack.com/oauth/v2/authorize";
/// Bot scopes, as in the app manifest (ArchBoss docs/ops/slack-app-manifest.json).
pub const BOT_SCOPES: &str = "chat:write,chat:write.public,channels:read,groups:read";
pub const CHANNEL_CAP: usize = 1000;
/// Used when a 429 carries no usable `Retry-After`.
const DEFAULT_RETRY_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackError {
    /// The token no longer works (uninstalled, revoked, invalid).
    Revoked,
    /// The channel was deleted or archived.
    ChannelGone,
    /// Retry after this many seconds.
    RateLimited(u64),
    /// Any other Slack error code, or `transport`, `bad_response`, `http_<status>`.
    Other(String),
}

impl SlackError {
    /// A stable code for logs and redirects (never provider text).
    pub fn code(&self) -> &str {
        match self {
            Self::Revoked => "revoked",
            Self::ChannelGone => "channel_gone",
            Self::RateLimited(_) => "ratelimited",
            Self::Other(c) => c,
        }
    }

    /// Worth retrying on the backoff: rate limits, Slack 5xx and transport failures (connect,
    /// timeout, unparseable body); every other code is permanent, so the caller falls back at once.
    pub fn retryable(&self) -> bool {
        match self {
            Self::RateLimited(_) => true,
            Self::Other(c) => c.starts_with("http_5") || c == "transport" || c == "bad_response",
            Self::Revoked | Self::ChannelGone => false,
        }
    }

    fn from_code(code: &str, retry_after: Option<u64>) -> Self {
        match code {
            "invalid_auth" | "token_revoked" | "account_inactive" => Self::Revoked,
            "channel_not_found" | "is_archived" | "not_in_channel" => Self::ChannelGone,
            "ratelimited" => Self::RateLimited(retry_after.unwrap_or(DEFAULT_RETRY_SECS)),
            // Slack codes are short snake_case words; anything else is not echoed.
            c if c.len() <= 64 && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') => {
                Self::Other(c.into())
            }
            _ => Self::Other("unknown".into()),
        }
    }
}

/// The result of `oauth.v2.access`. No `Debug`: it holds the bot token.
pub struct Install {
    pub access_token: String,
    pub team_id: String,
    pub team_name: String,
    pub bot_user_id: String,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Channel {
    pub id: String,
    pub name: String,
}

#[async_trait]
pub trait SlackClient: Send + Sync {
    /// Exchanges an OAuth `code` for a bot install.
    async fn oauth_access(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<Install, SlackError>;

    /// Unarchived public channels and the private channels the bot is in, at most `CHANNEL_CAP`.
    async fn channels(&self, token: &str) -> Result<Vec<Channel>, SlackError>;

    /// Revokes `token` at Slack (`auth.revoke`).
    async fn revoke(&self, token: &str) -> Result<(), SlackError>;

    /// Posts `text` to `channel`; returns the message `ts`.
    async fn post_message(
        &self,
        token: &str,
        channel: &str,
        text: &str,
        client_msg_id: &str,
    ) -> Result<String, SlackError>;
}

/// `SlackClient` over HTTPS; `base` is the Web API root (`API_BASE`, or a mock in tests).
pub struct HttpSlack {
    base: String,
    http: reqwest::Client,
}

impl HttpSlack {
    pub fn new(base: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            base: base.into().trim_end_matches('/').to_owned(),
            http,
        }
    }

    fn url(&self, method: &str) -> String {
        format!("{}/{method}", self.base)
    }

    /// Sends `req` and returns the body of an `ok: true` response.
    async fn call(req: RequestBuilder) -> Result<Value, SlackError> {
        let res = req
            .send()
            .await
            .map_err(|_| SlackError::Other("transport".into()))?;
        let retry = res
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok());
        let status = res.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(SlackError::RateLimited(retry.unwrap_or(DEFAULT_RETRY_SECS)));
        }
        if !status.is_success() {
            return Err(SlackError::Other(format!("http_{}", status.as_u16())));
        }
        let body: Value = res
            .json()
            .await
            .map_err(|_| SlackError::Other("bad_response".into()))?;
        if body["ok"].as_bool() == Some(true) {
            Ok(body)
        } else {
            Err(SlackError::from_code(
                body["error"].as_str().unwrap_or("unknown"),
                retry,
            ))
        }
    }
}

fn str_field(v: &Value) -> Result<String, SlackError> {
    v.as_str()
        .map(str::to_owned)
        .ok_or_else(|| SlackError::Other("bad_response".into()))
}

#[async_trait]
impl SlackClient for HttpSlack {
    async fn oauth_access(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<Install, SlackError> {
        let form = [
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ];
        let b = Self::call(self.http.post(self.url("oauth.v2.access")).form(&form)).await?;
        Ok(Install {
            access_token: str_field(&b["access_token"])?,
            team_id: str_field(&b["team"]["id"])?,
            team_name: str_field(&b["team"]["name"])?,
            bot_user_id: str_field(&b["bot_user_id"])?,
            scope: str_field(&b["scope"])?,
        })
    }

    async fn channels(&self, token: &str) -> Result<Vec<Channel>, SlackError> {
        let mut out = Vec::new();
        let mut cursor = String::new();
        loop {
            let mut q = vec![
                ("types", "public_channel,private_channel"),
                ("exclude_archived", "true"),
                ("limit", "200"),
            ];
            if !cursor.is_empty() {
                q.push(("cursor", &cursor));
            }
            let req = self
                .http
                .get(self.url("conversations.list"))
                .bearer_auth(token)
                .query(&q);
            let b = Self::call(req).await?;
            let page: Vec<Channel> = serde_json::from_value(b["channels"].clone())
                .map_err(|_| SlackError::Other("bad_response".into()))?;
            out.extend(page);
            cursor = b["response_metadata"]["next_cursor"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if cursor.is_empty() || out.len() >= CHANNEL_CAP {
                out.truncate(CHANNEL_CAP);
                return Ok(out);
            }
        }
    }

    async fn revoke(&self, token: &str) -> Result<(), SlackError> {
        let req = self.http.post(self.url("auth.revoke")).bearer_auth(token);
        Self::call(req).await.map(|_| ())
    }

    async fn post_message(
        &self,
        token: &str,
        channel: &str,
        text: &str,
        client_msg_id: &str,
    ) -> Result<String, SlackError> {
        let body = serde_json::json!({
            "channel": channel, "text": text, "client_msg_id": client_msg_id
        });
        let req = self
            .http
            .post(self.url("chat.postMessage"))
            .bearer_auth(token)
            .json(&body);
        str_field(&Self::call(req).await?["ts"])
    }
}

#[cfg(test)]
mod tests {
    use super::SlackError;

    #[test]
    fn unknown_or_odd_codes_are_not_echoed() {
        assert_eq!(
            SlackError::from_code("Some <provider> text", None),
            SlackError::Other("unknown".into())
        );
        assert_eq!(
            SlackError::from_code("ratelimited", None),
            SlackError::RateLimited(60)
        );
    }

    #[test]
    fn permanent_codes_map_to_revoked_or_channel_gone_and_limits_5xx_and_transport_retry() {
        for c in ["account_inactive", "token_revoked", "invalid_auth"] {
            assert_eq!(SlackError::from_code(c, None), SlackError::Revoked, "{c}");
        }
        for c in ["not_in_channel", "channel_not_found", "is_archived"] {
            assert_eq!(
                SlackError::from_code(c, None),
                SlackError::ChannelGone,
                "{c}"
            );
        }
        let retry = |e: SlackError| e.retryable();
        assert!(retry(SlackError::RateLimited(1)));
        assert!(retry(SlackError::Other("http_503".into())));
        for e in ["transport", "bad_response"] {
            assert!(retry(SlackError::Other(e.into())), "{e}");
        }
        for e in ["http_404", "missing_scope"] {
            assert!(!retry(SlackError::Other(e.into())), "{e}");
        }
        assert!(!retry(SlackError::Revoked) && !retry(SlackError::ChannelGone));
    }
}
