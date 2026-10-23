use loco_rs::{app::AppContext, Error, Result};
use serde::Deserialize;

/// The `settings:` block of config/*.yaml.
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub web_base_url: String,
    pub api_base_url: String,
    pub session_secret: String,
    /// Keys unsubscribe links; empty falls back to `session_secret` (see `unsubscribe_key`).
    #[serde(default)]
    pub unsubscribe_secret: String,
    pub cookie_secure: bool,
    /// Empty means host-only cookie (local development).
    pub cookie_domain: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    /// Empty disables Slack (`slack_not_configured`).
    #[serde(default)]
    pub slack_client_id: String,
    #[serde(default)]
    pub slack_client_secret: String,
    #[serde(default = "slack_api_base_url")]
    pub slack_api_base_url: String,
}

fn slack_api_base_url() -> String {
    crate::adapters::slack::API_BASE.into()
}

impl Settings {
    pub fn load(ctx: &AppContext) -> Result<Self> {
        let raw = ctx
            .config
            .settings
            .clone()
            .ok_or_else(|| Error::string("config: missing `settings:` block"))?;
        let s: Self = serde_json::from_value(raw).map_err(|e| Error::string(&e.to_string()))?;
        if s.session_secret.len() < 16 {
            return Err(Error::string("SESSION_SECRET must be at least 16 bytes"));
        }
        if !s.unsubscribe_secret.is_empty() && s.unsubscribe_secret.len() < 16 {
            return Err(Error::string(
                "UNSUBSCRIBE_SECRET must be at least 16 bytes",
            ));
        }
        Ok(s)
    }

    /// The unsubscribe HMAC secret: `UNSUBSCRIBE_SECRET`, else `SESSION_SECRET` (links issued
    /// under the fallback keep working once it is set to the same value).
    pub fn unsubscribe_key(&self) -> &str {
        if self.unsubscribe_secret.is_empty() {
            &self.session_secret
        } else {
            &self.unsubscribe_secret
        }
    }

    /// Settings are installed by `middleware::install_adapters`; callers read them from the shared store.
    pub fn get(ctx: &AppContext) -> Self {
        ctx.shared_store
            .get::<Self>()
            .expect("Settings not installed (install_adapters missing)")
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::Settings;
    use crate::services::recipients::unsubscribe_token;

    fn settings(unsubscribe: &str) -> Settings {
        serde_json::from_value(serde_json::json!({
            "web_base_url": "", "api_base_url": "", "cookie_secure": true, "cookie_domain": "",
            "github_client_id": "", "github_client_secret": "",
            "session_secret": "session-secret-0123456789",
            "unsubscribe_secret": unsubscribe,
        }))
        .unwrap()
    }

    #[test]
    fn fallback_tokens_verify_once_unsubscribe_secret_equals_session_secret() {
        let id = Uuid::new_v4();
        let before = unsubscribe_token(settings("").unsubscribe_key(), id);
        let after = settings("session-secret-0123456789");
        assert_eq!(unsubscribe_token(after.unsubscribe_key(), id), before);
    }

    #[test]
    fn unsubscribe_secret_wins_when_set() {
        let s = settings("unsubscribe-secret-0123456789");
        assert_eq!(s.unsubscribe_key(), "unsubscribe-secret-0123456789");
        assert_eq!(settings("").unsubscribe_key(), "session-secret-0123456789");
    }
}
