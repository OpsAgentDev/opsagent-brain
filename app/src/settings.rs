use loco_rs::{app::AppContext, Error, Result};
use serde::Deserialize;

/// The `settings:` block of config/*.yaml.
#[derive(Clone, Debug, Deserialize)]
pub struct Settings {
    pub web_base_url: String,
    pub api_base_url: String,
    pub session_secret: String,
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
        Ok(s)
    }

    /// Settings are installed by `middleware::install_adapters`; callers read them from the shared store.
    pub fn get(ctx: &AppContext) -> Self {
        ctx.shared_store
            .get::<Self>()
            .expect("Settings not installed (install_adapters missing)")
    }
}
