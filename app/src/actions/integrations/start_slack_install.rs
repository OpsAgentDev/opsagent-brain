use super::{configured, not_configured, redirect_uri, SlackSettings};
use crate::{
    adapters::slack::{AUTHORIZE_URL, BOT_SCOPES},
    error::AppResult,
};

/// The Slack consent URL carrying `state`; 503 `slack_not_configured` without client
/// credentials. The caller keeps `state` (in the session) to check the callback against.
pub struct StartSlackInstall {
    settings: SlackSettings,
}

impl StartSlackInstall {
    pub fn new(settings: SlackSettings) -> Self {
        Self { settings }
    }

    pub fn run(&self, state: &str) -> AppResult<String> {
        let s = &self.settings;
        if !configured(s) {
            return Err(not_configured());
        }
        let e = |v: &str| urlencoding::encode(v).into_owned();
        Ok(format!(
            "{AUTHORIZE_URL}?client_id={}&scope={}&redirect_uri={}&state={}",
            e(&s.client_id),
            e(BOT_SCOPES),
            e(&redirect_uri(s)),
            e(state)
        ))
    }
}
