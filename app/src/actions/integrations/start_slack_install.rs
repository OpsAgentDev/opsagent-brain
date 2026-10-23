use axum::http::StatusCode;

use super::{configured, redirect_uri, SLACK_NOT_CONFIGURED};
use crate::{
    adapters::slack::{AUTHORIZE_URL, BOT_SCOPES},
    error::{AppError, AppResult},
    settings::Settings,
};

/// The Slack consent URL carrying `state`; 503 `slack_not_configured` without client
/// credentials. The caller keeps `state` (in the session) to check the callback against.
pub struct StartSlackInstall {
    settings: Settings,
}

impl StartSlackInstall {
    pub fn new(settings: Settings) -> Self {
        Self { settings }
    }

    pub fn run(&self, state: &str) -> AppResult<String> {
        let s = &self.settings;
        if !configured(s) {
            return Err(AppError::Refused {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: SLACK_NOT_CONFIGURED,
                detail: "Slack is not configured.".into(),
            });
        }
        let e = |v: &str| urlencoding::encode(v).into_owned();
        Ok(format!(
            "{AUTHORIZE_URL}?client_id={}&scope={}&redirect_uri={}&state={}",
            e(&s.slack_client_id),
            e(BOT_SCOPES),
            e(&redirect_uri(s)),
            e(state)
        ))
    }
}
