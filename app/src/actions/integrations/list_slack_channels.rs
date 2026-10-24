use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::repo::Clock;
use opsagent_deliver::repo::{REVOKED, SLACK};
use opsagent_secrets::Kek;
use uuid::Uuid;

use super::open_token;
use crate::{
    actions::uow::UnitOfWork,
    adapters::slack::{Channel, SlackClient, SlackError},
    error::{AppError, AppResult},
};

/// Channels the bot can post to. A revoked token marks the integration `revoked`.
pub struct ListSlackChannels {
    uow: Arc<dyn UnitOfWork>,
    kek: Arc<dyn Kek>,
    slack: Arc<dyn SlackClient>,
    clock: Arc<dyn Clock>,
}

fn refused(status: StatusCode, code: &'static str, detail: &str) -> AppError {
    let detail = detail.into();
    AppError::Refused {
        status,
        code,
        detail,
    }
}

fn revoked() -> AppError {
    let detail = "Slack access was revoked; reconnect Slack.";
    refused(StatusCode::SERVICE_UNAVAILABLE, "slack_revoked", detail)
}

impl ListSlackChannels {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        kek: Arc<dyn Kek>,
        slack: Arc<dyn SlackClient>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            uow,
            kek,
            slack,
            clock,
        }
    }

    pub async fn run(&self, organisation_id: Uuid) -> AppResult<Vec<Channel>> {
        let repo = self.uow.integrations();
        let all = repo.list(organisation_id).await?;
        let Some(row) = all.into_iter().find(|i| i.kind == SLACK) else {
            let detail = "Slack is not connected.";
            return Err(refused(
                StatusCode::NOT_FOUND,
                "slack_not_connected",
                detail,
            ));
        };
        if row.status == REVOKED {
            return Err(revoked());
        }
        let token = open_token(&*self.uow, self.kek.as_ref(), &row).await?;
        match self.slack.channels(&token).await {
            Ok(c) => Ok(c),
            Err(SlackError::Revoked) => {
                repo.mark_revoked(organisation_id, row.id, self.clock.now())
                    .await?;
                Err(revoked())
            }
            Err(SlackError::RateLimited(s)) => Err(AppError::RateLimited {
                detail: "Slack is rate limiting; retry later.".into(),
                retry_after_secs: s,
            }),
            Err(e) => {
                tracing::warn!(error_code = e.code(), "slack channel list failed");
                let detail = "Slack did not answer as expected.";
                Err(refused(StatusCode::BAD_GATEWAY, "slack_error", detail))
            }
        }
    }
}
