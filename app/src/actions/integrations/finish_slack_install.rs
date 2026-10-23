use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{audit::AuditEntry, org::Role, repo::RepoError};
use opsagent_deliver::repo::SLACK;
use opsagent_secrets::Kek;
use serde_json::json;
use uuid::Uuid;

use super::{configured, redirect_uri, seal_token, SLACK_NOT_CONFIGURED, WORKSPACE_IN_USE};
use crate::{
    actions::uow::UnitOfWork,
    adapters::slack::{Install, SlackClient, SlackError},
    api_error::ApiError,
    config::Config,
    error::{AppError, AppResult},
};

/// Why an install did not finish; the callback redirects with `redirect_code`.
#[derive(Debug)]
pub enum InstallError {
    /// Slack refused the code exchange (logged by code).
    Exchange(SlackError),
    App(AppError),
}

impl From<AppError> for InstallError {
    fn from(e: AppError) -> Self {
        Self::App(e)
    }
}

impl InstallError {
    /// The `code=` of the error redirect: Slack's code, `slack_workspace_in_use`,
    /// `slack_not_configured`, else `internal` (logged here).
    pub fn redirect_code(self) -> String {
        match self {
            Self::Exchange(e) => urlencoding::encode(e.code()).into_owned(),
            Self::App(AppError::Refused { code, .. })
                if code == WORKSPACE_IN_USE || code == SLACK_NOT_CONFIGURED =>
            {
                code.into()
            }
            Self::App(e) => {
                // The mapping logs an internal error once, as every route does.
                let _ = ApiError::from(e);
                "internal".into()
            }
        }
    }
}

/// Completes a Slack install for `actor`, an owner of the organisation the OAuth state names:
/// exchanges the code, seals the bot token and makes it the org's active Slack integration.
pub struct FinishSlackInstall {
    uow: Arc<dyn UnitOfWork>,
    kek: Arc<dyn Kek>,
    slack: Arc<dyn SlackClient>,
    settings: Config,
}

impl FinishSlackInstall {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        kek: Arc<dyn Kek>,
        slack: Arc<dyn SlackClient>,
        settings: Config,
    ) -> Self {
        Self {
            uow,
            kek,
            slack,
            settings,
        }
    }

    /// 403 unless `user_id` owns `organisation_id` (checked before the callback reads Slack's
    /// answer, as the install may have outlived the ownership).
    pub async fn ensure_owner(&self, organisation_id: Uuid, user_id: Uuid) -> AppResult<()> {
        let members = self.uow.orgs().members(organisation_id).await?;
        let owner = |m: &opsagent_core::org::Member| m.user_id == user_id && m.role == Role::Owner;
        members
            .iter()
            .any(owner)
            .then_some(())
            .ok_or(AppError::Forbidden)
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        actor: Uuid,
        code: &str,
    ) -> Result<(), InstallError> {
        let s = &self.settings;
        if !configured(s) {
            return Err(AppError::Refused {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: SLACK_NOT_CONFIGURED,
                detail: "Slack is not configured.".into(),
            }
            .into());
        }
        let redirect = redirect_uri(s);
        let exchange =
            self.slack
                .oauth_access(&s.slack_client_id, &s.slack_client_secret, code, &redirect);
        let install = exchange.await.map_err(|e| {
            tracing::warn!(error_code = e.code(), "slack oauth exchange failed");
            InstallError::Exchange(e)
        })?;
        Ok(self.save(organisation_id, actor, &install).await?)
    }

    /// Seals the bot token and makes it the org's active Slack integration (a reinstall
    /// replaces it). 409 `slack_workspace_in_use` when another organisation's active
    /// integration has the team.
    pub async fn save(
        &self,
        organisation_id: Uuid,
        actor: Uuid,
        install: &Install,
    ) -> AppResult<()> {
        let token = seal_token(
            &*self.uow,
            self.kek.as_ref(),
            organisation_id,
            &install.access_token,
        )
        .await?;
        let config = json!({
            "team_id": install.team_id, "team_name": install.team_name,
            "bot_user_id": install.bot_user_id, "scope": install.scope,
        });
        let tx = self.uow.begin().await?;
        tx.integrations()
            .upsert_slack(organisation_id, config, token)
            .await
            .map_err(|e| match e {
                RepoError::Conflict(_) => AppError::Refused {
                    status: StatusCode::CONFLICT,
                    code: WORKSPACE_IN_USE,
                    detail: "This Slack workspace is linked to another organisation.".into(),
                },
                e => e.into(),
            })?;
        let target = Some(("integration", SLACK.into()));
        let entry = AuditEntry::member(
            Some(organisation_id),
            actor,
            "integration.slack_connect",
            target,
        );
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }
}
