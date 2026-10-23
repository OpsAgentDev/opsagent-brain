//! Integration use cases: Slack install (OAuth), channel listing, listing, removal. Bot tokens
//! are sealed with the org DEK through `creds` (AAD table `integrations`, column `ciphertext`)
//! and never logged.
mod delete_integration;
mod finish_slack_install;
mod list_integrations;
mod list_slack_channels;
mod start_slack_install;

use opsagent_deliver::repo::{Integration, SealedToken};
use opsagent_secrets::{Aad, Kek};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use delete_integration::DeleteIntegration;
pub use finish_slack_install::{FinishSlackInstall, InstallError};
pub use list_integrations::ListIntegrations;
pub use list_slack_channels::ListSlackChannels;
pub use start_slack_install::StartSlackInstall;

use crate::{
    actions::uow::Repos,
    config::Config,
    creds::Dek,
    error::{AppError, AppResult},
};

/// Another organisation already holds this Slack workspace (one workspace, one organisation).
pub const WORKSPACE_IN_USE: &str = "slack_workspace_in_use";
pub const SLACK_NOT_CONFIGURED: &str = "slack_not_configured";

pub struct Integrations {
    pub start_slack_install: StartSlackInstall,
    pub finish_slack_install: FinishSlackInstall,
    pub list_slack_channels: ListSlackChannels,
    pub list_integrations: ListIntegrations,
    pub delete_integration: DeleteIntegration,
}

fn aad(organisation_id: Uuid) -> Aad {
    Aad {
        organisation_id,
        table: "integrations",
        column: "ciphertext",
    }
}

fn configured(s: &Config) -> bool {
    !s.slack_client_id.is_empty() && !s.slack_client_secret.is_empty()
}

fn redirect_uri(s: &Config) -> String {
    format!(
        "{}/v1/integrations/slack/callback",
        s.api_base_url.trim_end_matches('/')
    )
}

/// `token` sealed under the org DEK, with the KEK version to store beside it.
async fn seal_token(
    repos: &dyn Repos,
    kek: &dyn Kek,
    organisation_id: Uuid,
    token: &str,
) -> AppResult<SealedToken> {
    let dek = Dek::of(repos.orgs(), kek, organisation_id).await?;
    let sealed = dek.seal_bytes(token.as_bytes(), &aad(organisation_id));
    Ok(SealedToken {
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce.to_vec(),
        kek_version: dek.version,
    })
}

/// The integration's plaintext token.
pub async fn open_token(
    repos: &dyn Repos,
    kek: &dyn Kek,
    row: &Integration,
) -> AppResult<Zeroizing<String>> {
    let org = row.organisation_id;
    let dek = Dek::of(repos.orgs(), kek, org).await?;
    let plain = dek.open_bytes(&row.ciphertext, &row.nonce, &aad(org))?;
    String::from_utf8(plain.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| AppError::Internal("integration token is not UTF-8".into()))
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use opsagent_deliver::repo::IntegrationsRepo;
    use uuid::Uuid;

    use crate::adapters::{
        memory::MemStore,
        slack::{Channel, Install, SlackClient, SlackError},
    };

    /// Records each call, and for `revoke` whether the org still held an integration then.
    pub struct FakeSlack {
        pub store: MemStore,
        pub org: Uuid,
        pub calls: Mutex<Vec<String>>,
    }

    impl FakeSlack {
        pub fn new(store: &MemStore, org: Uuid) -> Arc<Self> {
            let (store, calls) = (store.clone(), Mutex::default());
            Arc::new(Self { store, org, calls })
        }

        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn record(&self, call: String) {
            self.calls.lock().unwrap().push(call);
        }
    }

    pub fn install(team: &str) -> Install {
        Install {
            access_token: "xoxb-secret-token".into(),
            team_id: team.into(),
            team_name: "Acme".into(),
            bot_user_id: "U0BOT".into(),
            scope: "chat:write".into(),
        }
    }

    #[async_trait]
    impl SlackClient for FakeSlack {
        async fn oauth_access(
            &self,
            _: &str,
            _: &str,
            code: &str,
            _: &str,
        ) -> Result<Install, SlackError> {
            self.record(format!("oauth_access:{code}"));
            Ok(install("T1"))
        }

        async fn channels(&self, token: &str) -> Result<Vec<Channel>, SlackError> {
            self.record(format!("channels:{token}"));
            Ok(vec![])
        }

        async fn revoke(&self, token: &str) -> Result<(), SlackError> {
            let held = self.store.list(self.org).await.unwrap().len();
            self.record(format!("revoke:{token}:held={held}"));
            Ok(())
        }

        async fn post_message(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<String, SlackError> {
            unreachable!("not used by integration actions")
        }
    }
}
