use std::sync::Arc;

use opsagent_core::audit::AuditEntry;
use opsagent_deliver::repo::SLACK;
use opsagent_secrets::Kek;
use uuid::Uuid;

use super::open_token;
use crate::{
    actions::uow::UnitOfWork,
    adapters::slack::SlackClient,
    error::{AppError, AppResult},
};

/// Removes integration `id` for owner `actor`. A Slack token is revoked at Slack first (best
/// effort), while the sealed token still exists.
pub struct DeleteIntegration {
    uow: Arc<dyn UnitOfWork>,
    kek: Arc<dyn Kek>,
    slack: Arc<dyn SlackClient>,
}

impl DeleteIntegration {
    pub fn new(uow: Arc<dyn UnitOfWork>, kek: Arc<dyn Kek>, slack: Arc<dyn SlackClient>) -> Self {
        Self { uow, kek, slack }
    }

    pub async fn run(&self, organisation_id: Uuid, actor: Uuid, id: Uuid) -> AppResult<()> {
        let all = self.uow.integrations().list(organisation_id).await?;
        let row = all
            .into_iter()
            .find(|i| i.id == id)
            .ok_or(AppError::NotFound)?;
        if row.kind == SLACK {
            match open_token(&*self.uow, self.kek.as_ref(), &row).await {
                Ok(t) => {
                    if let Err(e) = self.slack.revoke(&t).await {
                        tracing::warn!(error_code = e.code(), "slack token revoke failed");
                    }
                }
                Err(_) => tracing::warn!(
                    error_code = "token_unreadable",
                    "slack token revoke skipped"
                ),
            }
        }
        let tx = self.uow.begin().await?;
        if !tx.integrations().delete(organisation_id, id).await? {
            return Err(AppError::NotFound);
        }
        let target = Some(("integration", id.to_string()));
        let entry = AuditEntry::member(Some(organisation_id), actor, "integration.delete", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::org::Role;
    use opsagent_deliver::repo::IntegrationsRepo;

    use super::*;
    use crate::{
        actions::{
            integrations::{test_support::*, Callback, FinishSlackInstall, InstallError},
            recipients::test_support::{kek, member, org},
        },
        adapters::memory::MemStore,
        config::Config,
    };

    fn settings() -> Config {
        let vars = |k: &str| match k {
            "APP_BASE_URL" => Some("https://api.test".to_owned()),
            "SLACK_CLIENT_ID" => Some("cid".to_owned()),
            "SLACK_CLIENT_SECRET" => Some("csecret".to_owned()),
            _ => None,
        };
        Config::from_vars(vars).unwrap_or_else(|e| panic!("{e}"))
    }

    #[tokio::test]
    async fn delete_integration_revokes_before_delete() {
        let store = MemStore::default();
        let o = org(&store, "Acme").await;
        let owner = member(&store, o, "owner@example.com", Role::Owner)
            .await
            .user_id;
        let slack = FakeSlack::new(&store, o);
        let (uow, kek) = (Arc::new(store.clone()), Arc::new(kek()));
        let finish = FinishSlackInstall::new(uow.clone(), kek.clone(), slack.clone(), settings());
        let callback = Callback {
            code: Some("good".into()),
            error: None,
        };
        finish.run(o, owner, callback).await.unwrap();
        let id = store.list(o).await.unwrap()[0].id;
        let delete = DeleteIntegration::new(uow, kek, slack.clone());
        let err = delete.run(o, owner, Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound), "{err:?}");
        delete.run(o, owner, id).await.unwrap();
        assert_eq!(
            slack.calls(),
            ["oauth_access:good", "revoke:xoxb-secret-token:held=1"]
        );
        assert!(store.list(o).await.unwrap().is_empty());
        let actions: Vec<_> = store
            .audit_entries()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions, ["integration.slack_connect", "integration.delete"]);
    }

    #[tokio::test]
    async fn finish_install_is_owner_only_and_seals_the_token() {
        let store = MemStore::default();
        let o = org(&store, "Acme").await;
        let m = member(&store, o, "dev@example.com", Role::Member)
            .await
            .user_id;
        let slack = FakeSlack::new(&store, o);
        let (uow, kek) = (Arc::new(store.clone()), Arc::new(kek()));
        let finish = FinishSlackInstall::new(uow, kek.clone(), slack, settings());
        let callback = Callback {
            code: Some("good".into()),
            error: None,
        };
        let err = finish.run(o, m, callback).await.unwrap_err();
        assert!(
            matches!(err, InstallError::App(AppError::Forbidden)),
            "{err:?}"
        );
        finish.save(o, m, &install("T1")).await.unwrap();
        let row = &store.list(o).await.unwrap()[0];
        assert_ne!(row.ciphertext, b"xoxb-secret-token".to_vec());
        let plain = open_token(&store, kek.as_ref(), row).await.unwrap();
        assert_eq!(plain.as_str(), "xoxb-secret-token");
    }
}
