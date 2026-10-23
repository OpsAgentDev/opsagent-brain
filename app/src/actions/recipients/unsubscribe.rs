use std::sync::Arc;

use opsagent_core::{audit::AuditEntry, repo::Clock};
use opsagent_deliver::repo::Suppression;

use super::tokens::{email_hash, verify_unsubscribe};
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// Unsubscribes the recipient a valid token names and suppresses its address everywhere.
/// Idempotent; 410 for a forged token or a deleted recipient.
pub struct Unsubscribe {
    uow: Arc<dyn UnitOfWork>,
    /// `Settings::unsubscribe_key`: the unsubscribe secret, else the session secret.
    secret: String,
    clock: Arc<dyn Clock>,
}

impl Unsubscribe {
    pub fn new(uow: Arc<dyn UnitOfWork>, secret: &str, clock: Arc<dyn Clock>) -> Self {
        let secret = secret.to_owned();
        Self { uow, secret, clock }
    }

    pub async fn run(&self, token: &str) -> AppResult<()> {
        let gone = AppError::Gone("unsubscribe_token_invalid");
        let Some(id) = verify_unsubscribe(&self.secret, token) else {
            return Err(gone);
        };
        let row = self
            .uow
            .recipients()
            .by_id_unscoped(id)
            .await?
            .ok_or(gone)?;
        let tx = self.uow.begin().await?;
        let repo = tx.recipients();
        if repo
            .unsubscribe(row.organisation_id, row.id, self.clock.now())
            .await?
        {
            let target = ("recipient", row.id.to_string());
            let org = row.organisation_id;
            let entry = AuditEntry::system(org, "recipient.unsubscribe", target, "success");
            tx.audit()
                .record(entry.with_meta(serde_json::json!({})))
                .await?;
        }
        let hash = email_hash(&row.email);
        repo.suppress(None, &hash, Suppression::Unsubscribed)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
