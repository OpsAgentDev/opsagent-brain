use std::sync::Arc;

use opsagent_core::{audit::AuditEntry, repo::Clock};

use super::MailGuard;
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
    tokens::hash_token,
};

/// Activates the pending recipient holding confirm `token`; 410 if unknown, used or expired.
/// Anonymous: the single-use token is the authorisation.
pub struct ConfirmRecipient {
    uow: Arc<dyn UnitOfWork>,
    guard: Arc<MailGuard>,
    clock: Arc<dyn Clock>,
}

impl ConfirmRecipient {
    pub fn new(uow: Arc<dyn UnitOfWork>, guard: Arc<MailGuard>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, guard, clock }
    }

    pub async fn run(&self, token: &str) -> AppResult<()> {
        let tx = self.uow.begin().await?;
        let row = tx
            .recipients()
            .confirm(&hash_token(token), self.clock.now())
            .await?
            .ok_or(AppError::Gone("recipient_token_invalid"))?;
        let target = ("recipient", row.id.to_string());
        let entry = AuditEntry::system(row.organisation_id, "recipient.confirm", target, "success");
        tx.audit()
            .record(entry.with_meta(serde_json::json!({})))
            .await?;
        tx.commit().await?;
        self.guard.confirmed(row.organisation_id, &row.email).await
    }
}
