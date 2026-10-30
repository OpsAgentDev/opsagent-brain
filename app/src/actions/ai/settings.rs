use std::sync::Arc;

use opsagent_core::audit::AuditEntry;

use super::{AiAccess, AiStatus};
use crate::{actions::orgs::OrgScope, error::AppResult};

/// Turns Dashboard AI on or off (owner only; the caller checks), audited `ai.enable` /
/// `ai.disable`. Off stops new calls; cached explanations and chat history stay.
pub struct SetEnabled {
    access: Arc<AiAccess>,
}

impl SetEnabled {
    pub fn new(access: Arc<AiAccess>) -> Self {
        Self { access }
    }

    pub async fn run(&self, scope: &OrgScope, on: bool) -> AppResult<AiStatus> {
        let org = scope.organisation.id;
        let tx = self.access.uow.begin().await?;
        tx.ai().set_enabled(org, on).await?;
        let action = if on { "ai.enable" } else { "ai.disable" };
        let entry = AuditEntry::member(Some(org), scope.member.user_id, action, None);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        self.access.status(scope).await
    }
}
