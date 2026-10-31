use std::sync::Arc;

use opsagent_core::audit::AuditEntry;
use sea_orm::prelude::Decimal;
use serde_json::json;

use super::{invalid, AiAccess, AiStatus};
use crate::{actions::orgs::OrgScope, error::AppResult};

/// Sets the organisation's monthly credit ceiling across both BYOK connections, and with
/// `patch` the switch too (owner only; the caller checks). `None` removes the ceiling; a
/// negative one is 422 `invalid`. Off stops new calls; cached explanations and chat stay.
pub struct SetCeiling {
    access: Arc<AiAccess>,
}

impl SetCeiling {
    pub fn new(access: Arc<AiAccess>) -> Self {
        Self { access }
    }

    pub async fn run(&self, scope: &OrgScope, c: Option<Decimal>) -> AppResult<AiStatus> {
        self.patch(scope, None, Some(c)).await
    }

    /// The whole `PATCH /orgs/{org}/ai` body (at least one field), in one transaction; the
    /// switch is audited `ai.enable` / `ai.disable`.
    pub async fn patch(
        &self,
        scope: &OrgScope,
        on: Option<bool>,
        ceiling: Option<Option<Decimal>>,
    ) -> AppResult<AiStatus> {
        let a = &self.access;
        if on.is_none() && ceiling.is_none() {
            return Err(invalid("Send enabled or monthly_credit_ceiling."));
        }
        if ceiling.flatten().is_some_and(|c| c < Decimal::ZERO) {
            return Err(invalid("monthly_credit_ceiling must not be negative"));
        }
        let org = scope.organisation.id;
        let tx = a.uow.begin().await?;
        if let Some(c) = ceiling {
            tx.ai().set_credit_ceiling(org, c).await?;
            let meta = json!({ "monthly_credit_ceiling": c.map(|c| format!("{c:.2}")) });
            let entry = AuditEntry::member(Some(org), scope.member.user_id, "ai.ceiling.set", None);
            tx.audit().record(entry.with_meta(meta)).await?;
        }
        if let Some(on) = on {
            tx.ai().set_enabled(org, on).await?;
            let action = if on { "ai.enable" } else { "ai.disable" };
            let entry = AuditEntry::member(Some(org), scope.member.user_id, action, None);
            tx.audit().record(entry).await?;
        }
        tx.commit().await?;
        a.status(scope).await
    }
}
