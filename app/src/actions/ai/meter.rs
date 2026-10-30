//! Metering a successful call: credits from the price table, the quota and top-up debit,
//! the `ai.call` audit row, and the 80 % / 100 % owner emails.
use opsagent_core::{
    ai::{KeyStatus, Purpose, UsageRow},
    audit::AuditEntry,
    model::{credits, Usage},
};
use sea_orm::prelude::Decimal;
use serde_json::json;
use uuid::Uuid;

use super::{
    access::{AiAccess, CallPlan, Quota},
    failures::AiCallError,
    notices::Notice,
};
use crate::{
    actions::orgs::OrgScope,
    config::{model_price, preferred_models},
    error::AppResult,
};

impl AiAccess {
    /// Records the call's credits (the part beyond the period quota comes off the top-up
    /// balance), clears a BYOK key's failure, audits `ai.call`, then sends the quota notices.
    pub(super) async fn meter(
        &self,
        scope: &OrgScope,
        plan: &CallPlan,
        purpose: Purpose,
        model: &str,
        usage: &Usage,
    ) -> Result<(), AiCallError> {
        let org = scope.organisation.id;
        let default = preferred_models(plan.provider, plan.role)[0];
        let (price, estimated) = match model_price(model) {
            Some(p) => (p, false),
            None => (model_price(default).expect("every default is priced"), true),
        };
        let credits = credits(usage, &price);
        let row = UsageRow {
            organisation_id: org,
            member_id: Some(scope.member.id),
            purpose,
            provider: plan.provider,
            model: model.to_owned(),
            key_source: plan.source,
            usage: *usage,
            credits,
            estimated,
        };
        let tx = self.uow.begin().await?;
        let quota = match plan.key_id {
            Some(key_id) => {
                tx.ai().record_usage(&row, Decimal::ZERO).await?;
                let now = self.clock.now();
                tx.ai()
                    .set_key_status(org, key_id, KeyStatus::Ok, now)
                    .await?;
                None
            }
            None => {
                let q = self.quota(&*tx, org).await?;
                let left = (q.quota - q.used).max(Decimal::ZERO);
                let debit = (credits - left).max(Decimal::ZERO);
                tx.ai().record_usage(&row, debit).await?;
                Some(q)
            }
        };
        let meta = json!({
            "purpose": purpose.as_str(), "model": model,
            "credits": format!("{:.2}", credits), "key_source": plan.source.as_str(),
        });
        let entry = AuditEntry::member(Some(org), scope.member.user_id, "ai.call", None);
        tx.audit().record(entry.with_meta(meta)).await?;
        tx.commit().await?;
        if let Some(q) = quota {
            // The call is answered and metered; a failed notice must not fail it.
            if self.quota_notices(org, &q, q.used + credits).await.is_err() {
                tracing::warn!(error_code = "ai_notice_failed", "ai quota notice failed");
            }
        }
        Ok(())
    }

    /// The 80 % and 100 % emails, once per period each; crossing both at once sends the
    /// 100 % one only.
    async fn quota_notices(&self, org: Uuid, q: &Quota, used: Decimal) -> AppResult<()> {
        if q.quota <= Decimal::ZERO {
            return Ok(());
        }
        let start = q.period.0.timestamp();
        let (k80, k100) = (format!("quota80:{start}"), format!("quota100:{start}"));
        let end = q.period.1.format("%-d %B %Y");
        let url = self.s.settings_url("");
        if used >= q.quota {
            let n = Notice {
                subject: "Your OpsAgent AI credits are used up".into(),
                text: format!(
                    "Your organisation has used all {} Dashboard AI credits for this period. \
                     They renew on {end}. Until then, buy a top-up or add your own key: {url}",
                    q.quota
                ),
            };
            self.uow.ai().notice_once(org, &k80).await?;
            return self.notices.once(org, &k100, n).await;
        }
        if used * Decimal::from(100) >= q.quota * Decimal::from(80) {
            let n = Notice {
                subject: "You have used 80% of your OpsAgent AI credits".into(),
                text: format!(
                    "Your organisation has used 80% of its {} Dashboard AI credits for this \
                     period. They renew on {end}. Top-ups and your own key: {url}",
                    q.quota
                ),
            };
            return self.notices.once(org, &k80, n).await;
        }
        Ok(())
    }
}
