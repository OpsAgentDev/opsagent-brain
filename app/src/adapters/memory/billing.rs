use std::collections::HashSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    billing::{BillingRepo, BillingStatus as B, OrgBilling, SubscriptionState},
    connection::ConnectionStatus as S,
    repo::RepoResult,
};
use uuid::Uuid;

use super::{MemState, MemStore};

/// One organisation's billing row, with the creation time of the last event applied.
#[derive(Clone, Default)]
pub(super) struct BillingRow {
    billing: OrgBilling,
    event_at: Option<DateTime<Utc>>,
}

impl MemState {
    /// The billing row of a live or deleted organisation; `NotFound` when there is none.
    fn billing_mut(&mut self, organisation_id: Uuid) -> RepoResult<&mut BillingRow> {
        self.org_mut(organisation_id)?;
        Ok(self.billing.entry(organisation_id).or_default())
    }
}

#[async_trait]
impl BillingRepo for MemStore {
    async fn billing(&self, organisation_id: Uuid) -> RepoResult<OrgBilling> {
        Ok(self.state().billing_mut(organisation_id)?.billing.clone())
    }

    async fn set_customer(&self, organisation_id: Uuid, customer_id: &str) -> RepoResult<()> {
        let mut s = self.state();
        s.billing_mut(organisation_id)?.billing.customer_id = Some(customer_id.into());
        Ok(())
    }

    async fn apply_subscription(
        &self,
        organisation_id: Uuid,
        sub: &SubscriptionState,
        event_created: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let mut s = self.state();
        let row = s.billing_mut(organisation_id)?;
        if row.event_at.is_some_and(|at| at > event_created) {
            return Ok(false);
        }
        let b = &mut row.billing;
        let mut sub = sub.clone();
        if sub.status == B::PastDue && b.status == B::Paused {
            sub.status = B::Paused;
        }
        b.past_due_since = match sub.status {
            B::PastDue | B::Paused => b.past_due_since.or(Some(event_created)),
            _ => None,
        };
        b.status = sub.status;
        b.subscription = Some(sub);
        row.event_at = Some(event_created);
        Ok(true)
    }

    async fn record_event(&self, event_id: &str, _event_type: &str) -> RepoResult<bool> {
        Ok(self.state().stripe_events.insert(event_id.into()))
    }

    async fn billable_count(
        &self,
        organisation_id: Uuid,
        period_start: DateTime<Utc>,
    ) -> RepoResult<i64> {
        let s = self.state();
        let accounts: HashSet<_> = s
            .connections
            .iter()
            .map(|(c, _)| c)
            .filter(|c| c.organisation_id == organisation_id)
            .filter(|c| match c.status {
                S::Connected | S::Degraded | S::Revoked => true,
                S::Disconnected => {
                    c.billable_from.is_some()
                        && c.disconnected_at.is_some_and(|at| at >= period_start)
                }
                _ => false,
            })
            .map(|c| {
                (
                    c.provider.clone(),
                    c.external_account_id.clone().unwrap_or(c.id.to_string()),
                )
            })
            .collect();
        Ok(accounts.len() as i64)
    }
}
