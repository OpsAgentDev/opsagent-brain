use std::collections::BTreeSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    billing::{
        BillingRepo, BillingStatus as B, OrgBilling, SubscriptionState, REVOKED_AT_PERIOD_END,
    },
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
    payment_at: Option<DateTime<Utc>>,
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
        let ends = (sub.current_period_end, row.billing.subscription.as_ref());
        let earlier_end = matches!(ends, (Some(new), Some(old)) if old.current_period_end.is_some_and(|o| new < o));
        match row.event_at {
            Some(at) if at > event_created || (at == event_created && earlier_end) => {
                return Ok(false)
            }
            _ => {}
        }
        // An ending status always wins over a newer payment status.
        let live = matches!(sub.status, B::Active | B::PastDue | B::Trialing);
        let payment_newer = live && row.payment_at.is_some_and(|at| at > event_created);
        let b = &mut row.billing;
        let mut sub = sub.clone();
        if payment_newer || (sub.status == B::PastDue && b.status == B::Paused) {
            sub.status = b.status;
        }
        if !payment_newer {
            b.past_due_since = match sub.status {
                B::PastDue | B::Paused => b.past_due_since.or(Some(event_created)),
                _ => None,
            };
        }
        let old_start = b.subscription.as_ref().and_then(|o| o.current_period_start);
        if b.paid_quantity.is_none() || old_start != sub.current_period_start {
            b.paid_quantity = Some(sub.quantity);
        }
        b.status = sub.status;
        b.subscription = Some(sub);
        row.event_at = Some(event_created);
        Ok(true)
    }

    async fn apply_payment(
        &self,
        organisation_id: Uuid,
        status: B,
        at: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let mut s = self.state();
        let row = s.billing_mut(organisation_id)?;
        let newer = |t: Option<DateTime<Utc>>| t.is_some_and(|t| t > at);
        let b = &mut row.billing;
        let moves = matches!(
            (status, b.status),
            (B::PastDue, B::Trialing | B::Active) | (B::Active, B::PastDue | B::Paused)
        );
        if b.subscription.is_none() || newer(row.event_at) || newer(row.payment_at) || !moves {
            return Ok(false);
        }
        b.status = status;
        if let Some(sub) = b.subscription.as_mut() {
            sub.status = status;
        }
        b.past_due_since = match status {
            B::PastDue => b.past_due_since.or(Some(at)),
            _ => None,
        };
        row.payment_at = Some(at);
        Ok(true)
    }

    async fn org_for_customer(&self, customer_id: &str) -> RepoResult<Option<Uuid>> {
        let s = self.state();
        let mut hits = s.billing.iter();
        let found = hits.find(|(_, r)| r.billing.customer_id.as_deref() == Some(customer_id));
        Ok(found.map(|(id, _)| *id))
    }

    async fn record_event(&self, event_id: &str, _event_type: &str) -> RepoResult<bool> {
        Ok(self.state().stripe_events.insert(event_id.into()))
    }

    async fn subscribed_orgs(&self) -> RepoResult<Vec<Uuid>> {
        let s = self.state();
        let live = |id: &Uuid| s.orgs.iter().any(|o| o.id == *id && o.deleted_at.is_none());
        let mut ids: Vec<Uuid> = s
            .billing
            .iter()
            .filter(|(id, r)| r.billing.status.is_subscribed() && live(id))
            .map(|(id, _)| *id)
            .collect();
        ids.sort();
        Ok(ids)
    }

    async fn lock_seats(&self, _organisation_id: Uuid) -> RepoResult<()> {
        Ok(()) // a transaction already holds a private snapshot
    }

    async fn pause(
        &self,
        organisation_id: Uuid,
        past_due_before: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let mut s = self.state();
        let b = &mut s.billing_mut(organisation_id)?.billing;
        let due = b.past_due_since.is_some_and(|t| t <= past_due_before);
        if b.status != B::PastDue || !due {
            return Ok(false);
        }
        b.status = B::Paused;
        if let Some(sub) = b.subscription.as_mut() {
            sub.status = B::Paused;
        }
        Ok(true)
    }

    async fn billable_accounts(
        &self,
        organisation_id: Uuid,
        since: Option<DateTime<Utc>>,
    ) -> RepoResult<Vec<String>> {
        let s = self.state();
        let accounts: BTreeSet<_> = s
            .connections
            .iter()
            .map(|(c, _)| c)
            .filter(|c| c.organisation_id == organisation_id)
            .filter(|c| match c.status {
                S::Connected | S::Degraded | S::Revoked => true,
                S::Disconnected => {
                    c.billable_from.is_some()
                        && since.is_some_and(|p| c.disconnected_at.is_some_and(|at| at >= p))
                        && c.status_reason.as_deref() != Some(REVOKED_AT_PERIOD_END)
                }
                _ => false,
            })
            .map(|c| {
                let account = c.external_account_id.clone();
                format!("{}:{}", c.provider, account.unwrap_or(c.id.to_string()))
            })
            .collect();
        Ok(accounts.into_iter().collect())
    }

    async fn record_quantity(
        &self,
        organisation_id: Uuid,
        quantity: i32,
        paid: i32,
    ) -> RepoResult<()> {
        let mut s = self.state();
        let b = &mut s.billing_mut(organisation_id)?.billing;
        if let Some(sub) = b.subscription.as_mut() {
            sub.quantity = quantity;
        }
        b.paid_quantity = Some(paid);
        Ok(())
    }
}
