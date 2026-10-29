use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    billing::{BillingRepo, BillingStatus, OrgBilling, SubscriptionState, Tier},
    repo::{RepoError, RepoResult},
};
use sea_orm::{ConnectionTrait, QueryResult};
use uuid::Uuid;

use super::ledger_storage::stmt;
use super::{db_err, Conn, Pg};

const BILLING: &str = "SELECT stripe_customer_id, stripe_subscription_id, billing_status, \
  billing_tier, billing_quantity, trial_ends_at, current_period_start, current_period_end, \
  past_due_since FROM organisations WHERE id = $1";

/// Skips events older than the last one applied; a `past_due` event leaves `paused` (set by
/// `billing_sync`) in place, and `past_due_since` keeps the first past-due instant.
// past_due_since keys off the incoming status: a stored `paused` stays (and keeps it) only
// while Stripe still says past_due; any other incoming status clears it.
// A payment status applied after this event's creation (`payment_event_at > $9`) is newer
// than this event's status, so both status columns are kept, unless this event ends the
// subscription (canceled, trial_ended, none): an ended subscription always wins.
const APPLY: &str = "UPDATE organisations SET stripe_subscription_id = $2, \
  billing_status = CASE WHEN (coalesce(payment_event_at > $9, false) \
      AND $3 IN ('active', 'past_due', 'trialing')) \
    OR ($3 = 'past_due' AND billing_status = 'paused') THEN billing_status ELSE $3 END, \
  billing_tier = $4, billing_quantity = $5, trial_ends_at = $6, current_period_start = $7, \
  current_period_end = $8, \
  past_due_since = CASE WHEN coalesce(payment_event_at > $9, false) \
      AND $3 IN ('active', 'past_due', 'trialing') THEN past_due_since \
    WHEN $3 IN ('past_due', 'paused') THEN coalesce(past_due_since, $9) END, \
  billing_event_at = $9, updated_at = now() \
  WHERE id = $1 AND (billing_event_at IS NULL OR billing_event_at < $9 \
  OR (billing_event_at = $9 AND coalesce($8 >= current_period_end, true)))";

const PAYMENT: &str = "UPDATE organisations SET billing_status = $2, \
  past_due_since = CASE WHEN $2 = 'past_due' THEN coalesce(past_due_since, $3) END, \
  payment_event_at = $3, updated_at = now() \
  WHERE id = $1 AND stripe_subscription_id IS NOT NULL \
  AND coalesce(billing_event_at <= $3, true) AND coalesce(payment_event_at <= $3, true) \
  AND (($2 = 'past_due' AND billing_status IN ('trialing', 'active')) \
    OR ($2 = 'active' AND billing_status IN ('past_due', 'paused')))";

/// One per account (a reconnected account has a new row on the same account id). A
/// disconnected row counts only if it was ever connected (`billable_from`), and not when
/// `billing_sync` ended it for being revoked through a period's end (not billed after it).
const BILLABLE: &str =
    "SELECT count(DISTINCT provider || ':' || coalesce(external_account_id, id::text)) AS n \
  FROM connections WHERE organisation_id = $1 AND (status IN ('connected', 'degraded', 'revoked') \
  OR (status = 'disconnected' AND billable_from IS NOT NULL AND disconnected_at >= $2 \
  AND status_reason IS DISTINCT FROM 'revoked_at_period_end'))";

fn get<T: sea_orm::TryGetable>(r: &QueryResult, col: &str) -> RepoResult<T> {
    r.try_get("", col).map_err(db_err)
}

fn billing_of(r: &QueryResult) -> RepoResult<OrgBilling> {
    let stored = get::<String>(r, "billing_status")?;
    let status = BillingStatus::parse(&stored)
        .ok_or_else(|| RepoError::Storage(format!("unknown billing status {stored:?}")))?;
    let tier = get::<Option<String>>(r, "billing_tier")?;
    let subscription = match get::<Option<String>>(r, "stripe_subscription_id")? {
        Some(subscription_id) => Some(SubscriptionState {
            subscription_id,
            status,
            tier: tier.as_deref().and_then(Tier::parse),
            quantity: get::<Option<i32>>(r, "billing_quantity")?.unwrap_or(0),
            trial_ends_at: get(r, "trial_ends_at")?,
            current_period_start: get(r, "current_period_start")?,
            current_period_end: get(r, "current_period_end")?,
        }),
        None => None,
    };
    Ok(OrgBilling {
        customer_id: get(r, "stripe_customer_id")?,
        subscription,
        status,
        past_due_since: get(r, "past_due_since")?,
    })
}

impl<C: Conn> Pg<C> {
    async fn org_exists(&self, organisation_id: Uuid) -> RepoResult<bool> {
        let sql = "SELECT 1 AS one FROM organisations WHERE id = $1";
        let r = self
            .db()
            .query_one_raw(stmt(sql, vec![organisation_id.into()]));
        Ok(r.await.map_err(db_err)?.is_some())
    }
}

#[async_trait]
impl<C: Conn> BillingRepo for Pg<C> {
    async fn billing(&self, organisation_id: Uuid) -> RepoResult<OrgBilling> {
        let r = self
            .db()
            .query_one_raw(stmt(BILLING, vec![organisation_id.into()]));
        billing_of(&r.await.map_err(db_err)?.ok_or(RepoError::NotFound)?)
    }

    async fn lock_seats(&self, organisation_id: Uuid) -> RepoResult<()> {
        let sql = "SELECT pg_advisory_xact_lock(hashtext('billing_seats:' || $1::text))";
        self.db()
            .execute_raw(stmt(sql, vec![organisation_id.into()]))
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn set_customer(&self, organisation_id: Uuid, customer_id: &str) -> RepoResult<()> {
        let sql =
            "UPDATE organisations SET stripe_customer_id = $2, updated_at = now() WHERE id = $1";
        let values = vec![organisation_id.into(), customer_id.into()];
        let r = self
            .db()
            .execute_raw(stmt(sql, values))
            .await
            .map_err(db_err)?;
        match r.rows_affected() {
            0 => Err(RepoError::NotFound),
            _ => Ok(()),
        }
    }

    async fn apply_subscription(
        &self,
        organisation_id: Uuid,
        s: &SubscriptionState,
        event_created: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let values = vec![
            organisation_id.into(),
            s.subscription_id.clone().into(),
            s.status.as_str().into(),
            s.tier.map(Tier::as_str).into(),
            s.quantity.into(),
            s.trial_ends_at.into(),
            s.current_period_start.into(),
            s.current_period_end.into(),
            event_created.into(),
        ];
        let r = self
            .db()
            .execute_raw(stmt(APPLY, values))
            .await
            .map_err(db_err)?;
        if r.rows_affected() == 1 {
            return Ok(true);
        }
        match self.org_exists(organisation_id).await? {
            true => Ok(false),
            false => Err(RepoError::NotFound),
        }
    }

    async fn apply_payment(
        &self,
        organisation_id: Uuid,
        status: BillingStatus,
        at: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let values = vec![organisation_id.into(), status.as_str().into(), at.into()];
        let r = self.db().execute_raw(stmt(PAYMENT, values));
        if r.await.map_err(db_err)?.rows_affected() == 1 {
            return Ok(true);
        }
        match self.org_exists(organisation_id).await? {
            true => Ok(false),
            false => Err(RepoError::NotFound),
        }
    }

    async fn org_for_customer(&self, customer_id: &str) -> RepoResult<Option<Uuid>> {
        let sql = "SELECT id FROM organisations WHERE stripe_customer_id = $1";
        let r = self.db().query_one_raw(stmt(sql, vec![customer_id.into()]));
        r.await.map_err(db_err)?.map(|r| get(&r, "id")).transpose()
    }

    async fn record_event(&self, event_id: &str, event_type: &str) -> RepoResult<bool> {
        let sql =
            "INSERT INTO stripe_events (id, type) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING";
        let r = self
            .db()
            .execute_raw(stmt(sql, vec![event_id.into(), event_type.into()]));
        Ok(r.await.map_err(db_err)?.rows_affected() == 1)
    }

    async fn subscribed_orgs(&self) -> RepoResult<Vec<Uuid>> {
        // tenancy: the nightly billing_sync pass; each organisation scopes its own work.
        let sql = "SELECT id FROM organisations WHERE deleted_at IS NULL \
          AND billing_status IN ('trialing', 'active', 'past_due', 'paused') ORDER BY id";
        let rows = self.db().query_all_raw(stmt(sql, vec![]));
        rows.await
            .map_err(db_err)?
            .iter()
            .map(|r| get(r, "id"))
            .collect()
    }

    async fn pause(
        &self,
        organisation_id: Uuid,
        past_due_before: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let sql = "UPDATE organisations SET billing_status = 'paused', updated_at = now() \
          WHERE id = $1 AND billing_status = 'past_due' AND past_due_since <= $2";
        let values = vec![organisation_id.into(), past_due_before.into()];
        let r = self.db().execute_raw(stmt(sql, values));
        Ok(r.await.map_err(db_err)?.rows_affected() == 1)
    }

    async fn billable_count(
        &self,
        organisation_id: Uuid,
        period_start: DateTime<Utc>,
    ) -> RepoResult<i64> {
        let values = vec![organisation_id.into(), period_start.into()];
        let r = self
            .db()
            .query_one_raw(stmt(BILLABLE, values))
            .await
            .map_err(db_err)?;
        get(
            &r.ok_or_else(|| RepoError::Storage("count returned no row".into()))?,
            "n",
        )
    }
}
