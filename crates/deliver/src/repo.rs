//! Storage ports for delivery: recipients and suppressions, integrations, the deliveries
//! ledger, and schedules. Implemented in the app (SeaORM and an in-memory fake).
use async_trait::async_trait;
use chrono::{DateTime, NaiveTime, Utc};
use opsagent_core::{
    repo::{PageOf, PageRequest, RepoResult},
    run::RunKey,
};
use uuid::Uuid;

use crate::{
    model::{ConnectionSnapshot, FindingSnapshot},
    route::Recipient,
};

/// `recipients.status` before the confirm link is used.
pub const PENDING: &str = "pending";
pub const ACTIVE: &str = "active";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRow {
    pub id: Uuid,
    pub organisation_id: Uuid,
    /// `None`: organisation-wide.
    pub connection_id: Option<Uuid>,
    pub email: String,
    /// Set for a member recipient (active at once, no unsubscribe footer).
    pub member_id: Option<Uuid>,
    /// `pending` or `active`.
    pub status: String,
    pub unsubscribed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A recipient to add: `pending` with a confirm token, `active` without one.
pub struct NewRecipient {
    pub connection_id: Option<Uuid>,
    pub email: String,
    pub member_id: Option<Uuid>,
    /// The confirm token's hash and expiry.
    pub confirm: Option<(String, DateTime<Utc>)>,
}

/// Why an address gets no mail (`email_suppressions.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suppression {
    /// Global and permanent; replaces a `ConfirmBlocked` row.
    Unsubscribed,
    /// Per organisation, `SUPPRESSION_DAYS`.
    Ignored,
    /// Global, `SUPPRESSION_DAYS`; stops confirm mails only.
    ConfirmBlocked,
}

/// Days an `Ignored` or `ConfirmBlocked` row lasts; `suppress` renews it.
pub const SUPPRESSION_DAYS: i64 = 90;

impl Suppression {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsubscribed => "unsubscribed",
            Self::Ignored => "ignored",
            Self::ConfirmBlocked => "confirm_blocked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Unsubscribed, Self::Ignored, Self::ConfirmBlocked]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

#[async_trait]
pub trait RecipientsRepo: Send + Sync {
    async fn list(
        &self,
        organisation_id: Uuid,
        page: PageRequest,
    ) -> RepoResult<PageOf<RecipientRow>>;
    /// `Conflict("recipient")` for the same email and connection.
    async fn insert(&self, organisation_id: Uuid, new: NewRecipient) -> RepoResult<RecipientRow>;
    async fn delete(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<bool>;
    /// Activates the pending, unexpired recipient holding `token_hash` (single use).
    /// tenancy: the token names its row and organisation.
    async fn confirm(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<RecipientRow>>;
    /// tenancy: a verified unsubscribe token names the row.
    async fn by_id_unscoped(&self, id: Uuid) -> RepoResult<Option<RecipientRow>>;
    /// Sets `unsubscribed_at`; false when already unsubscribed or gone.
    async fn unsubscribe(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        at: DateTime<Utc>,
    ) -> RepoResult<bool>;
    /// Active, subscribed recipients of a connection, or organisation-wide (`None`), oldest first.
    async fn for_connection(
        &self,
        organisation_id: Uuid,
        connection_id: Option<Uuid>,
    ) -> RepoResult<Vec<Recipient>>;
    /// The organisation's owners as member recipients (`id` is the user id), oldest first.
    async fn owners(&self, organisation_id: Uuid) -> RepoResult<Vec<Recipient>>;
    /// Records or renews a row (`organisation_id` `None`: global). An expiring kind never
    /// replaces another kind; `Unsubscribed` replaces anything.
    async fn suppress(
        &self,
        organisation_id: Option<Uuid>,
        email_hash: &str,
        kind: Suppression,
    ) -> RepoResult<()>;
    /// Live rows for the address: global ones and `organisation_id`'s.
    async fn suppressed(
        &self,
        organisation_id: Uuid,
        email_hash: &str,
    ) -> RepoResult<Vec<Suppression>>;
    /// Lowercased address to the id of its oldest recipient row in the organisation, for each
    /// of `emails` (lowercased) that has one.
    async fn ids_by_email(
        &self,
        organisation_id: Uuid,
        emails: &[String],
    ) -> RepoResult<std::collections::HashMap<String, Uuid>>;
}

pub const SLACK: &str = "slack";
pub const REVOKED: &str = "revoked";

#[derive(Debug, Clone, PartialEq)]
pub struct Integration {
    pub id: Uuid,
    pub organisation_id: Uuid,
    pub kind: String,
    /// `active` or `revoked`.
    pub status: String,
    /// Slack: `team_id`, `team_name`, `bot_user_id`, `scope`.
    pub config: serde_json::Value,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    /// For a revoked integration, when it was revoked.
    pub updated_at: DateTime<Utc>,
}

/// A token sealed under the org DEK, with the KEK version that wrapped the DEK.
pub struct SealedToken {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub kek_version: i32,
}

#[async_trait]
pub trait IntegrationsRepo: Send + Sync {
    /// The organisation's Slack integration, active (a reinstall replaces it).
    /// `Conflict("slack_workspace")` when another organisation holds `config.team_id`.
    async fn upsert_slack(
        &self,
        organisation_id: Uuid,
        config: serde_json::Value,
        token: SealedToken,
    ) -> RepoResult<()>;
    /// Oldest first.
    async fn list(&self, organisation_id: Uuid) -> RepoResult<Vec<Integration>>;
    async fn active_slack(&self, organisation_id: Uuid) -> RepoResult<Option<Integration>>;
    /// The revocation time is the store's clock (Pg: SQL `now()`), as `deliveries.sent_at`.
    async fn mark_revoked(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        at: DateTime<Utc>,
    ) -> RepoResult<()>;
    async fn delete(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<bool>;
}

/// `deliveries.kind` and `deliveries.status` values.
pub const BRIEFING: &str = "briefing";
pub const WEEKLY: &str = "weekly";
pub const SENT: &str = "sent";
pub const FAILED: &str = "failed";
pub const FALLBACK_EMAIL: &str = "fallback_email";
pub const SUPPRESSED: &str = "suppressed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRow {
    pub id: Uuid,
    pub organisation_id: Uuid,
    pub connection_id: Option<Uuid>,
    pub kind: String,
    /// `slack` or `email`.
    pub channel: String,
    /// The channel id or the address.
    pub target: String,
    pub status: String,
    pub attempts: i32,
    pub sent_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// One effect `key` of run `run_id`.
pub struct NewDelivery<'a> {
    pub connection_id: Option<Uuid>,
    pub run_id: Uuid,
    pub key: &'a str,
    pub kind: &'a str,
    pub channel: &'a str,
    pub target: &'a str,
    pub status: &'a str,
    /// Slack message `ts`.
    pub external_ref: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DeliveryFilter {
    pub connection_id: Option<Uuid>,
    pub kind: Option<String>,
}

#[async_trait]
pub trait DeliveriesRepo: Send + Sync {
    async fn list(
        &self,
        organisation_id: Uuid,
        filter: DeliveryFilter,
        page: PageRequest,
    ) -> RepoResult<PageOf<DeliveryRow>>;
    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<DeliveryRow>>;
    /// Writes, or rewrites, the row of (`run_id`, `key`): a resumed run adds no rows. `sent_at`
    /// is set once, by the first `sent` or `fallback_email`.
    async fn record(&self, organisation_id: Uuid, row: NewDelivery<'_>) -> RepoResult<()>;
    /// The last `kind` row sent (to Slack or as the email fallback) strictly before `before`.
    async fn last_success_at(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        kind: &str,
        before: DateTime<Utc>,
    ) -> RepoResult<Option<DateTime<Utc>>>;
    /// Slack is revoked and no briefing of the connection fell back to email between the
    /// revocation and `before`.
    async fn revoke_notice_due(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        before: DateTime<Utc>,
    ) -> RepoResult<bool>;
    /// `NotFound` for a connection outside the organisation.
    async fn connection_snapshot(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<ConnectionSnapshot>;
    /// Live findings, plus any with an event since `since` (events oldest first).
    async fn finding_snapshots(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        since: DateTime<Utc>,
    ) -> RepoResult<Vec<FindingSnapshot>>;
}

/// A parked run whose retry (or interrupted enqueue) is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueRun {
    pub run_id: Uuid,
    pub job_type: String,
    /// Its `next_attempt_at`, the marker a hand-off clears.
    pub marker: DateTime<Utc>,
    pub organisation_deleted: bool,
}

/// The first instant to schedule from, given the schedule's zone.
pub type SinceFn<'a> = &'a (dyn Fn(&str) -> Option<DateTime<Utc>> + Send + Sync);

#[async_trait]
pub trait SchedulesRepo: Send + Sync {
    /// The connection's default schedules (scan and briefing at the given local times, else
    /// the defaults) and the organisation's weekly summary, in the organisation's zone.
    /// Idempotent per (connection, job) and (organisation, job).
    async fn create_defaults(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        times: (Option<NaiveTime>, Option<NaiveTime>),
        now: DateTime<Utc>,
    ) -> RepoResult<()>;
    /// Points the connection's `job_type` schedule at `cron_local`, next due after
    /// `from(zone)`. No-op when it is missing or already on `cron_local`.
    async fn set_cron(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        job_type: &str,
        cron_local: &str,
        from: SinceFn<'_>,
    ) -> RepoResult<()>;
    async fn disable_for_org(&self, organisation_id: Uuid) -> RepoResult<u64>;
    /// `create_defaults` for every connected connection of a live organisation that lacks
    /// the newest default (`watch_scan`); returns how many.
    /// tenancy: scheduler pass; each row's organisation scopes its writes.
    async fn backfill_defaults(&self, now: DateTime<Utc>) -> RepoResult<u64>;
    /// Enabled schedules due at `now`, of live organisations, most overdue first.
    /// tenancy: scheduler pass.
    async fn due_ids(&self, now: DateTime<Utc>) -> RepoResult<Vec<Uuid>>;
    /// Row-locks the schedule until the transaction ends if it is still due and no other
    /// transaction holds it (`FOR UPDATE SKIP LOCKED`): its run key, cron and zone.
    /// tenancy: scheduler pass, by id from `due_ids`.
    async fn lock_due(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<(RunKey, String, String)>>;
    /// Moves `next_due_at` to `next`; `None` disables the schedule.
    /// tenancy: scheduler pass, the row locked by `lock_due`.
    async fn advance(&self, id: Uuid, next: Option<DateTime<Utc>>) -> RepoResult<()>;
    /// Queued runs whose `next_attempt_at` is due at `now`, earliest first.
    /// tenancy: scheduler pass; each run names its organisation.
    async fn due_runs(&self, now: DateTime<Utc>) -> RepoResult<Vec<DueRun>>;
    /// Takes the scheduler's transaction-level lock if no other scheduler holds it; the end of
    /// the transaction releases it. Call on a transaction.
    async fn try_lock_scheduler(&self) -> RepoResult<bool>;
}
