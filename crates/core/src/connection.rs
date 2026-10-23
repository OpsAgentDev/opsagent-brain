use async_trait::async_trait;
use chrono::{DateTime, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::repo::RepoResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Pending,
    Verifying,
    Connected,
    Degraded,
    Revoked,
    Blocked,
    /// Terminal: customer disconnected. A new connect flow creates a new row.
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    StackReported,
    VerifyOk,
    VerifySubset,
    VerifySuperset,
    ExternalIdNotEnforced,
    AccessDeniedThrice,
    RoleReturned,
    Disconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid connection transition: {from:?} on {event:?}")]
pub struct InvalidTransition {
    pub from: ConnectionStatus,
    pub event: ConnectionEvent,
}

/// PRD 7.2. Anything not listed is an error; throttling/5xx never reach here.
pub fn transition(
    from: ConnectionStatus,
    event: ConnectionEvent,
) -> Result<ConnectionStatus, InvalidTransition> {
    use ConnectionEvent as E;
    use ConnectionStatus as S;
    let verifiable = matches!(from, S::Verifying | S::Connected | S::Degraded | S::Blocked);
    let live = matches!(from, S::Connected | S::Degraded);
    let open = from != S::Disconnected;
    match (from, event) {
        (S::Pending, E::StackReported) => Ok(S::Verifying),
        (_, E::VerifyOk) if verifiable => Ok(S::Connected),
        (_, E::VerifySubset) if verifiable => Ok(S::Degraded),
        (_, E::VerifySuperset | E::ExternalIdNotEnforced) if verifiable => Ok(S::Blocked),
        (_, E::AccessDeniedThrice) if live => Ok(S::Revoked),
        (_, E::Disconnect) if open => Ok(S::Disconnected),
        // Full re-verification (policy diff, ExternalId guard) before scanning resumes.
        (S::Revoked, E::RoleReturned) => Ok(S::Verifying),
        _ => Err(InvalidTransition { from, event }),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    pub id: Uuid,
    pub organisation_id: Uuid,
    pub provider: String,
    pub display_name: Option<String>,
    pub status: ConnectionStatus,
    pub status_reason: Option<String>,
    pub external_account_id: Option<String>,
    pub template_version: Option<String>,
    pub scan_time_local: Option<NaiveTime>,
    pub briefing_time_local: Option<NaiveTime>,
    pub api_rate_ceiling: Option<i32>,
    pub slack_channel_id: Option<String>,
    pub first_connected_at: Option<DateTime<Utc>>,
    pub billable_from: Option<DateTime<Utc>>,
    /// Consecutive verify calls refused access, and when the first of them was.
    pub verify_denied_streak: i32,
    pub verify_denied_first_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A `pending` connection; its sealed credentials are stored with it.
#[derive(Debug, Clone)]
pub struct NewConnection {
    pub organisation_id: Uuid,
    pub provider: String,
    pub display_name: String,
    pub template_version: Option<String>,
    /// The provider's credential kind, stored beside the sealed credentials.
    pub credential_kind: String,
}

/// `None` leaves a field as it is.
#[derive(Debug, Clone, Default)]
pub struct ConnectionPatch {
    pub display_name: Option<String>,
    pub scan_time_local: Option<NaiveTime>,
    pub briefing_time_local: Option<NaiveTime>,
    pub api_rate_ceiling: Option<i32>,
    /// `Some(None)` clears the channel.
    pub slack_channel_id: Option<Option<String>>,
}

/// One recorded verify outcome; the grants are the stored grant labels.
#[derive(Debug, Clone, PartialEq)]
pub struct Verification {
    pub outcome: String,
    pub at: DateTime<Utc>,
    pub assume_with_ok: Option<bool>,
    pub assume_without_denied: Option<bool>,
    pub policy_matches: Option<bool>,
    pub extra_grants: serde_json::Value,
    pub missing_grants: serde_json::Value,
}

/// What a successful verify call established about the connection (status aside).
#[derive(Debug, Clone, Default)]
pub struct Verified {
    /// The provider account behind the role, for a connected or degraded outcome.
    pub account: Option<String>,
    /// The new `status_reason`; `None` clears it.
    pub reason: Option<String>,
    /// Set on the first connect: stamps `first_connected_at` and `billable_from`.
    pub first_connected_at: Option<DateTime<Utc>>,
}

/// Credentials sealed under the org DEK; `kek_version` is the KEK version that wrapped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedCreds {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub kek_version: i32,
}

#[async_trait]
pub trait ConnectionsRepo: Send + Sync {
    async fn insert(&self, new: NewConnection, creds: SealedCreds) -> RepoResult<Connection>;
    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Connection>>;
    /// Holds the connection row until the transaction ends (serialises scan requests). Not a
    /// lock outside a transaction; `MemStore` ignores it.
    async fn lock(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Connection>>;
    /// Every connection of the organisation, oldest first.
    async fn list(&self, organisation_id: Uuid) -> RepoResult<Vec<Connection>>;
    /// The latest recorded verification; `None` without one or outside the organisation.
    async fn last_verification(
        &self,
        organisation_id: Uuid,
        id: Uuid,
    ) -> RepoResult<Option<Verification>>;
    /// `NotFound` when the connection is not in the organisation.
    async fn update(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        patch: ConnectionPatch,
    ) -> RepoResult<Connection>;
    /// Compare-and-set on status, also writing `reason` when given; false when the row was
    /// not in `from`. `Conflict("account")` as for `record_verified` when `to` claims an
    /// account another connection holds.
    async fn cas_status(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        from: ConnectionStatus,
        to: ConnectionStatus,
        reason: Option<&str>,
    ) -> RepoResult<bool>;
    /// Records `v` (its `at` is the record time) for verify run `run_id`; `NotFound` when the
    /// connection is not in the organisation.
    async fn record_verification(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        run_id: Uuid,
        v: &Verification,
    ) -> RepoResult<()>;
    /// Writes `v` and clears the denial streak. `Conflict("account")` when the account is
    /// claimed by another connection of the provider (connected, degraded or revoked); on
    /// Postgres the transaction is then aborted, so call it under `Tx::savepoint`.
    async fn record_verified(&self, organisation_id: Uuid, id: Uuid, v: Verified)
        -> RepoResult<()>;
    async fn record_denial(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        streak: i32,
        first_at: DateTime<Utc>,
    ) -> RepoResult<()>;
    /// `NotFound` when the connection is not in the organisation or has no credentials.
    async fn load_creds(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<SealedCreds>;
    /// Replaces the stored credentials; `NotFound` as for `load_creds`.
    async fn save_creds(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        creds: SealedCreds,
    ) -> RepoResult<()>;
}
