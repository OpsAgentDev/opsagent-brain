use async_trait::async_trait;
use chrono::{DateTime, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::BTreeMap;

use crate::{
    billing::REVOKED_AT_PERIOD_END,
    finding::{PostureRow, Severity},
    repo::RepoResult,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Pending,
    Verifying,
    Connected,
    Degraded,
    Revoked,
    Blocked,
    /// Terminal: customer disconnected. A new connect flow creates a new row. Only one billing
    /// turned off for lost access resumes, through Reconnect (`Connection::reconnectable`).
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
    /// Three nightly full scans in a row ended `failed` (`SCANS_FAILING`).
    ScansFailedThrice,
    /// A nightly full scan ended `done` while the connection was `SCANS_FAILING`.
    ScanDone,
}

/// `status_reason` of a connection degraded because its nightly scans keep failing (PRD 7.3).
pub const SCANS_FAILING: &str = "scans_failing";

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
        (S::Connected, E::ScansFailedThrice) => Ok(S::Degraded),
        (S::Degraded, E::ScanDone) => Ok(S::Connected),
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
    /// Tell the owners right away about new critical findings.
    pub urgent_alerts: bool,
    /// When it moved to `disconnected` (billable until the end of that period).
    pub disconnected_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Connection {
    /// Reconnect can repair it: it lost access (`revoked`), or billing turned it off at a period
    /// end for that (`disconnected` with `REVOKED_AT_PERIOD_END`), which resumes as `revoked` would.
    pub fn reconnectable(&self) -> bool {
        match self.status {
            ConnectionStatus::Revoked => true,
            ConnectionStatus::Disconnected => {
                self.status_reason.as_deref() == Some(REVOKED_AT_PERIOD_END)
            }
            _ => false,
        }
    }
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
    pub urgent_alerts: Option<bool>,
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
    /// `cas_status` that also needs the current `status_reason` to be `from_reason`, and clears
    /// the reason; false when the row was not in that state.
    async fn cas_status_clearing(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        from: (ConnectionStatus, &str),
        to: ConnectionStatus,
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
    /// tenancy: operator tasks name a connection by id alone; the row names its organisation.
    async fn by_id_unscoped(&self, id: Uuid) -> RepoResult<Option<Connection>>;
    /// tenancy: the claimed-account notice must find the holder in whichever organisation it
    /// is. The connection of `provider` that claims `account` (connected, degraded or revoked).
    async fn claimed_by(&self, provider: &str, account: &str) -> RepoResult<Option<Connection>>;
}

/// Posture score of a connection (checks.md): `max(0, 100 - sum over checks of
/// min(CHECK_CAP, sum of weight(open)))`, with the open count per severity. The cap keeps one
/// check from sinking the score alone. Accepted, snoozed and flapping findings are not in the rows.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Posture {
    pub score: f64,
    pub counts_by_severity: BTreeMap<Severity, u64>,
}

/// Most points one check can take off the score.
pub const CHECK_CAP: f32 = 25.0;

impl Posture {
    pub fn from_rows(rows: &[PostureRow]) -> Self {
        use Severity::*;
        let mut counts: BTreeMap<Severity, u64> =
            [Critical, High, Medium, Low, Info].map(|s| (s, 0)).into();
        let mut per_check: BTreeMap<&str, f32> = BTreeMap::new();
        for r in rows {
            *per_check.entry(&r.check_id).or_default() += r.severity.weight() * r.open as f32;
            *counts.entry(r.severity).or_default() += r.open;
        }
        let sum: f32 = per_check.values().map(|w| w.min(CHECK_CAP)).sum();
        Self {
            score: f64::from((100.0 - sum).max(0.0)),
            counts_by_severity: counts,
        }
    }
}

#[cfg(test)]
mod posture_tests {
    use super::*;

    #[test]
    fn from_rows_weighs_open_findings_caps_each_check_and_floors_at_zero() {
        let row = |severity, open| PostureRow {
            check_id: "c".into(),
            severity,
            open,
        };
        let p = Posture::from_rows(&[row(Severity::High, 2), row(Severity::Low, 1)]);
        assert_eq!(p.score, 89.5);
        assert_eq!(p.counts_by_severity[&Severity::High], 2);
        assert_eq!(p.counts_by_severity[&Severity::Info], 0);
        // One check takes at most 25 points; several can still reach 0.
        assert_eq!(
            Posture::from_rows(&[row(Severity::Critical, 11)]).score,
            75.0
        );
        let other = |check: &str, severity, open| PostureRow {
            check_id: check.into(),
            severity,
            open,
        };
        let many: Vec<_> = ["01", "02", "03", "04", "05"]
            .map(|c| other(c, Severity::Critical, 3))
            .into();
        assert_eq!(Posture::from_rows(&many).score, 0.0);
        assert_eq!(
            Posture::from_rows(&[row(Severity::High, 19), other("x", Severity::Medium, 2)]).score,
            71.0
        );
        let json = serde_json::to_value(Posture::from_rows(&[])).unwrap();
        assert_eq!(json["score"], 100.0);
        assert_eq!(json["counts_by_severity"]["critical"], 0);
    }
}
