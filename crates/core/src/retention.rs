//! Retention (retention.md): the nightly job's deletes. Global: one pass over every
//! organisation's expired rows, then the purge of organisations deleted long enough ago.
use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::repo::RepoResult;

/// A table whose rows expire on one timestamp column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TtlTable {
    ResourceHistory,
    Evidence,
    ApiCallsRaw,
    Sessions,
    MagicLinks,
    OauthConsentRequests,
    OauthAccessTokens,
    OauthRefreshTokens,
    Invites,
    EmailSuppressions,
    /// On `last_message_at`; messages go with their session.
    ChatSessions,
    AiUsage,
}

impl TtlTable {
    pub const ALL: [TtlTable; 12] = [
        Self::ResourceHistory,
        Self::Evidence,
        Self::ApiCallsRaw,
        Self::Sessions,
        Self::MagicLinks,
        Self::OauthConsentRequests,
        Self::OauthAccessTokens,
        Self::OauthRefreshTokens,
        Self::Invites,
        Self::EmailSuppressions,
        Self::ChatSessions,
        Self::AiUsage,
    ];

    /// The table's name in storage, also its key in the run's stats.
    pub fn name(self) -> &'static str {
        match self {
            Self::ResourceHistory => "resource_history",
            Self::Evidence => "evidence",
            Self::ApiCallsRaw => "api_calls_raw",
            Self::Sessions => "sessions",
            Self::MagicLinks => "magic_links",
            Self::OauthConsentRequests => "oauth_consent_requests",
            Self::OauthAccessTokens => "oauth_access_tokens",
            Self::OauthRefreshTokens => "oauth_refresh_tokens",
            Self::Invites => "invites",
            Self::EmailSuppressions => "email_suppressions",
            Self::ChatSessions => "chat_sessions",
            Self::AiUsage => "ai_usage",
        }
    }
}

/// Rows one organisation's purge deleted, per table; the purge record's only metadata.
pub type PurgeCounts = BTreeMap<&'static str, u64>;

/// An organisation soft-deleted before the purge cutoff. `busy`: it has a queued run or a
/// running one that may still be live, so its purge waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DueOrg {
    pub id: Uuid,
    pub busy: bool,
}

/// The purge record's audit action.
pub const ORG_PURGED: &str = "org.purged";

#[async_trait]
pub trait RetentionRepo: Send + Sync {
    /// Deletes at most `batch` rows of `table` whose expiry column is before `cutoff`;
    /// returns how many. The caller loops until 0.
    async fn delete_expired(
        &self,
        table: TtlTable,
        cutoff: DateTime<Utc>,
        batch: u64,
    ) -> RepoResult<u64>;

    /// Deletes at most `batch` prunable runs (oldest first) scheduled before `older_than`,
    /// with their dependents, in one transaction; returns how many runs. Prunable: terminal,
    /// a `watch_scan` or `deliver_alert` run or any skipped run, with no finding events, no
    /// evidence, no finding pointing at it and no `alert:baseline` side effect.
    async fn prune_runs(&self, older_than: DateTime<Utc>, batch: u64) -> RepoResult<u64>;

    /// Organisations soft-deleted before `deleted_before`, oldest deletion first; busy when
    /// they have a queued run or a running run started (or, unstarted, scheduled) after
    /// `busy_since`.
    async fn due_orgs(
        &self,
        deleted_before: DateTime<Utc>,
        busy_since: DateTime<Utc>,
    ) -> RepoResult<Vec<DueOrg>>;

    /// Within the caller's transaction: deletes every row of `org` (its `audit_events` too),
    /// its members' users that have no other membership left, then the organisation, and
    /// records one `org.purged` entry at `at` holding the counts. `None`, writing nothing,
    /// unless `org` is, when locked, due and not busy (as in `due_orgs`): already purged,
    /// live, deleted too recently, or busy since it was listed.
    async fn purge_org(
        &self,
        org: Uuid,
        deleted_before: DateTime<Utc>,
        busy_since: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> RepoResult<Option<PurgeCounts>>;

    /// Within the caller's transaction: deletes `org.purged` records made before `before`.
    async fn delete_old_purge_records(&self, before: DateTime<Utc>) -> RepoResult<u64>;
}
