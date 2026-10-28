//! Retention (retention.md): the nightly job's deletes. Global: one pass over every
//! organisation's expired rows.
use async_trait::async_trait;
use chrono::{DateTime, Utc};

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
}

impl TtlTable {
    pub const ALL: [TtlTable; 10] = [
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
        }
    }
}

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
}
