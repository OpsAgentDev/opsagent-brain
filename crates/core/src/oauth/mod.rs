//! OAuth for MCP clients: domain types, repository trait, and validation rules.
//! Tokens and codes are stored as hashes only.
pub mod rules;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::repo::RepoResult;

/// The one scope a token can carry.
pub const SCOPE: &str = "opsagent.read";

/// A dynamic client expires this long after it was last used (never while it has a live grant).
pub const DYNAMIC_CLIENT_TTL_DAYS: i64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    Dynamic,
    MetadataDocument,
}

impl ClientKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dynamic => "dynamic",
            Self::MetadataDocument => "metadata_document",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dynamic" => Some(Self::Dynamic),
            "metadata_document" => Some(Self::MetadataDocument),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClient {
    pub client_id: String,
    pub kind: ClientKind,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub document_fetched_at: Option<DateTime<Utc>>,
    /// Metadata documents only: when the cached document must be fetched again.
    pub document_cache_until: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// Dynamic clients only; slides to `touch + DYNAMIC_CLIENT_TTL_DAYS`.
    pub expires_at: Option<DateTime<Utc>>,
}

/// An authorize request awaiting consent; once decided it also carries the hashed code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRequest {
    pub id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub state: Option<String>,
    pub resource: String,
    pub scope: String,
    pub member_id: Option<Uuid>,
    pub organisation_id: Option<Uuid>,
    pub code_hash: Option<String>,
    pub code_expires_at: Option<DateTime<Utc>>,
    pub code_used_at: Option<DateTime<Utc>>,
    /// The grant issued from this request's code, so a replayed code can revoke it.
    pub grant_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

/// `(client, member, organisation)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub id: Uuid,
    pub client_id: String,
    pub member_id: Uuid,
    pub organisation_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshToken {
    pub id: Uuid,
    pub grant_id: Uuid,
    pub organisation_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub spent_at: Option<DateTime<Utc>>,
    pub successor_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    pub id: Uuid,
    pub grant_id: Uuid,
    pub organisation_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait OAuthRepo: Send + Sync {
    /// Insert, or replace everything but `last_used_at`.
    async fn upsert_client(&self, client: &OAuthClient) -> RepoResult<()>;
    async fn client(&self, client_id: &str) -> RepoResult<Option<OAuthClient>>;
    async fn touch_client(&self, client_id: &str, now: DateTime<Utc>) -> RepoResult<()>;
    /// True while any unrevoked grant names the client (a dynamic client then never expires).
    async fn client_has_live_grant(&self, client_id: &str) -> RepoResult<bool>;

    async fn insert_consent(&self, request: &ConsentRequest) -> RepoResult<()>;
    async fn consent(&self, id: Uuid) -> RepoResult<Option<ConsentRequest>>;
    /// Records the member's approval and the hashed code; `NotFound` for an unknown or
    /// already decided request.
    async fn decide_consent(
        &self,
        id: Uuid,
        member_id: Uuid,
        organisation_id: Uuid,
        code_hash: &str,
        code_expires_at: DateTime<Utc>,
    ) -> RepoResult<()>;
    /// Marks the code used and returns its request, only if it was unused and unexpired.
    async fn consume_code(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<ConsentRequest>>;
    /// The request a code belongs to, used or not, for replay detection.
    async fn consent_by_code_hash(&self, code_hash: &str) -> RepoResult<Option<ConsentRequest>>;
    async fn set_consent_grant(&self, id: Uuid, grant_id: Uuid) -> RepoResult<()>;

    async fn insert_grant(&self, grant: &Grant) -> RepoResult<()>;
    async fn grant(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Grant>>;
    /// Unrevoked grants, oldest first.
    async fn grants_for_org(&self, organisation_id: Uuid) -> RepoResult<Vec<Grant>>;
    async fn insert_refresh(&self, token: &RefreshToken) -> RepoResult<()>;
    /// Looked up by hash alone: the presented token names its organisation.
    async fn refresh_by_hash(&self, token_hash: &str) -> RepoResult<Option<RefreshToken>>;
    /// Marks the token spent and names its successor; `NotFound` if missing or already spent.
    async fn spend_refresh(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        successor_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()>;
    async fn insert_access(&self, token: &AccessToken) -> RepoResult<()>;
    /// The token and its grant (revoked or not), looked up by hash alone.
    async fn access_by_hash(&self, token_hash: &str) -> RepoResult<Option<(AccessToken, Grant)>>;

    /// The `revoke_*` calls keep an earlier `revoked_at`.
    async fn revoke_grant(
        &self,
        organisation_id: Uuid,
        grant_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()>;
    async fn revoke_member_grants(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()>;
    async fn revoke_org_grants(&self, organisation_id: Uuid, now: DateTime<Utc>) -> RepoResult<()>;
    async fn touch_grant(
        &self,
        organisation_id: Uuid,
        grant_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()>;
}
