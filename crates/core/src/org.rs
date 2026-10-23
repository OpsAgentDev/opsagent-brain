//! Organisations, their members and invites.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{repo::RepoResult, user::Email};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    /// The stored and wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Member => "member",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(Self::Owner),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Organisation {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub timezone: String,
    pub kek_version: Option<i32>,
    pub wrapped_dek: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// `id` is chosen by the caller: the DEK is wrapped bound to it before the row exists.
#[derive(Debug, Clone)]
pub struct NewOrganisation {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub timezone: String,
    pub kek_version: i32,
    pub wrapped_dek: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct OrganisationPatch {
    pub name: Option<String>,
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub id: Uuid,
    pub organisation_id: Uuid,
    pub user_id: Uuid,
    pub email: Email,
    pub role: Role,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Invite {
    pub id: Uuid,
    pub organisation_id: Uuid,
    pub email: Email,
    pub role: Role,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait OrganisationsRepo: Send + Sync {
    /// `Conflict("slug")` when the slug is taken; does not abort an enclosing transaction.
    async fn insert(&self, new: NewOrganisation) -> RepoResult<Organisation>;
    async fn get(&self, organisation_id: Uuid) -> RepoResult<Option<Organisation>>;
    /// Holds the organisation row until the transaction ends (serialises owner changes). A
    /// no-op outside a transaction; `MemStore` ignores it, so race tests run on Pg only.
    async fn lock(&self, organisation_id: Uuid) -> RepoResult<()>;
    /// The live organisation `slug` and `user_id`'s membership of it.
    async fn membership(
        &self,
        slug: &str,
        user_id: Uuid,
    ) -> RepoResult<Option<(Organisation, Member)>>;
    /// Live organisations `user_id` belongs to, with the role held.
    async fn list_for_user(&self, user_id: Uuid) -> RepoResult<Vec<(Organisation, Role)>>;
    async fn update(
        &self,
        organisation_id: Uuid,
        patch: OrganisationPatch,
    ) -> RepoResult<Organisation>;
    async fn soft_delete(&self, organisation_id: Uuid, at: DateTime<Utc>) -> RepoResult<()>;
    /// True for a soft-deleted or missing organisation.
    async fn is_deleted(&self, organisation_id: Uuid) -> RepoResult<bool>;
    async fn add_member(
        &self,
        organisation_id: Uuid,
        user_id: Uuid,
        role: Role,
    ) -> RepoResult<Member>;
    async fn members(&self, organisation_id: Uuid) -> RepoResult<Vec<Member>>;
    /// Removes the member and cancels the user's pending invites to the organisation; false
    /// when `member_id` is not a member of `organisation_id`.
    async fn remove_member(&self, organisation_id: Uuid, member_id: Uuid) -> RepoResult<bool>;
    async fn owner_count(&self, organisation_id: Uuid) -> RepoResult<u64>;
    async fn insert_invite(
        &self,
        organisation_id: Uuid,
        email: &Email,
        role: Role,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> RepoResult<Invite>;
    /// Marks a pending, unexpired invite accepted, once.
    async fn take_invite(&self, token_hash: &str, now: DateTime<Utc>)
        -> RepoResult<Option<Invite>>;
}

/// URL slug from an org name: lowercase ASCII alphanumerics and single dashes, at most 48.
pub fn slugify(name: &str) -> String {
    let mut s = String::new();
    for c in name.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c);
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    let s = s.trim_matches('-');
    if s.is_empty() {
        "org".into()
    } else {
        s.chars().take(48).collect()
    }
}

/// A text-direction override or isolate (spoofs how mail text reads).
pub fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// The trimmed name, or why it is not acceptable.
pub fn valid_name(raw: &str) -> Result<String, &'static str> {
    let n = raw.trim();
    if n.is_empty() || n.chars().count() > 100 {
        return Err("name must be 1 to 100 characters");
    }
    // Names reach mail subjects and bodies: no line breaks or text-direction overrides.
    if n.chars().any(|c| c.is_ascii_control() || is_bidi(c)) {
        return Err("name must not contain control characters");
    }
    Ok(n.into())
}

#[cfg(test)]
mod tests {
    use super::{slugify, valid_name, Role};

    #[test]
    fn names_reject_control_and_bidi_characters() {
        for bad in [
            "A\nB",
            "A\rB",
            "A\u{7}B",
            "A\u{202E}B",
            "A\u{2066}B",
            "A\tB",
        ] {
            assert!(valid_name(bad).is_err(), "{bad:?}");
        }
        assert_eq!(valid_name("  Acme Ltd – Ops ").unwrap(), "Acme Ltd – Ops");
    }

    #[test]
    fn slugs_are_dashed_ascii() {
        assert_eq!(slugify("  Acme Ltd – Ops "), "acme-ltd-ops");
        assert_eq!(slugify("–"), "org");
    }

    #[test]
    fn roles_round_trip_stored_names() {
        for r in [Role::Owner, Role::Member] {
            assert_eq!(Role::parse(r.as_str()), Some(r));
        }
        assert_eq!(Role::parse("admin"), None);
    }
}
