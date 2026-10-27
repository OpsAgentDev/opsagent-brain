//! Users and their sign-in links.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::repo::RepoResult;

/// A trimmed, lowercased address that passed a sanity check; it cannot hold anything else.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    /// `None` if `raw` cannot be an email.
    pub fn parse(raw: &str) -> Option<Self> {
        let e = raw.trim().to_lowercase();
        let (local, domain) = e.split_once('@')?;
        let ok = e.len() <= 254
            && !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && !domain.contains('@')
            // Not valid in a bare addr-spec; keeps every mail path's parser in agreement.
            && !e.chars().any(|c| {
                c.is_whitespace() || c.is_control() || "<>\",;()[]\\:".contains(c)
            });
        ok.then_some(Self(e))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub id: Uuid,
    pub email: Email,
    pub name: Option<String>,
    pub github_id: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait UsersRepo: Send + Sync {
    async fn get(&self, id: Uuid) -> RepoResult<Option<User>>;
    async fn find_by_email(&self, email: &Email) -> RepoResult<Option<User>>;
    /// Safe under concurrent first use.
    async fn find_or_create_by_email(&self, email: &Email) -> RepoResult<User>;
    /// Match on GitHub id, else link to the user with `email`, else create. `name` fills a
    /// missing name only.
    async fn find_or_create_github(
        &self,
        github_id: i64,
        email: &Email,
        name: Option<String>,
    ) -> RepoResult<User>;
    /// Stores a link for `user_id` (sent to `email`); only the token's hash is kept.
    /// `return_to` is where sign-in lands afterwards; the caller has validated it.
    async fn issue_magic_link(
        &self,
        user_id: Uuid,
        email: &Email,
        token_hash: &str,
        return_to: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> RepoResult<()>;
    /// Marks the link used, once; its user and `return_to` if it was unused and unexpired at
    /// `now`.
    async fn consume_magic_link(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<(Uuid, Option<String>)>>;
}

#[cfg(test)]
mod tests {
    use super::Email;

    #[test]
    fn email_parse_normalises_case_and_rejects_garbage() {
        assert_eq!(
            Email::parse("  Ada@Example.COM ").unwrap().as_str(),
            "ada@example.com"
        );
        for bad in [
            "",
            "ada",
            "@example.com",
            "ada@example",
            "ada@.example.com",
            "ada@example.com.",
            "ada@b@example.com",
            "a da@example.com",
            "ada@exa\u{7}mple.com",
            "<ada@example.com>",
            "ada@example.com>",
            "\"ada\"@example.com",
            "ada,bob@example.com",
            "ada@example.com,bob@example.com",
            "ada;bob@example.com",
            "ada(c)@example.com",
            "ada@[example.com]",
            "ad\\a@example.com",
            "ada:x@example.com",
        ] {
            assert!(Email::parse(bad).is_none(), "{bad:?}");
        }
        for ok in ["a+b@x.io", "a.b-c_d@x-y.io"] {
            assert!(Email::parse(ok).is_some(), "{ok:?}");
        }
        let long = format!("{}@example.com", "a".repeat(250));
        assert!(Email::parse(&long).is_none());
    }
}
