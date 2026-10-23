use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::RepoResult,
    user::{Email, User, UsersRepo},
};
use uuid::Uuid;

use super::{MagicLinkRow, MemState, MemStore};

impl MemState {
    fn user_mut(&mut self, f: impl Fn(&User) -> bool) -> Option<&mut User> {
        self.users.iter_mut().find(|u| f(u))
    }

    fn new_user(&mut self, email: &Email, name: Option<String>, github_id: Option<i64>) -> User {
        let u = User {
            id: Uuid::new_v4(),
            email: email.clone(),
            name,
            github_id,
            created_at: Utc::now(),
        };
        self.users.push(u.clone());
        u
    }
}

#[async_trait]
impl UsersRepo for MemStore {
    async fn get(&self, id: Uuid) -> RepoResult<Option<User>> {
        Ok(self.state().user_mut(|u| u.id == id).cloned())
    }

    async fn find_by_email(&self, email: &Email) -> RepoResult<Option<User>> {
        Ok(self.state().user_mut(|u| u.email == *email).cloned())
    }

    async fn find_or_create_by_email(&self, email: &Email) -> RepoResult<User> {
        let mut s = self.state();
        if let Some(u) = s.user_mut(|u| u.email == *email) {
            return Ok(u.clone());
        }
        Ok(s.new_user(email, None, None))
    }

    async fn find_or_create_github(
        &self,
        github_id: i64,
        email: &Email,
        name: Option<String>,
    ) -> RepoResult<User> {
        let mut s = self.state();
        if let Some(u) = s.user_mut(|u| u.github_id == Some(github_id)) {
            return Ok(u.clone());
        }
        if let Some(u) = s.user_mut(|u| u.email == *email) {
            u.github_id = Some(github_id);
            u.name = u.name.take().or(name);
            return Ok(u.clone());
        }
        Ok(s.new_user(email, name, Some(github_id)))
    }

    async fn issue_magic_link(
        &self,
        user_id: Uuid,
        _email: &Email,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> RepoResult<()> {
        self.state().magic_links.push(MagicLinkRow {
            user_id,
            token_hash: token_hash.into(),
            expires_at,
            used: false,
        });
        Ok(())
    }

    async fn consume_magic_link(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<Uuid>> {
        let mut s = self.state();
        let link = s
            .magic_links
            .iter_mut()
            .find(|l| l.token_hash == token_hash && !l.used && l.expires_at > now);
        Ok(link.map(|l| {
            l.used = true;
            l.user_id
        }))
    }
}
