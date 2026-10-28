use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::RepoResult,
    user::{Email, LiveCode, User, UsersRepo},
};
use uuid::Uuid;

use super::{MagicLinkRow, MemState, MemStore};

impl MemState {
    fn user_mut(&mut self, f: impl Fn(&User) -> bool) -> Option<&mut User> {
        self.users.iter_mut().find(|u| f(u))
    }

    fn new_user(
        &mut self,
        email: &Email,
        name: Option<String>,
        github_id: Option<i64>,
        google_id: Option<String>,
    ) -> User {
        let u = User {
            id: Uuid::new_v4(),
            email: email.clone(),
            name,
            github_id,
            google_id,
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
        Ok(s.new_user(email, None, None, None))
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
        Ok(s.new_user(email, name, Some(github_id), None))
    }

    async fn find_or_create_google(
        &self,
        google_id: &str,
        email: &Email,
        name: Option<String>,
    ) -> RepoResult<User> {
        let mut s = self.state();
        if let Some(u) = s.user_mut(|u| u.google_id.as_deref() == Some(google_id)) {
            return Ok(u.clone());
        }
        if let Some(u) = s.user_mut(|u| u.email == *email) {
            u.google_id = Some(google_id.to_owned());
            u.name = u.name.take().or(name);
            return Ok(u.clone());
        }
        Ok(s.new_user(email, name, None, Some(google_id.to_owned())))
    }

    async fn issue_magic_link(
        &self,
        user_id: Uuid,
        email: &Email,
        token_hash: &str,
        code_hash: &str,
        return_to: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> RepoResult<()> {
        self.state().magic_links.push(MagicLinkRow {
            id: Uuid::new_v4(),
            user_id,
            email: email.clone(),
            code_hash: Some(code_hash.into()),
            code_attempts: 0,
            token_hash: token_hash.into(),
            return_to: return_to.map(Into::into),
            expires_at,
            used: false,
        });
        Ok(())
    }

    async fn consume_magic_link(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<(Uuid, Option<String>)>> {
        let mut s = self.state();
        let link = s
            .magic_links
            .iter_mut()
            .find(|l| l.token_hash == token_hash && !l.used && l.expires_at > now);
        Ok(link.map(|l| {
            l.used = true;
            (l.user_id, l.return_to.clone())
        }))
    }

    async fn live_codes(&self, email: &Email, now: DateTime<Utc>) -> RepoResult<Vec<LiveCode>> {
        let s = self.state();
        Ok(s.magic_links
            .iter()
            .filter(|l| l.email == *email && !l.used && l.expires_at > now)
            .filter_map(|l| {
                Some(LiveCode {
                    id: l.id,
                    user_id: l.user_id,
                    token_hash: l.token_hash.clone(),
                    code_hash: l.code_hash.clone()?,
                    return_to: l.return_to.clone(),
                })
            })
            .collect())
    }

    async fn spend_code(&self, id: Uuid, now: DateTime<Utc>) -> RepoResult<bool> {
        let mut s = self.state();
        let link = s
            .magic_links
            .iter_mut()
            .find(|l| l.id == id && !l.used && l.expires_at > now);
        Ok(link.map(|l| l.used = true).is_some())
    }

    async fn count_wrong_code(&self, ids: &[Uuid]) -> RepoResult<()> {
        for l in self
            .state()
            .magic_links
            .iter_mut()
            .filter(|l| ids.contains(&l.id))
        {
            l.code_attempts += 1;
            if l.code_attempts >= 5 {
                l.code_hash = None;
            }
        }
        Ok(())
    }
}
