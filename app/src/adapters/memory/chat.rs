use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    chat::{ChatMessage, ChatRepo, ChatSession},
    model::MsgRole,
    repo::{Cursor, PageOf, PageRequest, RepoError, RepoResult},
};
use uuid::Uuid;

use super::{page, MemState, MemStore};

fn key(s: &ChatSession) -> Cursor {
    (s.last_message_at.fixed_offset(), s.id)
}

impl MemState {
    /// Removes the sessions `gone` picks and their messages (the foreign key's cascade); returns
    /// `(sessions, messages)` removed.
    pub(super) fn drop_sessions(
        &mut self,
        mut gone: impl FnMut(&ChatSession) -> bool,
    ) -> (u64, u64) {
        let ids: Vec<Uuid> = self
            .chat_sessions
            .iter()
            .filter(|c| gone(c))
            .map(|c| c.id)
            .collect();
        self.chat_sessions.retain(|c| !ids.contains(&c.id));
        let n = self.chat_messages.len();
        self.chat_messages.retain(|m| !ids.contains(&m.session_id));
        (ids.len() as u64, (n - self.chat_messages.len()) as u64)
    }

    fn owns_session(&self, org: Uuid, session_id: Uuid) -> bool {
        let mut all = self.chat_sessions.iter();
        all.any(|c| c.organisation_id == org && c.id == session_id)
    }
}

#[async_trait]
impl ChatRepo for MemStore {
    async fn create_session(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        title: &str,
        at: DateTime<Utc>,
    ) -> RepoResult<ChatSession> {
        let mut s = self.state();
        let mut members = s.members.iter();
        if !members.any(|m| m.id == member_id && m.organisation_id == organisation_id) {
            return Err(RepoError::NotFound);
        }
        let c = ChatSession {
            id: Uuid::now_v7(),
            organisation_id,
            member_id,
            title: title.into(),
            created_at: at,
            last_message_at: at,
        };
        s.chat_sessions.push(c.clone());
        Ok(c)
    }

    async fn sessions(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        p: PageRequest,
    ) -> RepoResult<PageOf<ChatSession>> {
        let s = self.state();
        let mine = s
            .chat_sessions
            .iter()
            .filter(|c| c.organisation_id == organisation_id && c.member_id == member_id);
        Ok(page(mine.cloned().collect(), key, p))
    }

    async fn session(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        id: Uuid,
    ) -> RepoResult<Option<ChatSession>> {
        let s = self.state();
        let found = s.chat_sessions.iter().find(|c| {
            c.organisation_id == organisation_id && c.member_id == member_id && c.id == id
        });
        Ok(found.cloned())
    }

    async fn recent_messages(
        &self,
        organisation_id: Uuid,
        session_id: Uuid,
        n: u64,
    ) -> RepoResult<Vec<ChatMessage>> {
        let s = self.state();
        if !s.owns_session(organisation_id, session_id) {
            return Ok(vec![]);
        }
        let mut all: Vec<ChatMessage> = s
            .chat_messages
            .iter()
            .filter(|m| m.session_id == session_id)
            .cloned()
            .collect();
        all.sort_by_key(|m| (m.created_at, m.id));
        let skip = all.len().saturating_sub(n as usize);
        Ok(all.split_off(skip))
    }

    async fn append(
        &self,
        organisation_id: Uuid,
        session_id: Uuid,
        role: MsgRole,
        text: &str,
        partial: bool,
        at: DateTime<Utc>,
    ) -> RepoResult<ChatMessage> {
        let mut s = self.state();
        let c = s
            .chat_sessions
            .iter_mut()
            .find(|c| c.organisation_id == organisation_id && c.id == session_id)
            .ok_or(RepoError::NotFound)?;
        c.last_message_at = at;
        let m = ChatMessage {
            id: Uuid::now_v7(),
            session_id,
            role,
            text: text.into(),
            partial,
            created_at: at,
        };
        s.chat_messages.push(m.clone());
        Ok(m)
    }
}
