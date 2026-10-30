//! Dashboard chat history (dashboard-ai.md, Chat): text only, one member's sessions.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    model::MsgRole,
    repo::{PageOf, PageRequest, RepoResult},
};

/// An untitled session takes this many characters of its first message.
pub const TITLE_CHARS: usize = 60;

#[derive(Debug, Clone, PartialEq)]
pub struct ChatSession {
    pub id: Uuid,
    pub organisation_id: Uuid,
    /// The membership (`members.id`), not the user.
    pub member_id: Uuid,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub last_message_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChatMessage {
    pub id: Uuid,
    pub session_id: Uuid,
    pub role: MsgRole,
    pub text: String,
    /// The reply was cut off (time limit, step limit, provider failure).
    pub partial: bool,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait ChatRepo: Send + Sync {
    async fn create_session(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        title: &str,
        at: DateTime<Utc>,
    ) -> RepoResult<ChatSession>;
    /// The member's sessions, latest message first (cursor on `last_message_at`).
    async fn sessions(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        page: PageRequest,
    ) -> RepoResult<PageOf<ChatSession>>;
    /// `None` unless the session is the member's.
    async fn session(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        id: Uuid,
    ) -> RepoResult<Option<ChatSession>>;
    /// The last `n` messages, oldest first.
    async fn recent_messages(
        &self,
        organisation_id: Uuid,
        session_id: Uuid,
        n: u64,
    ) -> RepoResult<Vec<ChatMessage>>;
    /// Adds a message and moves the session's `last_message_at` to `at`; a user message gives
    /// an untitled session (title `""`) its first `TITLE_CHARS` characters as the title.
    /// `NotFound` for a session not in the organisation.
    async fn append(
        &self,
        organisation_id: Uuid,
        session_id: Uuid,
        role: MsgRole,
        text: &str,
        partial: bool,
        at: DateTime<Utc>,
    ) -> RepoResult<ChatMessage>;
}
