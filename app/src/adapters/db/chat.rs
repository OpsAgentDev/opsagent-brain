//! `ChatRepo` on Postgres. Messages hold `{"text": …}` only; they go with their session.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    chat::{ChatMessage, ChatRepo, ChatSession},
    model::MsgRole,
    repo::{PageOf, PageRequest, RepoError, RepoResult},
};
use sea_orm::{ConnectionTrait, QueryResult};
use uuid::Uuid;

use super::ledger_storage::stmt;
use super::{db_err, Conn, Pg};

const SESSION_COLS: &str = "id, organisation_id, member_id, title, created_at, last_message_at";
const MESSAGE_COLS: &str = "id, session_id, role, content->>'text' AS text, partial, created_at";

/// Only for a member of the organisation.
const CREATE: &str = "INSERT INTO chat_sessions (id, organisation_id, member_id, title, \
  created_at, last_message_at) SELECT $1, m.organisation_id, m.id, $4, $5, $5 FROM members m \
  WHERE m.organisation_id = $2 AND m.id = $3 RETURNING ";

const SESSIONS: &str = "FROM chat_sessions WHERE organisation_id = $1 AND member_id = $2 \
  AND ($3::timestamptz IS NULL OR (last_message_at, id) < ($3, $4)) \
  ORDER BY last_message_at DESC, id DESC LIMIT $5";

const APPEND: &str = "WITH s AS (UPDATE chat_sessions SET last_message_at = $7 \
  WHERE organisation_id = $1 AND id = $2 RETURNING id) \
  INSERT INTO chat_messages (id, session_id, organisation_id, role, content, partial, created_at) \
  SELECT $3, s.id, $1, $4, $5, $6, $7 FROM s RETURNING ";

const RECENT: &str = "FROM chat_messages WHERE organisation_id = $1 AND session_id = $2 \
  ORDER BY created_at DESC, id DESC LIMIT $3";

fn get<T: sea_orm::TryGetable>(r: &QueryResult, col: &str) -> RepoResult<T> {
    r.try_get("", col).map_err(db_err)
}

fn session_of(r: &QueryResult) -> RepoResult<ChatSession> {
    Ok(ChatSession {
        id: get(r, "id")?,
        organisation_id: get(r, "organisation_id")?,
        member_id: get(r, "member_id")?,
        title: get(r, "title")?,
        created_at: get(r, "created_at")?,
        last_message_at: get(r, "last_message_at")?,
    })
}

fn message_of(r: &QueryResult) -> RepoResult<ChatMessage> {
    let role: String = get(r, "role")?;
    Ok(ChatMessage {
        id: get(r, "id")?,
        session_id: get(r, "session_id")?,
        role: MsgRole::parse(&role)
            .ok_or_else(|| RepoError::Storage(format!("unknown role {role:?}")))?,
        text: get::<Option<String>>(r, "text")?.unwrap_or_default(),
        partial: get(r, "partial")?,
        created_at: get(r, "created_at")?,
    })
}

#[async_trait]
impl<C: Conn> ChatRepo for Pg<C> {
    async fn create_session(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        title: &str,
        at: DateTime<Utc>,
    ) -> RepoResult<ChatSession> {
        let values = vec![
            Uuid::now_v7().into(),
            organisation_id.into(),
            member_id.into(),
            title.into(),
            at.into(),
        ];
        let r = self
            .query_row(&format!("{CREATE}{SESSION_COLS}"), values)
            .await?;
        session_of(&r.ok_or(RepoError::NotFound)?)
    }

    async fn sessions(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        p: PageRequest,
    ) -> RepoResult<PageOf<ChatSession>> {
        let sql = format!("SELECT {SESSION_COLS} {SESSIONS}");
        let values = vec![
            organisation_id.into(),
            member_id.into(),
            p.after.map(|a| a.0).into(),
            p.after.map(|a| a.1).into(),
            (p.limit as i64 + 1).into(),
        ];
        let rows = self
            .db()
            .query_all_raw(stmt(&sql, values))
            .await
            .map_err(db_err)?;
        let mut items = rows
            .iter()
            .map(session_of)
            .collect::<RepoResult<Vec<_>>>()?;
        let more = items.len() as u64 > p.limit;
        items.truncate(p.limit as usize);
        let next = more
            .then(|| {
                items
                    .last()
                    .map(|s| (s.last_message_at.fixed_offset(), s.id))
            })
            .flatten();
        Ok(PageOf { items, next })
    }

    async fn session(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        id: Uuid,
    ) -> RepoResult<Option<ChatSession>> {
        let sql = format!(
            "SELECT {SESSION_COLS} FROM chat_sessions WHERE organisation_id = $1 \
             AND member_id = $2 AND id = $3"
        );
        let values = vec![organisation_id.into(), member_id.into(), id.into()];
        let r = self.query_row(&sql, values).await?;
        r.as_ref().map(session_of).transpose()
    }

    async fn recent_messages(
        &self,
        organisation_id: Uuid,
        session_id: Uuid,
        n: u64,
    ) -> RepoResult<Vec<ChatMessage>> {
        let sql =
            format!("SELECT * FROM (SELECT {MESSAGE_COLS} {RECENT}) m ORDER BY created_at, id");
        let values = vec![organisation_id.into(), session_id.into(), (n as i64).into()];
        let rows = self
            .db()
            .query_all_raw(stmt(&sql, values))
            .await
            .map_err(db_err)?;
        rows.iter().map(message_of).collect()
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
        let values = vec![
            organisation_id.into(),
            session_id.into(),
            Uuid::now_v7().into(),
            role.as_str().into(),
            serde_json::json!({ "text": text }).into(),
            partial.into(),
            at.into(),
        ];
        let r = self
            .query_row(&format!("{APPEND}{MESSAGE_COLS}"), values)
            .await?;
        message_of(&r.ok_or(RepoError::NotFound)?)
    }
}
