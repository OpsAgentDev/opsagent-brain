//! Dashboard chat: a member's own sessions, and a turn streamed as Server-Sent Events.
use std::{convert::Infallible, time::Duration};

use axum::{
    extract::{Path, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    Json,
};
use chrono::{DateTime, FixedOffset};
use opsagent_core::chat::{ChatMessage, ChatSession};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc;
use tracing::Instrument;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{parse_id, OrgIdPath, OrgPath};
use crate::{
    actions::ai::ChatEvent,
    api_error::{ApiError, ApiJson, ApiQuery, Problem},
    middleware::org_scope::OrgScope,
    state::AppState,
    views::page::{page_request, Page, PageParams},
};

#[derive(Serialize, ToSchema)]
pub struct ChatSessionOut {
    pub id: Uuid,
    pub title: String,
    pub created_at: DateTime<FixedOffset>,
    pub last_message_at: DateTime<FixedOffset>,
}

fn session_view(s: ChatSession) -> ChatSessionOut {
    ChatSessionOut {
        id: s.id,
        title: s.title,
        created_at: s.created_at.fixed_offset(),
        last_message_at: s.last_message_at.fixed_offset(),
    }
}

#[derive(Serialize, ToSchema)]
pub struct ChatMessageOut {
    pub id: Uuid,
    /// `user` or `assistant`.
    pub role: String,
    pub text: String,
    /// The answer was cut off (time, step or token limit, or a provider failure).
    pub partial: bool,
    pub created_at: DateTime<FixedOffset>,
}

#[derive(Serialize, ToSchema)]
pub struct ChatSessionDetail {
    pub session: ChatSessionOut,
    /// Oldest first.
    pub messages: Vec<ChatMessageOut>,
}

#[derive(Deserialize, ToSchema)]
pub struct NewSessionIn {
    /// Without one, the first message's first 60 characters.
    pub title: Option<String>,
}

#[utoipa::path(post, path = "/orgs/{org}/chat/sessions", tag = "chat", params(OrgPath),
    request_body = NewSessionIn,
    responses((status = 200, body = ChatSessionOut), (status = 404, body = Problem)))]
async fn create(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiJson(b): ApiJson<NewSessionIn>,
) -> Result<Json<ChatSessionOut>, ApiError> {
    let sessions = &app.actions.ai.chat_sessions;
    let s = sessions.create(&scope, b.title.as_deref()).await?;
    Ok(Json(session_view(s)))
}

#[utoipa::path(get, path = "/orgs/{org}/chat/sessions", tag = "chat", params(OrgPath, PageParams),
    responses((status = 200, body = Page<ChatSessionOut>), (status = 404, body = Problem),
        (status = 422, body = Problem)))]
async fn list(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<ChatSessionOut>>, ApiError> {
    let sessions = &app.actions.ai.chat_sessions;
    let got = sessions.list(&scope, page_request(&p)?).await?;
    Ok(Json(Page::of(got).map(session_view)))
}

#[utoipa::path(get, path = "/orgs/{org}/chat/sessions/{id}", tag = "chat", params(OrgIdPath),
    responses((status = 200, body = ChatSessionDetail), (status = 404, body = Problem)))]
async fn show(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<ChatSessionDetail>, ApiError> {
    let sessions = &app.actions.ai.chat_sessions;
    let (s, messages) = sessions.get(&scope, parse_id(&id)?).await?;
    let message = |m: ChatMessage| ChatMessageOut {
        id: m.id,
        role: m.role.as_str().into(),
        text: m.text,
        partial: m.partial,
        created_at: m.created_at.fixed_offset(),
    };
    Ok(Json(ChatSessionDetail {
        session: session_view(s),
        messages: messages.into_iter().map(message).collect(),
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct MessageIn {
    /// At most 4,000 characters.
    pub text: String,
}

fn frame(e: ChatEvent) -> Event {
    let (name, data) = match e {
        ChatEvent::Delta { text } => ("delta", json!({ "text": text })),
        ChatEvent::Tool { name } => ("tool", json!({ "name": name })),
        ChatEvent::Done {
            message_id,
            partial,
            partial_reason,
        } => (
            "done",
            json!({ "message_id": message_id, "partial": partial, "partial_reason": partial_reason }),
        ),
        ChatEvent::Error { code } => ("error", json!({ "code": code })),
    };
    Event::default().event(name).data(data.to_string())
}

#[utoipa::path(post, path = "/orgs/{org}/chat/sessions/{id}/messages", tag = "chat",
    params(OrgIdPath), request_body = MessageIn,
    responses(
        (status = 200, content_type = "text/event-stream", body = String,
            description = "Events `delta` `{text}`, `tool` `{name}`, then `done` \
                `{message_id, partial, partial_reason}` (`step_limit`, `token_limit`, \
                `time_limit`, `rate_limited` or null) or `error` `{code}`"),
        (status = 402, body = Problem, description = "`ai_quota_reached`"),
        (status = 404, body = Problem), (status = 409, body = Problem, description = "`ai_disabled`"),
        (status = 422, body = Problem),
        (status = 429, body = Problem, description = "`ai_busy`: three answers already running"),
        (status = 502, body = Problem, description = "`ai_key_failing`"),
        (status = 503, body = Problem, description = "`ai_unavailable`")))]
async fn post_message(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(b): ApiJson<MessageIn>,
) -> Result<Response, ApiError> {
    let turn = app.chat.start(scope, parse_id(&id)?, b.text).await?;
    let (tx, rx) = mpsc::unbounded_channel();
    // Spawned: the answer is stored and metered even if the browser goes away.
    tokio::spawn(turn.run(tx).in_current_span());
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        let e = rx.recv().await?;
        Some((Ok::<_, Infallible>(frame(e)), rx))
    });
    let keep_alive = KeepAlive::new().interval(Duration::from_secs(15));
    let sse = Sse::new(stream).keep_alive(keep_alive);
    Ok(([("x-accel-buffering", "no")], sse).into_response())
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(create, list))
        .routes(routes!(show))
        .routes(routes!(post_message))
}
