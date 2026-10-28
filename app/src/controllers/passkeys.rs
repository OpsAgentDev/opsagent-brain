//! Adding, listing and removing the signed-in user's passkeys (mutating routes ride the CSRF
//! guard like every signed-in request), and signing in with one (anonymous, Origin-checked).
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, FixedOffset};
use opsagent_core::{oauth::rules::consent_return_to, passkey::StoredPasskey};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
};

use super::{
    auth::{check_origin, landing, start_session, Redirect, StartQuery},
    parse_id,
};
use crate::{
    api_error::{ApiError, ApiJson, Problem},
    middleware::org_scope::AuthUser,
    state::AppState,
};

/// Session key for the registration ceremony between start and finish: `(user_id, state)`, so a
/// session that changed user in between cannot finish it.
const REG_KEY: &str = "passkey_reg";
/// Session key for the sign-in ceremony: `(state, validated return_to)`; removed by finish.
const AUTH_KEY: &str = "passkey_auth";

#[derive(Serialize, ToSchema)]
pub struct PasskeyView {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<FixedOffset>,
    pub last_used_at: Option<DateTime<FixedOffset>>,
}

impl From<StoredPasskey> for PasskeyView {
    fn from(p: StoredPasskey) -> Self {
        Self {
            id: p.id,
            name: p.name,
            created_at: p.created_at.fixed_offset(),
            last_used_at: p.last_used_at.map(|t| t.fixed_offset()),
        }
    }
}

/// WebAuthn creation options (`{publicKey: …}`) for
/// `PublicKeyCredential.parseCreationOptionsFromJSON`; a discoverable credential is required.
#[utoipa::path(post, path = "/auth/passkeys/register/start", tag = "auth",
    responses((status = 200, body = Object, description = "WebAuthn creation options"),
        (status = 401, body = Problem)))]
async fn register_start(
    State(app): State<AppState>,
    session: Session,
    AuthUser(id): AuthUser,
) -> Result<Json<CreationChallengeResponse>, ApiError> {
    let (ccr, state) = app.actions.auth.passkeys.start_register(id).await?;
    session.insert(REG_KEY, (id, state)).await?;
    Ok(Json(ccr))
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterFinish {
    /// The authenticator's response (`credential.toJSON()`).
    #[schema(value_type = Object)]
    pub credential: RegisterPublicKeyCredential,
    /// Defaults to "Passkey <date>"; at most 100 characters.
    pub name: Option<String>,
}

#[utoipa::path(post, path = "/auth/passkeys/register/finish", tag = "auth",
    request_body = RegisterFinish,
    responses((status = 201, body = PasskeyView), (status = 400, body = Problem),
        (status = 401, body = Problem), (status = 422, body = Problem)))]
async fn register_finish(
    State(app): State<AppState>,
    session: Session,
    AuthUser(id): AuthUser,
    ApiJson(body): ApiJson<RegisterFinish>,
) -> Result<(StatusCode, Json<PasskeyView>), ApiError> {
    let state = session
        .remove::<(Uuid, PasskeyRegistration)>(REG_KEY)
        .await?
        .and_then(|(started_by, state)| (started_by == id).then_some(state))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "passkey_no_ceremony",
                "Start adding the passkey again.",
            )
        })?;
    let passkeys = &app.actions.auth.passkeys;
    let p = passkeys
        .finish_register(id, &body.credential, state, body.name)
        .await?;
    Ok((StatusCode::CREATED, Json(p.into())))
}

#[utoipa::path(get, path = "/auth/passkeys", tag = "auth",
    responses((status = 200, body = Vec<PasskeyView>), (status = 401, body = Problem)))]
async fn list(
    State(app): State<AppState>,
    AuthUser(id): AuthUser,
) -> Result<Json<Vec<PasskeyView>>, ApiError> {
    let rows = app.actions.auth.passkeys.list(id).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

#[derive(IntoParams)]
#[into_params(parameter_in = Path)]
pub struct PasskeyPath {
    pub id: Uuid,
}

/// Only your own passkeys; anyone else's (or an unknown id) is 404.
#[utoipa::path(delete, path = "/auth/passkeys/{id}", tag = "auth", params(PasskeyPath),
    responses((status = 204), (status = 401, body = Problem), (status = 404, body = Problem)))]
async fn remove(
    State(app): State<AppState>,
    AuthUser(user): AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let passkeys = &app.actions.auth.passkeys;
    passkeys.remove(user, parse_id(&id)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// WebAuthn request options (`{publicKey: …}`) with an empty allow list, for
/// `PublicKeyCredential.parseRequestOptionsFromJSON`.
#[utoipa::path(post, path = "/auth/passkeys/login/start", tag = "auth", params(StartQuery),
    responses((status = 200, body = Object, description = "WebAuthn request options"),
        (status = 403, body = Problem)))]
async fn login_start(
    State(app): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Query(q): Query<StartQuery>,
) -> Result<Json<RequestChallengeResponse>, ApiError> {
    check_origin(&headers, &app.config.web_base_url)?;
    let (rcr, state) = app.actions.auth.passkeys.start_login()?;
    let return_to = q.return_to.as_deref().and_then(consent_return_to);
    session.insert(AUTH_KEY, (state, return_to)).await?;
    Ok(Json(rcr))
}

#[derive(Deserialize, ToSchema)]
pub struct LoginFinish {
    /// The authenticator's assertion (`credential.toJSON()`).
    #[schema(value_type = Object)]
    pub credential: PublicKeyCredential,
}

/// Starts the session and returns where to land: the `return_to` given at start, else the
/// dashboard. Without a started ceremony, or for an unknown or bad credential, 401
/// `passkey_invalid`.
#[utoipa::path(post, path = "/auth/passkeys/login/finish", tag = "auth",
    request_body = LoginFinish,
    responses((status = 200, body = Redirect, description = "Session cookie set"),
        (status = 401, body = Problem), (status = 403, body = Problem),
        (status = 422, body = Problem)))]
async fn login_finish(
    State(app): State<AppState>,
    session: Session,
    headers: HeaderMap,
    ApiJson(body): ApiJson<LoginFinish>,
) -> Result<Json<Redirect>, ApiError> {
    let web = app.config.web_base_url.clone();
    check_origin(&headers, &web)?;
    // Removed before verifying, so a state is single-use whatever the outcome.
    let (state, return_to) = session
        .remove::<(DiscoverableAuthentication, Option<String>)>(AUTH_KEY)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "passkey_invalid",
                "Start signing in with the passkey again.",
            )
        })?;
    let passkeys = &app.actions.auth.passkeys;
    let user_id = passkeys.finish_login(&body.credential, state).await?;
    start_session(&session, user_id).await?;
    Ok(Json(Redirect {
        redirect: landing(&web, return_to.as_deref()),
    }))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(register_start))
        .routes(routes!(register_finish))
        .routes(routes!(list))
        .routes(routes!(remove))
        .routes(routes!(login_start))
        .routes(routes!(login_finish))
}
