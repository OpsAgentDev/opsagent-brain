use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use loco_rs::{
    app::AppContext,
    controller::Routes,
    prelude::{get, post},
};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use sea_orm::EntityTrait;
use serde::Deserialize;
use serde_json::{json, Value};
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    api_error::{ApiError, ApiJson},
    mailers::magic_link as mail,
    middleware::{csrf, mailer, org_scope::AuthUser, session::USER_KEY},
    models::{_entities::users, audit, magic_links, users as user_model},
    settings::Settings,
};

const GH_KEY: &str = "github_oauth";
const UA: &str = "opsagent-brain";

#[derive(Deserialize)]
struct MagicLinkRequest {
    email: String,
}

/// Always 202, so the response never reveals whether an address is valid or known.
async fn request_link(
    State(ctx): State<AppContext>,
    ApiJson(body): ApiJson<MagicLinkRequest>,
) -> Result<StatusCode, ApiError> {
    if let Some(email) = user_model::normalize_email(&body.email) {
        let user = user_model::find_or_create_by_email(&ctx.db, &email).await?;
        let token = magic_links::issue(&ctx.db, user.id, &email).await?;
        let link = format!(
            "{}/v1/auth/magic-link/{token}",
            Settings::get(&ctx).api_base_url
        );
        if let Err(e) = mailer(&ctx).send(mail::magic_link(&email, &link)).await {
            tracing::error!(error = %e, "magic link mail failed");
        }
    }
    Ok(StatusCode::ACCEPTED)
}

/// Rotates the session id and binds the session to `user_id`.
async fn start_session(ctx: &AppContext, session: &Session, user_id: Uuid) -> Result<(), ApiError> {
    session.cycle_id().await?;
    session.insert(USER_KEY, user_id).await?;
    audit::record(
        &ctx.db,
        None,
        user_id,
        "auth.sign_in",
        Some(("user", user_id.to_string())),
    )
    .await?;
    Ok(())
}

#[derive(Deserialize)]
struct RedeemRequest {
    token: String,
}

/// Anonymous, so CSRF-token-exempt; protected by an origin check instead. Accepted when the
/// `Origin` header equals the origin of `WEB_BASE_URL`, or `Sec-Fetch-Site` is
/// `same-origin`/`same-site` (browsers set it and scripts cannot forge it).
fn check_origin(headers: &HeaderMap, web_base_url: &str) -> Result<(), ApiError> {
    let header = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    let web_origin = web_base_url.trim_end_matches('/');
    let ok = header("origin").is_some_and(|o| o == web_origin)
        || matches!(header("sec-fetch-site"), Some("same-origin" | "same-site"));
    if ok {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "bad_origin",
            "Request origin not allowed.",
        ))
    }
}

async fn redeem_link(
    State(ctx): State<AppContext>,
    session: Session,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RedeemRequest>,
) -> Result<Json<Value>, ApiError> {
    let web = Settings::get(&ctx).web_base_url;
    check_origin(&headers, &web)?;
    let user_id = magic_links::consume(&ctx.db, &body.token)
        .await?
        .ok_or_else(|| ApiError::gone("link_invalid"))?;
    start_session(&ctx, &session, user_id).await?;
    Ok(Json(
        json!({ "redirect": format!("{}/dashboard", web.trim_end_matches('/')) }),
    ))
}

/// Expands to a configured GitHub OAuth client (the typestate client type is not nameable
/// without noise); 503 if no client id/secret is set.
macro_rules! github_client {
    ($s:expr) => {{
        if $s.github_client_id.is_empty() || $s.github_client_secret.is_empty() {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "github_not_configured",
                "GitHub sign-in is not configured.",
            ));
        }
        BasicClient::new(ClientId::new($s.github_client_id.clone()))
            .set_client_secret(ClientSecret::new($s.github_client_secret.clone()))
            .set_auth_uri(
                AuthUrl::new("https://github.com/login/oauth/authorize".into())
                    .map_err(ApiError::internal)?,
            )
            .set_token_uri(
                TokenUrl::new("https://github.com/login/oauth/access_token".into())
                    .map_err(ApiError::internal)?,
            )
            .set_redirect_uri(
                RedirectUrl::new(format!(
                    "{}/v1/auth/sign-in/github/callback",
                    $s.api_base_url
                ))
                .map_err(ApiError::internal)?,
            )
    }};
}

async fn github_start(
    State(ctx): State<AppContext>,
    session: Session,
) -> Result<Json<Value>, ApiError> {
    let s = Settings::get(&ctx);
    let client = github_client!(s);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read:user".into()))
        .add_scope(Scope::new("user:email".into()))
        .set_pkce_challenge(challenge)
        .url();
    session
        .insert(GH_KEY, (state.secret().clone(), verifier.secret().clone()))
        .await?;
    Ok(Json(json!({ "url": url })))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct GhUser {
    id: i64,
    login: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GhEmail {
    email: String,
    primary: bool,
    verified: bool,
}

fn bad_gateway(e: impl std::fmt::Display) -> ApiError {
    tracing::warn!(error = %e, "github exchange failed");
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        "oauth_exchange",
        "GitHub sign-in failed.",
    )
}

async fn github_callback(
    State(ctx): State<AppContext>,
    session: Session,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let s = Settings::get(&ctx);
    let client = github_client!(s);
    let stored = session.remove::<(String, String)>(GH_KEY).await?;
    let Some((state, verifier)) = stored.filter(|(st, _)| *st == q.state) else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "oauth_state",
            "OAuth state mismatch; start sign-in again.",
        ));
    };
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(ApiError::internal)?;
    let _ = state;
    let token = client
        .exchange_code(AuthorizationCode::new(q.code))
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&http)
        .await
        .map_err(bad_gateway)?;
    let access = token.access_token().secret();
    let get = |url: &str| http.get(url).bearer_auth(access).header("User-Agent", UA);
    let gh: GhUser = get("https://api.github.com/user")
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(bad_gateway)?
        .json()
        .await
        .map_err(bad_gateway)?;
    let emails: Vec<GhEmail> = get("https://api.github.com/user/emails")
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(bad_gateway)?
        .json()
        .await
        .map_err(bad_gateway)?;
    let email = emails
        .into_iter()
        .find(|e| e.primary && e.verified)
        .and_then(|e| user_model::normalize_email(&e.email))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "github_no_verified_email",
                "The GitHub account has no verified primary email.",
            )
        })?;
    let user = user_model::find_or_create_github(
        &ctx.db,
        &gh.id.to_string(),
        &email,
        gh.name.or(Some(gh.login)),
    )
    .await?;
    start_session(&ctx, &session, user.id).await?;
    let to = format!("{}/dashboard", s.web_base_url);
    Ok((StatusCode::FOUND, [(header::LOCATION, to)]).into_response())
}

async fn csrf_token(
    State(ctx): State<AppContext>,
    session: Session,
    _user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let sid = session.id().ok_or_else(ApiError::unauthenticated)?;
    Ok(Json(
        json!({ "token": csrf::token(&Settings::get(&ctx).session_secret, &sid.to_string()) }),
    ))
}

async fn sign_out(session: Session) -> Result<StatusCode, ApiError> {
    session.flush().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me(
    State(ctx): State<AppContext>,
    AuthUser(id): AuthUser,
) -> Result<Json<Value>, ApiError> {
    let u = users::Entity::find_by_id(id)
        .one(&ctx.db)
        .await?
        .ok_or_else(ApiError::unauthenticated)?;
    Ok(Json(
        json!({ "id": u.id, "email": u.email, "name": u.name }),
    ))
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("/v1/auth")
        .add("/magic-link", post(request_link))
        .add("/magic-link/redeem", post(redeem_link))
        .add("/sign-in/github/start", post(github_start))
        .add("/sign-in/github/callback", get(github_callback))
        .add("/csrf", get(csrf_token))
        .add("/sign-out", post(sign_out))
        .add("/me", get(me))
}
