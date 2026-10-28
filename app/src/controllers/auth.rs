use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use opsagent_core::{oauth::rules::consent_return_to, user::Email};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    actions::auth::{GithubProfile, MagicLinkInput, VerifyCodeInput},
    adapters::client_ip::ClientIp,
    api_error::{ApiError, ApiJson, Problem},
    middleware::{csrf, org_scope::AuthUser, session::USER_KEY},
    state::AppState,
};

const GH_KEY: &str = "github_oauth";
const UA: &str = "opsagent-brain";

#[derive(Deserialize, ToSchema)]
pub struct MagicLinkRequest {
    pub email: String,
    /// Where sign-in lands afterwards: only `/oauth/consent?request_id=<uuid>` is kept, anything
    /// else is dropped and the user lands on the dashboard.
    pub return_to: Option<String>,
}

/// Always 202, so the response never reveals whether an address is valid or known, or whether
/// it was rate limited (5 per address and 30 per client IP per hour).
#[utoipa::path(post, path = "/auth/magic-link", tag = "auth", request_body = MagicLinkRequest,
    responses((status = 202, description = "Sent if the address is valid and under the rate limit")))]
async fn request_link(
    State(app): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(body): ApiJson<MagicLinkRequest>,
) -> Result<StatusCode, ApiError> {
    // Only a proxy-reported address is a client; without one (local runs) there is no IP cap.
    let input = MagicLinkInput {
        email: body.email,
        client_ip: ip,
        return_to: body.return_to,
    };
    app.actions.auth.request_magic_link.run(input).await?;
    Ok(StatusCode::ACCEPTED)
}

/// Rotates the session id and binds the session to `user_id`.
async fn start_session(session: &Session, user_id: Uuid) -> Result<(), ApiError> {
    session.cycle_id().await?;
    session.insert(USER_KEY, user_id).await?;
    Ok(())
}

#[derive(Deserialize, ToSchema)]
pub struct RedeemRequest {
    pub token: String,
}

#[derive(Serialize, ToSchema)]
pub struct Redirect {
    pub redirect: String,
}

/// The web URL after sign-in: the validated `return_to`, else the dashboard.
fn landing(web_base_url: &str, return_to: Option<&str>) -> String {
    let path = return_to.and_then(consent_return_to);
    format!(
        "{}{}",
        web_base_url.trim_end_matches('/'),
        path.as_deref().unwrap_or("/dashboard")
    )
}

/// Anonymous, so CSRF-token-exempt; protected by an origin check instead. If `Origin` is
/// present it must equal the origin of `WEB_BASE_URL` exactly (nothing else can override a
/// mismatch). If it is absent, only `Sec-Fetch-Site: same-origin` is accepted (browsers set
/// that header and scripts cannot forge it); `same-site` is not enough.
fn check_origin(headers: &HeaderMap, web_base_url: &str) -> Result<(), ApiError> {
    let header = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    let ok = match header("origin") {
        Some(o) => o == web_base_url.trim_end_matches('/'),
        None => header("sec-fetch-site") == Some("same-origin"),
    };
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

#[utoipa::path(post, path = "/auth/magic-link/redeem", tag = "auth", request_body = RedeemRequest,
    responses((status = 200, body = Redirect, description = "Session cookie set"),
        (status = 403, body = Problem), (status = 410, body = Problem)))]
async fn redeem_link(
    State(app): State<AppState>,
    session: Session,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RedeemRequest>,
) -> Result<Json<Redirect>, ApiError> {
    let web = app.config.web_base_url.clone();
    check_origin(&headers, &web)?;
    let redeem = &app.actions.auth.redeem_magic_link;
    let (user_id, return_to) = redeem.run(&body.token).await?;
    start_session(&session, user_id).await?;
    Ok(Json(Redirect {
        redirect: landing(&web, return_to.as_deref()),
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct VerifyRequest {
    pub email: String,
    /// The 6-digit code from the sign-in mail; spaces are ignored.
    pub code: String,
}

/// Same session and `redirect` as redeem; 10 attempts per client IP and per address per 15
/// minutes, then 429.
#[utoipa::path(post, path = "/auth/magic-link/verify", tag = "auth", request_body = VerifyRequest,
    responses((status = 200, body = Redirect, description = "Session cookie set"),
        (status = 403, body = Problem), (status = 410, body = Problem),
        (status = 429, body = Problem)))]
async fn verify_code(
    State(app): State<AppState>,
    session: Session,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(body): ApiJson<VerifyRequest>,
) -> Result<Json<Redirect>, ApiError> {
    let web = app.config.web_base_url.clone();
    check_origin(&headers, &web)?;
    let input = VerifyCodeInput {
        email: body.email,
        code: body.code,
        client_ip: ip,
    };
    let (user_id, return_to) = app.actions.auth.verify_code.run(input).await?;
    start_session(&session, user_id).await?;
    Ok(Json(Redirect {
        redirect: landing(&web, return_to.as_deref()),
    }))
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

/// What the session keeps between GitHub start and callback.
#[derive(Serialize, Deserialize)]
struct GhPending {
    state: String,
    verifier: String,
    return_to: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AuthorizeUrl {
    pub url: String,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StartQuery {
    /// Where sign-in lands afterwards; same rule as the magic link's `return_to`.
    pub return_to: Option<String>,
}

#[utoipa::path(post, path = "/auth/sign-in/github/start", tag = "auth", params(StartQuery),
    responses((status = 200, body = AuthorizeUrl), (status = 503, body = Problem)))]
async fn github_start(
    State(app): State<AppState>,
    session: Session,
    Query(q): Query<StartQuery>,
) -> Result<Json<AuthorizeUrl>, ApiError> {
    let s = app.config.clone();
    let client = github_client!(s);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read:user".into()))
        .add_scope(Scope::new("user:email".into()))
        .set_pkce_challenge(challenge)
        .url();
    session
        .insert(
            GH_KEY,
            GhPending {
                state: state.secret().clone(),
                verifier: verifier.secret().clone(),
                return_to: q.return_to.as_deref().and_then(consent_return_to),
            },
        )
        .await?;
    Ok(Json(AuthorizeUrl {
        url: url.to_string(),
    }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
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

/// The GitHub user and their verified primary email, for an access token.
async fn github_identity(
    http: &reqwest::Client,
    access: &str,
) -> Result<(GhUser, Email), ApiError> {
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
        .and_then(|e| Email::parse(&e.email))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "github_no_verified_email",
                "The GitHub account has no verified primary email.",
            )
        })?;
    Ok((gh, email))
}

#[utoipa::path(get, path = "/auth/sign-in/github/callback", tag = "auth", params(CallbackQuery),
    responses((status = 302, description = "Session cookie set; redirects to the validated return_to, else the web dashboard"),
        (status = 400, body = Problem), (status = 502, body = Problem)))]
async fn github_callback(
    State(app): State<AppState>,
    session: Session,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let s = app.config.clone();
    let client = github_client!(s);
    let stored = session.remove::<GhPending>(GH_KEY).await?;
    let Some(GhPending {
        verifier,
        return_to,
        ..
    }) = stored.filter(|p| p.state == q.state)
    else {
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
    let token = client
        .exchange_code(AuthorizationCode::new(q.code))
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&http)
        .await
        .map_err(bad_gateway)?;
    let (gh, email) = github_identity(&http, token.access_token().secret()).await?;
    let profile = GithubProfile {
        github_id: gh.id,
        email,
        name: gh.name.or(Some(gh.login)),
    };
    let user_id = app.actions.auth.sign_in_github.run(profile).await?;
    start_session(&session, user_id).await?;
    let to = landing(&s.web_base_url, return_to.as_deref());
    Ok((StatusCode::FOUND, [(header::LOCATION, to)]).into_response())
}

#[derive(Serialize, ToSchema)]
pub struct Csrf {
    /// Send as `X-CSRF-Token` on every mutating request.
    pub token: String,
}

#[utoipa::path(get, path = "/auth/csrf", tag = "auth",
    responses((status = 200, body = Csrf), (status = 401, body = Problem)))]
async fn csrf_token(
    State(app): State<AppState>,
    session: Session,
    _user: AuthUser,
) -> Result<Json<Csrf>, ApiError> {
    let sid = session.id().ok_or_else(ApiError::unauthenticated)?;
    Ok(Json(Csrf {
        token: csrf::token(&app.config.session_secret, &sid.to_string()),
    }))
}

#[utoipa::path(post, path = "/auth/sign-out", tag = "auth", responses((status = 204)))]
async fn sign_out(session: Session) -> Result<StatusCode, ApiError> {
    session.flush().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct Me {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
}

#[utoipa::path(get, path = "/auth/me", tag = "auth",
    responses((status = 200, body = Me), (status = 401, body = Problem)))]
async fn me(State(app): State<AppState>, AuthUser(id): AuthUser) -> Result<Json<Me>, ApiError> {
    let u = app.actions.auth.current_user.run(id).await?;
    Ok(Json(Me {
        id: u.id,
        email: u.email.as_str().into(),
        name: u.name,
    }))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(request_link))
        .routes(routes!(redeem_link))
        .routes(routes!(verify_code))
        .routes(routes!(github_start))
        .routes(routes!(github_callback))
        .routes(routes!(csrf_token))
        .routes(routes!(sign_out))
        .routes(routes!(me))
}

#[cfg(test)]
mod tests {
    use super::landing;

    #[test]
    fn landing_follows_a_valid_return_to_else_the_dashboard() {
        let id = "0192f3a4-7b1c-7d2e-8f3a-4b5c6d7e8f90";
        let to = format!("/oauth/consent?request_id={id}");
        assert_eq!(
            landing("https://web.example/", Some(&to)),
            format!("https://web.example{to}")
        );
        for bad in [None, Some("//evil.example"), Some("https://evil.example")] {
            assert_eq!(
                landing("https://web.example", bad),
                "https://web.example/dashboard"
            );
        }
    }
}
