use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use opsagent_core::{oauth::rules::consent_return_to, user::Email};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    actions::auth::{GithubProfile, GoogleProfile, MagicLinkInput, VerifyCodeInput},
    adapters::client_ip::ClientIp,
    api_error::{ApiError, ApiJson, Problem},
    config::Config,
    middleware::{csrf, org_scope::AuthUser, session::USER_KEY},
    state::AppState,
};

const GH_KEY: &str = "github_oauth";
const GOOGLE_KEY: &str = "google_oauth";
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

/// The OAuth client with both endpoints set (the typestate of `oauth_client`).
type Client = BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

fn oauth_client(
    id: &str,
    secret: &str,
    auth_url: &str,
    token_url: &str,
    redirect: String,
) -> Result<Client, ApiError> {
    Ok(BasicClient::new(ClientId::new(id.into()))
        .set_client_secret(ClientSecret::new(secret.into()))
        .set_auth_uri(AuthUrl::new(auth_url.into()).map_err(ApiError::internal)?)
        .set_token_uri(TokenUrl::new(token_url.into()).map_err(ApiError::internal)?)
        .set_redirect_uri(RedirectUrl::new(redirect).map_err(ApiError::internal)?))
}

/// 503 `<provider>_not_configured` unless both the id and the secret are set.
fn github_client(c: &Config) -> Result<Client, ApiError> {
    if c.github_client_id.is_empty() || c.github_client_secret.is_empty() {
        return Err(ApiError::unavailable(
            "github_not_configured",
            "GitHub sign-in is not configured.",
        ));
    }
    oauth_client(
        &c.github_client_id,
        &c.github_client_secret,
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
        format!("{}/v1/auth/sign-in/github/callback", c.api_base_url),
    )
}

fn google_client(c: &Config) -> Result<Client, ApiError> {
    if c.google_client_id.is_empty() || c.google_client_secret.is_empty() {
        return Err(ApiError::unavailable(
            "google_not_configured",
            "Google sign-in is not configured.",
        ));
    }
    oauth_client(
        &c.google_client_id,
        &c.google_client_secret,
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
        format!("{}/v1/auth/sign-in/google/callback", c.api_base_url),
    )
}

/// What the session keeps between a provider's start and callback.
#[derive(Serialize, Deserialize)]
struct OauthPending {
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

/// The authorize URL with PKCE; state, verifier and `return_to` go in the session under `key`.
async fn oauth_start(
    session: &Session,
    key: &str,
    client: &Client,
    scopes: &[&str],
    return_to: Option<&str>,
) -> Result<Json<AuthorizeUrl>, ApiError> {
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut req = client.authorize_url(CsrfToken::new_random);
    for sc in scopes {
        req = req.add_scope(Scope::new((*sc).into()));
    }
    let (url, state) = req.set_pkce_challenge(challenge).url();
    let pending = OauthPending {
        state: state.secret().clone(),
        verifier: verifier.secret().clone(),
        return_to: return_to.and_then(consent_return_to),
    };
    session.insert(key, pending).await?;
    Ok(Json(AuthorizeUrl {
        url: url.to_string(),
    }))
}

#[utoipa::path(post, path = "/auth/sign-in/github/start", tag = "auth", params(StartQuery),
    responses((status = 200, body = AuthorizeUrl), (status = 503, body = Problem)))]
async fn github_start(
    State(app): State<AppState>,
    session: Session,
    Query(q): Query<StartQuery>,
) -> Result<Json<AuthorizeUrl>, ApiError> {
    let client = github_client(&app.config)?;
    let scopes = ["read:user", "user:email"];
    oauth_start(&session, GH_KEY, &client, &scopes, q.return_to.as_deref()).await
}

#[utoipa::path(post, path = "/auth/sign-in/google/start", tag = "auth", params(StartQuery),
    responses((status = 200, body = AuthorizeUrl), (status = 503, body = Problem)))]
async fn google_start(
    State(app): State<AppState>,
    session: Session,
    Query(q): Query<StartQuery>,
) -> Result<Json<AuthorizeUrl>, ApiError> {
    let client = google_client(&app.config)?;
    let scopes = ["openid", "email", "profile"];
    oauth_start(
        &session,
        GOOGLE_KEY,
        &client,
        &scopes,
        q.return_to.as_deref(),
    )
    .await
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// 302 to `{web}/sign-in?error=<code>`, keeping a validated `return_to`, so a browser that
/// navigated here lands on a page instead of JSON.
fn provider_failure(web_base_url: &str, err: &ApiError, return_to: Option<&str>) -> Response {
    let mut to = format!(
        "{}/sign-in?error={}",
        web_base_url.trim_end_matches('/'),
        err.code()
    );
    if let Some(r) = return_to.and_then(consent_return_to) {
        to.push_str(&format!("&return_to={}", urlencoding::encode(&r)));
    }
    (StatusCode::FOUND, [(header::LOCATION, to)]).into_response()
}

fn bad_gateway(e: impl std::fmt::Display) -> ApiError {
    tracing::warn!(error = %e, "oauth exchange failed");
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        "oauth_exchange",
        "Sign-in with the provider failed.",
    )
}

/// The provider's access token for the callback `code`.
async fn exchange(
    http: &reqwest::Client,
    client: &Client,
    code: String,
    verifier: String,
) -> Result<String, ApiError> {
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(http)
        .await
        .map_err(bad_gateway)?;
    Ok(token.access_token().secret().clone())
}

/// A JSON GET with the access token as bearer.
async fn fetch<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    access: &str,
) -> Result<T, ApiError> {
    http.get(url)
        .bearer_auth(access)
        .header("User-Agent", UA)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(bad_gateway)?
        .json()
        .await
        .map_err(bad_gateway)
}

/// The callback both providers share: checks the state, runs `sign_in(code, verifier)`, starts
/// the session and lands. Every failure after the state check, and a state mismatch, 302s to
/// `/sign-in?error=` instead of answering JSON.
async fn finish_oauth<F, Fut>(
    app: &AppState,
    session: &Session,
    key: &str,
    q: CallbackQuery,
    sign_in: F,
) -> Result<Response, ApiError>
where
    F: FnOnce(String, String) -> Fut,
    Fut: std::future::Future<Output = Result<Uuid, ApiError>>,
{
    let web = &app.config.web_base_url;
    let stored = session.remove::<OauthPending>(key).await?;
    // A mismatch keeps the `return_to` this same session stored at start (already validated).
    let return_to = stored.as_ref().and_then(|p| p.return_to.clone());
    let Some(p) = stored.filter(|p| p.state == q.state) else {
        let err = ApiError::new(
            StatusCode::BAD_REQUEST,
            "oauth_state",
            "OAuth state mismatch; start sign-in again.",
        );
        return Ok(provider_failure(web, &err, return_to.as_deref()));
    };
    let outcome = async {
        let user_id = sign_in(q.code, p.verifier).await?;
        start_session(session, user_id).await
    }
    .await;
    Ok(match outcome {
        Ok(()) => {
            let to = landing(web, p.return_to.as_deref());
            (StatusCode::FOUND, [(header::LOCATION, to)]).into_response()
        }
        Err(e) => provider_failure(web, &e, p.return_to.as_deref()),
    })
}

fn http_client() -> Result<reqwest::Client, ApiError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(ApiError::internal)
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

/// The GitHub user and their verified primary email, for an access token.
async fn github_identity(
    http: &reqwest::Client,
    access: &str,
) -> Result<(GhUser, Email), ApiError> {
    let gh: GhUser = fetch(http, "https://api.github.com/user", access).await?;
    let emails: Vec<GhEmail> = fetch(http, "https://api.github.com/user/emails", access).await?;
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
    responses((status = 302, description = "Session cookie set; redirects to the validated return_to, else the web dashboard. A failure redirects to /sign-in?error=<code>")))]
async fn github_callback(
    State(app): State<AppState>,
    session: Session,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let sign_in = |code, verifier| async {
        let client = github_client(&app.config)?;
        let http = http_client()?;
        let access = exchange(&http, &client, code, verifier).await?;
        let (gh, email) = github_identity(&http, &access).await?;
        let profile = GithubProfile {
            github_id: gh.id,
            email,
            name: gh.name.or(Some(gh.login)),
        };
        Ok(app.actions.auth.sign_in_github.run(profile).await?)
    };
    finish_oauth(&app, &session, GH_KEY, q, sign_in).await
}

#[derive(Deserialize)]
struct GoogleUser {
    sub: String,
    email: String,
    #[serde(default)]
    email_verified: bool,
    name: Option<String>,
}

/// The Google profile for an access token; the address must be verified.
async fn google_identity(http: &reqwest::Client, access: &str) -> Result<GoogleProfile, ApiError> {
    let u: GoogleUser = fetch(
        http,
        "https://openidconnect.googleapis.com/v1/userinfo",
        access,
    )
    .await?;
    let email = Email::parse(&u.email)
        .filter(|_| u.email_verified)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "google_no_verified_email",
                "The Google account has no verified email.",
            )
        })?;
    Ok(GoogleProfile {
        google_id: u.sub,
        email,
        name: u.name,
    })
}

#[utoipa::path(get, path = "/auth/sign-in/google/callback", tag = "auth", params(CallbackQuery),
    responses((status = 302, description = "Session cookie set; redirects to the validated return_to, else the web dashboard. A failure redirects to /sign-in?error=<code>")))]
async fn google_callback(
    State(app): State<AppState>,
    session: Session,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let sign_in = |code, verifier| async {
        let client = google_client(&app.config)?;
        let http = http_client()?;
        let access = exchange(&http, &client, code, verifier).await?;
        let profile = google_identity(&http, &access).await?;
        Ok(app.actions.auth.sign_in_google.run(profile).await?)
    };
    finish_oauth(&app, &session, GOOGLE_KEY, q, sign_in).await
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
        .routes(routes!(google_start))
        .routes(routes!(google_callback))
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
