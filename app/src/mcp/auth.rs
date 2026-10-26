//! The bearer layer in front of `/mcp`: resolves the access token and the member's scope on
//! every request, applies the per-token and per-organisation limits, and hands the tools a
//! `Caller` through the request extensions.
use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    actions::{hit_ip, oauth::Bearer},
    adapters::client_ip::ClientIp,
    api_error::ApiError,
    state::AppState,
    tools::{Caller, Via},
};

const WINDOW_SECS: i64 = 60;
const PER_TOKEN: i64 = 60;
const PER_ORG: i64 = 600;
/// Checked before the token lookup, so unauthenticated floods never reach the database.
const PER_IP: i64 = 600;

pub async fn layer(
    State(app): State<AppState>,
    ip: ClientIp,
    mut req: Request,
    next: Next,
) -> Response {
    let token = bearer_token(req.headers());
    match authenticate(&app, ip, token).await {
        Ok(b) => {
            req.extensions_mut().insert(Caller {
                scope: b.scope,
                via: Via::Mcp {
                    grant_id: b.grant.id,
                    client_id: b.grant.client_id,
                    token_id: b.token.id,
                },
            });
            next.run(req).await
        }
        Err(Refused::Token) => unauthorized(&app),
        Err(Refused::Api(e)) => e.into_response(),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| token.to_owned())
}

/// Why a request is refused: a missing or dead token (401 with discovery), or a limit or
/// failure.
enum Refused {
    Token,
    Api(ApiError),
}

fn rate_limited() -> Refused {
    let retry = u64::try_from(WINDOW_SECS).unwrap_or(60);
    Refused::Api(ApiError::rate_limited(
        "Too many MCP calls; retry in a minute.",
        retry,
    ))
}

async fn authenticate(
    app: &AppState,
    ip: ClientIp,
    token: Option<String>,
) -> Result<Bearer, Refused> {
    let internal = |e| Refused::Api(ApiError::from(e));
    let limiter = app.limiter.as_ref();
    if !hit_ip(limiter, "mcp", ip.0, PER_IP, WINDOW_SECS)
        .await
        .map_err(internal)?
    {
        return Err(rate_limited());
    }
    let Some(token) = token else {
        return Err(Refused::Token);
    };
    let now = app.clock.now();
    let oauth = &app.actions.oauth;
    let Some(b) = oauth
        .authenticate_bearer
        .run(&token, now)
        .await
        .map_err(internal)?
    else {
        return Err(Refused::Token);
    };
    let limits = [
        (format!("mcp:token:{}", b.token.id), PER_TOKEN),
        (format!("mcp:org:{}", b.grant.organisation_id), PER_ORG),
    ];
    for (key, cap) in limits {
        if !app
            .limiter
            .hit(&key, cap, WINDOW_SECS)
            .await
            .map_err(internal)?
        {
            return Err(rate_limited());
        }
    }
    let touch = format!("mcp:touch:{}", b.grant.id);
    if app
        .limiter
        .hit(&touch, 1, WINDOW_SECS)
        .await
        .map_err(internal)?
    {
        oauth
            .touch_grant
            .run(&b.grant, now)
            .await
            .map_err(internal)?;
    }
    Ok(b)
}

/// 401 pointing the client at the protected resource metadata (RFC 9728 section 5.1).
fn unauthorized(app: &AppState) -> Response {
    let value = format!(
        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", scope=\"{}\"",
        app.oauth_urls.issuer,
        opsagent_core::oauth::SCOPE,
    );
    let mut res = ApiError::unauthenticated().into_response();
    if let Ok(v) = HeaderValue::from_str(&value) {
        res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    res
}
