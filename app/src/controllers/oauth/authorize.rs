//! `GET /oauth/authorize`: validates, stores the request, and hands the browser to web's
//! consent page.
use axum::{
    extract::{rejection::QueryRejection, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

use super::OAuthError;
use crate::{
    actions::oauth::{redirect_with, AuthorizeError, AuthorizeParams},
    adapters::client_ip::ClientIp,
    state::AppState,
};

fn found(location: String) -> Response {
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, location),
            (header::CACHE_CONTROL, "no-store".into()),
        ],
    )
        .into_response()
}

async fn authorize(
    State(s): State<AppState>,
    ip: ClientIp,
    query: Result<Query<AuthorizeParams>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = query else {
        return OAuthError::invalid_request("The query is malformed.").into_response();
    };
    let now = s.clock.now();
    match s
        .actions
        .oauth
        .start_authorization
        .run(params, ip.0, now)
        .await
    {
        Ok(id) => found(format!(
            "{}/oauth/consent?request_id={id}",
            s.config.web_base_url.trim_end_matches('/')
        )),
        Err(AuthorizeError::NoRedirect(e)) => e.into_response(),
        Err(AuthorizeError::Redirect {
            redirect_uri,
            error,
            state,
        }) => {
            let pairs = [("error", Some(error)), ("state", state.as_deref())];
            found(redirect_with(&redirect_uri, &pairs, &s.oauth_urls.issuer))
        }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/oauth/authorize", get(authorize))
}
