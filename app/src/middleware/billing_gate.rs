//! The read-only gate (billing.md, Gating): on every organisation-scoped route, a request
//! other than GET, HEAD or OPTIONS from a gated organisation gets 402 `billing_required`.
//! It runs inside the `OrgScope` extractor, after membership, so a non-member still gets 404;
//! org-less routes (`/auth/*`, `/oauth/*`, `/mcp`, `/webhooks/stripe`, contact, waitlist)
//! never meet it.
use axum::{
    extract::MatchedPath,
    http::{request::Parts, Method},
};

use crate::{actions::orgs::OrgScope, api_error::ApiError, state::AppState};

/// What a read-only organisation may still do: pay, or leave.
const EXEMPT: [(&str, &str); 3] = [
    ("POST", "/v1/orgs/{org}/billing/checkout"),
    ("POST", "/v1/orgs/{org}/billing/portal"),
    ("DELETE", "/v1/orgs/{org}"),
];

/// `method` on route template `path` passes a read-only organisation.
pub fn exempt(method: &str, path: &str) -> bool {
    EXEMPT.contains(&(method, path))
}

pub async fn read_only(app: &AppState, scope: &OrgScope, parts: &Parts) -> Result<(), ApiError> {
    let m = &parts.method;
    if [Method::GET, Method::HEAD, Method::OPTIONS].contains(m) {
        return Ok(());
    }
    let path = parts.extensions.get::<MatchedPath>();
    if path.is_some_and(|p| exempt(m.as_str(), p.as_str())) {
        return Ok(());
    }
    let gate = &app.actions.billing.gate;
    Ok(gate.require_writable(scope.organisation.id).await?)
}
