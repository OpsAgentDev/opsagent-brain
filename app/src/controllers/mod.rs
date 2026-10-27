pub mod agents;
pub mod auth;
pub mod connections;
pub mod contact;
pub mod deliveries;
pub mod findings;
pub mod health;
pub mod integrations;
pub mod members;
pub mod oauth;
pub mod oauth_consent;
pub mod openapi;
pub mod orgs;
pub mod recipients;
pub mod resources;
pub mod runs;
#[cfg(feature = "test-support")]
pub mod test_routes;
pub mod waitlist;

use serde::Serialize;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// `{org}` path segment, for the OpenAPI document.
#[derive(IntoParams)]
#[into_params(parameter_in = Path)]
pub struct OrgPath {
    /// Organisation slug.
    pub org: String,
}

/// `{org}` and `{id}` path segments, for the OpenAPI document.
#[derive(IntoParams)]
#[into_params(parameter_in = Path)]
pub struct OrgIdPath {
    /// Organisation slug.
    pub org: String,
    pub id: Uuid,
}

/// 202 body for endpoints that enqueue a run.
#[derive(Serialize, ToSchema)]
pub struct RunAccepted {
    pub run_id: Uuid,
}

/// A malformed id is the same 404 as an unknown id or another org's.
pub(crate) fn parse_id(id: &str) -> Result<Uuid, crate::api_error::ApiError> {
    id.parse()
        .map_err(|_| crate::api_error::ApiError::not_found())
}
