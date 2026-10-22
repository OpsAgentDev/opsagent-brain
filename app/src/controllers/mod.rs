pub mod auth;
pub mod connections;
pub mod findings;
pub mod health;
pub mod members;
pub mod openapi;
pub mod orgs;
pub mod resources;
pub mod runs;

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
