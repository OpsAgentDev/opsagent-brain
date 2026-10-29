use std::collections::HashMap;

use axum::{
    extract::{FromRequestParts, Path},
    http::request::Parts,
};
use tower_sessions::Session;
use uuid::Uuid;

pub use crate::actions::orgs::OrgScope;

use super::session::USER_KEY;
use crate::{api_error::ApiError, state::AppState};

/// The signed-in user.
pub struct AuthUser(pub Uuid);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, ApiError> {
        let session = Session::from_request_parts(parts, s)
            .await
            .map_err(|(_, m)| ApiError::internal(m))?;
        match session.get::<Uuid>(USER_KEY).await? {
            Some(id) => Ok(Self(id)),
            None => Err(ApiError::unauthenticated()),
        }
    }
}

/// `{org}` (slug) resolved against the session user; 404 unless they are a member of it,
/// then the billing read-only gate (`billing_gate`).
impl FromRequestParts<AppState> for OrgScope {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self, ApiError> {
        let AuthUser(user_id) = AuthUser::from_request_parts(parts, app).await?;
        let Path(p) = Path::<HashMap<String, String>>::from_request_parts(parts, app)
            .await
            .map_err(|_| ApiError::not_found())?;
        let slug = p.get("org").ok_or_else(ApiError::not_found)?;
        let scope = app.actions.orgs.resolve_scope.run(user_id, slug).await?;
        super::billing_gate::read_only(app, &scope, parts).await?;
        Ok(scope)
    }
}
