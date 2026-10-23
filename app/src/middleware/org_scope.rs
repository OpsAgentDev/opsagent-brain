use std::collections::HashMap;

use axum::{
    extract::{FromRequestParts, Path},
    http::request::Parts,
};
use loco_rs::app::AppContext;
use tower_sessions::Session;
use uuid::Uuid;

pub use crate::actions::orgs::OrgScope;

use super::session::USER_KEY;
use crate::{api_error::ApiError, app::actions};

/// The signed-in user.
pub struct AuthUser(pub Uuid);

impl FromRequestParts<AppContext> for AuthUser {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, s: &AppContext) -> Result<Self, ApiError> {
        let session = Session::from_request_parts(parts, s)
            .await
            .map_err(|(_, m)| ApiError::internal(m))?;
        match session.get::<Uuid>(USER_KEY).await? {
            Some(id) => Ok(Self(id)),
            None => Err(ApiError::unauthenticated()),
        }
    }
}

/// `{org}` (slug) resolved against the session user; 404 unless they are a member of it.
impl FromRequestParts<AppContext> for OrgScope {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, ctx: &AppContext) -> Result<Self, ApiError> {
        let AuthUser(user_id) = AuthUser::from_request_parts(parts, ctx).await?;
        let Path(p) = Path::<HashMap<String, String>>::from_request_parts(parts, ctx)
            .await
            .map_err(|_| ApiError::not_found())?;
        let slug = p.get("org").ok_or_else(ApiError::not_found)?;
        Ok(actions(ctx)?.orgs.resolve_scope.run(user_id, slug).await?)
    }
}
