use std::collections::HashMap;

use axum::{
    extract::{FromRequestParts, Path},
    http::request::Parts,
};
use loco_rs::app::AppContext;
use opsagent_core::org::Role;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use tower_sessions::Session;
use uuid::Uuid;

use super::session::USER_KEY;
use crate::{
    api_error::ApiError,
    models::_entities::{members, organisations},
};

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

/// `{org}` (slug) resolved against the session user. Anyone who is not a member of a live org
/// gets the same 404 as for an org that does not exist.
pub struct OrgScope {
    pub user_id: Uuid,
    pub organisation_id: Uuid,
    pub member_id: Uuid,
    pub role: String,
}

impl OrgScope {
    pub fn require_owner(&self) -> Result<(), ApiError> {
        if self.role == Role::Owner.as_str() {
            Ok(())
        } else {
            Err(ApiError::forbidden())
        }
    }
}

impl FromRequestParts<AppContext> for OrgScope {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, ctx: &AppContext) -> Result<Self, ApiError> {
        let AuthUser(user_id) = AuthUser::from_request_parts(parts, ctx).await?;
        let Path(p) = Path::<HashMap<String, String>>::from_request_parts(parts, ctx)
            .await
            .map_err(|_| ApiError::not_found())?;
        let slug = p.get("org").ok_or_else(ApiError::not_found)?;
        let org = organisations::Entity::find()
            .filter(organisations::Column::Slug.eq(slug))
            .filter(organisations::Column::DeletedAt.is_null())
            .one(&ctx.db)
            .await?
            .ok_or_else(ApiError::not_found)?;
        let m = members::Entity::find()
            .filter(members::Column::OrganisationId.eq(org.id))
            .filter(members::Column::UserId.eq(user_id))
            .one(&ctx.db)
            .await?
            .ok_or_else(ApiError::not_found)?;
        Ok(Self {
            user_id,
            organisation_id: org.id,
            member_id: m.id,
            role: m.role,
        })
    }
}
