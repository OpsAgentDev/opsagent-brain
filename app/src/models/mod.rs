pub mod _entities;
pub mod audit;
pub mod connections;
pub mod ledger_storage;
pub mod magic_links;
pub mod members;
pub mod organisations;
pub mod schedules;
pub mod users;

use sea_orm::{
    prelude::DateTimeWithTimeZone, ColumnTrait, ConnectionTrait, EntityTrait, PrimaryKeyTrait,
    QueryFilter,
};
use uuid::Uuid;

use crate::api_error::ApiError;

pub fn now() -> DateTimeWithTimeZone {
    chrono::Utc::now().into()
}

/// Tenant-filtered lookup by raw path id: a malformed id, an unknown id and another org's id
/// are the same 404.
pub async fn find_in_org<E>(
    db: &impl ConnectionTrait,
    org_column: E::Column,
    organisation_id: Uuid,
    id: &str,
) -> Result<E::Model, ApiError>
where
    E: EntityTrait,
    <E::PrimaryKey as PrimaryKeyTrait>::ValueType: From<Uuid>,
{
    let id: Uuid = id.parse().map_err(|_| ApiError::not_found())?;
    E::find_by_id(id)
        .filter(org_column.eq(organisation_id))
        .one(db)
        .await?
        .ok_or_else(ApiError::not_found)
}
