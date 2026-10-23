pub mod _entities;

use sea_orm::{
    prelude::DateTimeWithTimeZone, ColumnTrait, ConnectionTrait, EntityTrait, PrimaryKeyTrait,
    QueryFilter,
};
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

use crate::api_error::ApiError;

/// A unit enum's serde name (`ConnectionStatus::Connected` -> `connected`).
pub fn enum_str<T: Serialize>(v: T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The unit enum named `s` (`enum_str` reversed); `None` for an unknown name.
pub fn enum_of<T: DeserializeOwned>(s: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(s.to_owned())).ok()
}

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
