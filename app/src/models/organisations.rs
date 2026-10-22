use sea_orm::{ConnectionTrait, DbErr, EntityTrait};
use uuid::Uuid;

use super::_entities::organisations;
use crate::api_error::ApiError;

/// Whether the organisation is soft-deleted (or gone). Workers check it before any call.
pub async fn deleted(db: &impl ConnectionTrait, id: Uuid) -> Result<bool, DbErr> {
    Ok(organisations::Entity::find_by_id(id)
        .one(db)
        .await?
        .is_none_or(|o| o.deleted_at.is_some()))
}

/// URL slug from an org name: lowercase ASCII alphanumerics and single dashes, at most 48.
pub fn slugify(name: &str) -> String {
    let mut s = String::new();
    for c in name.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c);
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    let s = s.trim_matches('-');
    if s.is_empty() {
        "org".into()
    } else {
        s.chars().take(48).collect()
    }
}

pub fn valid_name(raw: &str) -> Result<String, ApiError> {
    let n = raw.trim();
    if n.is_empty() || n.chars().count() > 100 {
        return Err(ApiError::invalid("name must be 1 to 100 characters"));
    }
    Ok(n.into())
}

pub fn valid_timezone(raw: &str) -> Result<String, ApiError> {
    raw.parse::<chrono_tz::Tz>()
        .map(|_| raw.into())
        .map_err(|_| ApiError::invalid("timezone must be an IANA name such as Europe/Berlin"))
}
