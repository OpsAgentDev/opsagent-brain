use opsagent_secrets::{generate_dek, EnvKek, Kek};
use rand::RngCore;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};
use uuid::Uuid;

use super::{
    _entities::organisations,
    audit,
    members::{self, OWNER},
    now,
};
use crate::api_error::ApiError;

fn slugify(name: &str) -> String {
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

/// Creates the org with a fresh wrapped DEK and makes `user_id` its owner.
pub async fn create(
    db: &DatabaseConnection,
    user_id: Uuid,
    name: &str,
    timezone: &str,
) -> Result<organisations::Model, ApiError> {
    let id = Uuid::new_v4();
    let wrapped = EnvKek::from_env()?.wrap(id, &generate_dek())?;
    let mut slug = slugify(name);
    if organisations::Entity::find()
        .filter(organisations::Column::Slug.eq(&slug))
        .one(db)
        .await?
        .is_some()
    {
        let mut b = [0u8; 3];
        rand::rngs::OsRng.fill_bytes(&mut b);
        slug = format!("{slug}-{:02x}{:02x}{:02x}", b[0], b[1], b[2]);
    }
    let txn = db.begin().await?;
    let org = organisations::ActiveModel {
        id: Set(id),
        name: Set(name.into()),
        slug: Set(slug),
        timezone: Set(timezone.into()),
        plan: Set(None),
        stripe_customer_id: Set(None),
        kek_version: Set(Some(
            i32::try_from(wrapped.version).map_err(ApiError::internal)?,
        )),
        wrapped_dek: Set(Some(wrapped.blob)),
        deleted_at: Set(None),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(&txn)
    .await?;
    members::add(&txn, id, user_id, OWNER).await?;
    audit::record(
        &txn,
        Some(id),
        user_id,
        "org.create",
        Some(("organisation", id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok(org)
}
