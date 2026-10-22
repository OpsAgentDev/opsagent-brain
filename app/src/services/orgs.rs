//! Organisation use cases: create (with its DEK and first owner) and delete.
use opsagent_secrets::{generate_dek, Kek};
use rand::RngCore;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};
use uuid::Uuid;

use crate::{
    api_error::ApiError,
    models::{
        _entities::organisations,
        audit,
        members::{self, OWNER},
        now,
        organisations::slugify,
    },
};

/// Creates the org with a fresh wrapped DEK and makes `user_id` its owner.
pub async fn create(
    db: &DatabaseConnection,
    kek: &dyn Kek,
    user_id: Uuid,
    name: &str,
    timezone: &str,
) -> Result<organisations::Model, ApiError> {
    let id = Uuid::new_v4();
    let wrapped = kek.wrap(id, &generate_dek())?;
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

/// Soft-deletes the organisation for owner `actor`.
pub async fn delete(
    db: &DatabaseConnection,
    organisation_id: Uuid,
    actor: Uuid,
) -> Result<(), ApiError> {
    // TODO(billing): cancel the Stripe subscription before marking the org deleted.
    let txn = db.begin().await?;
    let org = organisations::Entity::find_by_id(organisation_id)
        .one(&txn)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let mut a: organisations::ActiveModel = org.into();
    a.deleted_at = Set(Some(now()));
    a.updated_at = Set(now());
    a.update(&txn).await?;
    audit::record(
        &txn,
        Some(organisation_id),
        actor,
        "org.delete",
        Some(("organisation", organisation_id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
