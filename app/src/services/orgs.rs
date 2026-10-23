//! Organisation use cases: create (with its DEK and first owner) and delete.
use chrono::Utc;
use opsagent_core::{
    audit::{AuditEntry, AuditLog},
    org::{slugify, NewOrganisation, Organisation, OrganisationsRepo, Role},
    repo::RepoError,
};
use opsagent_deliver::repo::SchedulesRepo;
use opsagent_secrets::{generate_dek, Kek};
use rand::RngCore;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, TransactionTrait};
use uuid::Uuid;

use crate::{
    adapters::db::Pg, api_error::ApiError, models::_entities::connections,
    services::connections as connections_service,
};

/// `slug` with a random 6-hex suffix, for a name whose slug is taken.
fn suffixed(slug: &str) -> String {
    let mut b = [0u8; 3];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{slug}-{:02x}{:02x}{:02x}", b[0], b[1], b[2])
}

/// Creates the org with a fresh wrapped DEK and makes `user_id` its owner.
pub async fn create(
    db: &DatabaseConnection,
    kek: &dyn Kek,
    user_id: Uuid,
    name: &str,
    timezone: &str,
) -> Result<Organisation, ApiError> {
    let id = Uuid::new_v4();
    let wrapped = kek.wrap(id, &generate_dek())?;
    let mut new = NewOrganisation {
        id,
        slug: slugify(name),
        name: name.into(),
        timezone: timezone.into(),
        kek_version: i32::try_from(wrapped.version).map_err(ApiError::internal)?,
        wrapped_dek: wrapped.blob,
    };
    let txn = db.begin().await?;
    let repo = Pg::new(&txn);
    let org = match repo.insert(new.clone()).await {
        Err(RepoError::Conflict("slug")) => {
            new.slug = suffixed(&new.slug);
            repo.insert(new).await?
        }
        other => other?,
    };
    repo.add_member(id, user_id, Role::Owner).await?;
    let target = Some(("organisation", id.to_string()));
    repo.record(AuditEntry::member(Some(id), user_id, "org.create", target))
        .await?;
    txn.commit().await?;
    Ok(org)
}

/// Soft-deletes the organisation for owner `actor`, in one transaction: every connection is
/// disconnected and every schedule disabled, so nothing is scanned for it again.
pub async fn delete(
    db: &DatabaseConnection,
    organisation_id: Uuid,
    actor: Uuid,
) -> Result<(), ApiError> {
    // TODO(billing): cancel the Stripe subscription before marking the org deleted.
    let txn = db.begin().await?;
    let repo = Pg::new(&txn);
    repo.lock(organisation_id).await?;
    repo.soft_delete(organisation_id, Utc::now()).await?;
    let live = connections::Entity::find()
        .filter(connections::Column::OrganisationId.eq(organisation_id))
        .all(&txn)
        .await?;
    for c in live {
        connections_service::end(&txn, c, "organisation_deleted").await?;
    }
    repo.disable_for_org(organisation_id).await?;
    let target = Some(("organisation", organisation_id.to_string()));
    repo.record(AuditEntry::member(
        Some(organisation_id),
        actor,
        "org.delete",
        target,
    ))
    .await?;
    txn.commit().await?;
    Ok(())
}
