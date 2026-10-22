use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, PaginatorTrait,
    QueryFilter, Set,
};
use uuid::Uuid;

use super::{_entities::members, now};

pub const OWNER: &str = "owner";
pub const MEMBER: &str = "member";

pub async fn add(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> Result<members::Model, DbErr> {
    members::ActiveModel {
        id: Set(Uuid::new_v4()),
        organisation_id: Set(organisation_id),
        user_id: Set(user_id),
        role: Set(role.into()),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(db)
    .await
}

pub async fn owner_count(db: &impl ConnectionTrait, organisation_id: Uuid) -> Result<u64, DbErr> {
    members::Entity::find()
        .filter(members::Column::OrganisationId.eq(organisation_id))
        .filter(members::Column::Role.eq(OWNER))
        .count(db)
        .await
}
