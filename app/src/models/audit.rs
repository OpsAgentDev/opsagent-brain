use sea_orm::{ActiveModelTrait, ConnectionTrait, DbErr, Set};
use uuid::Uuid;

use super::{_entities::audit_events, now};

/// Insert one audit row; `actor_id` is the acting user's id.
pub async fn record(
    db: &impl ConnectionTrait,
    organisation_id: Option<Uuid>,
    actor_id: Uuid,
    action: &str,
    target: Option<(&str, String)>,
) -> Result<(), DbErr> {
    record_meta(
        db,
        organisation_id,
        actor_id,
        action,
        target,
        serde_json::json!({}),
    )
    .await
}

/// `record` with metadata.
pub async fn record_meta(
    db: &impl ConnectionTrait,
    organisation_id: Option<Uuid>,
    actor_id: Uuid,
    action: &str,
    target: Option<(&str, String)>,
    metadata: serde_json::Value,
) -> Result<(), DbErr> {
    let actor = ("member", Some(actor_id.to_string()));
    insert(
        db,
        organisation_id,
        actor,
        action,
        target,
        "success",
        metadata,
    )
    .await
}

/// Audit row for work done by the system (workers), with an explicit outcome.
pub async fn record_system(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    action: &str,
    target: (&str, String),
    outcome: &str,
    metadata: serde_json::Value,
) -> Result<(), DbErr> {
    let actor = ("system", None);
    insert(
        db,
        Some(organisation_id),
        actor,
        action,
        Some(target),
        outcome,
        metadata,
    )
    .await
}

async fn insert(
    db: &impl ConnectionTrait,
    organisation_id: Option<Uuid>,
    (actor_type, actor_id): (&str, Option<String>),
    action: &str,
    target: Option<(&str, String)>,
    outcome: &str,
    metadata: serde_json::Value,
) -> Result<(), DbErr> {
    let (target_type, target_id) = target.unzip();
    audit_events::ActiveModel {
        id: Set(Uuid::new_v4()),
        organisation_id: Set(organisation_id),
        actor_type: Set(actor_type.into()),
        actor_id: Set(actor_id),
        action: Set(action.into()),
        target_type: Set(target_type.map(Into::into)),
        target_id: Set(target_id),
        outcome: Set(Some(outcome.into())),
        metadata: Set(metadata),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(db)
    .await
    .map(|_| ())
}
