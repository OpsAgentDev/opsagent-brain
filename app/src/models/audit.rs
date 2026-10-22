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
    let (target_type, target_id) = target.unzip();
    audit_events::ActiveModel {
        id: Set(Uuid::new_v4()),
        organisation_id: Set(organisation_id),
        actor_type: Set("member".into()),
        actor_id: Set(Some(actor_id.to_string())),
        action: Set(action.into()),
        target_type: Set(target_type.map(Into::into)),
        target_id: Set(target_id),
        outcome: Set(Some("success".into())),
        metadata: Set(serde_json::json!({})),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(db)
    .await
    .map(|_| ())
}
