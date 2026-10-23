use async_trait::async_trait;
use opsagent_core::{
    audit::{AuditEntry, AuditLog},
    repo::RepoResult,
};
use sea_orm::{ActiveModelTrait, Set};
use uuid::Uuid;

use super::{db_err, Conn, Pg};
use crate::models::{_entities::audit_events, now};

#[async_trait]
impl<C: Conn> AuditLog for Pg<C> {
    async fn record(&self, e: AuditEntry) -> RepoResult<()> {
        let (actor_type, actor_id) = match e.actor {
            Some(id) => ("member", Some(id.to_string())),
            None => ("system", None),
        };
        let (target_type, target_id) = e.target.unzip();
        audit_events::ActiveModel {
            id: Set(Uuid::new_v4()),
            organisation_id: Set(e.organisation_id),
            actor_type: Set(actor_type.into()),
            actor_id: Set(actor_id),
            action: Set(e.action),
            target_type: Set(target_type.map(Into::into)),
            target_id: Set(target_id),
            outcome: Set(Some(e.outcome)),
            metadata: Set(e.meta),
            created_at: Set(now()),
            updated_at: Set(now()),
        }
        .insert(self.db())
        .await
        .map(|_| ())
        .map_err(db_err)
    }
}
