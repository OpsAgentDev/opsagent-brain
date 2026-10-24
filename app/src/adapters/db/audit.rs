use async_trait::async_trait;
use opsagent_core::{
    audit::{Actor, AuditEntry, AuditLog},
    repo::RepoResult,
};
use sea_orm::{ActiveModelTrait, ConnectionTrait, Set};
use uuid::Uuid;

use super::{db_err, ledger_storage::stmt, Conn, Pg};
use crate::models::{_entities::audit_events, now};

#[async_trait]
impl<C: Conn> AuditLog for Pg<C> {
    async fn record(&self, e: AuditEntry) -> RepoResult<()> {
        let (actor_type, actor_id) = match e.actor {
            Actor::Member(id) => ("member", Some(id.to_string())),
            Actor::System => ("system", None),
            Actor::McpClient(grant) => ("mcp_client", Some(grant.to_string())),
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

    async fn recorded_for_run(
        &self,
        organisation_id: Uuid,
        action: &str,
        run_id: Uuid,
    ) -> RepoResult<bool> {
        let row = self
            .db()
            .query_one_raw(stmt(
                "SELECT 1 FROM audit_events WHERE organisation_id = $1 \
                 AND action = $2 AND metadata->>'run_id' = $3",
                vec![
                    organisation_id.into(),
                    action.into(),
                    run_id.to_string().into(),
                ],
            ))
            .await
            .map_err(db_err)?;
        Ok(row.is_some())
    }
}
