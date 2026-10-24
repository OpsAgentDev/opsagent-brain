use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::repo::{RepoError, RepoResult};
use opsagent_deliver::repo::{Integration, IntegrationsRepo, SealedToken, ACTIVE, REVOKED, SLACK};
use sea_orm::{
    sea_query::{Expr, OnConflict},
    ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, SqlErr,
};
use uuid::Uuid;

use super::{db_err, utc, Conn, Pg};
use crate::models::{
    _entities::integrations::{self, Column as Col},
    now,
};

fn integration(m: integrations::Model) -> Integration {
    Integration {
        id: m.id,
        organisation_id: m.organisation_id,
        kind: m.kind,
        status: m.status,
        config: m.config,
        ciphertext: m.ciphertext,
        nonce: m.nonce,
        created_at: utc(m.created_at),
        updated_at: utc(m.updated_at),
    }
}

#[async_trait]
impl<C: Conn> IntegrationsRepo for Pg<C> {
    async fn upsert_slack(
        &self,
        organisation_id: Uuid,
        config: serde_json::Value,
        token: SealedToken,
    ) -> RepoResult<()> {
        let row = integrations::ActiveModel {
            id: Set(Uuid::new_v4()),
            organisation_id: Set(organisation_id),
            kind: Set(SLACK.into()),
            config: Set(config),
            ciphertext: Set(token.ciphertext),
            nonce: Set(token.nonce),
            kek_version: Set(token.kek_version),
            status: Set(ACTIVE.into()),
            created_at: Set(now()),
            updated_at: Set(now()),
        };
        let upsert = OnConflict::columns([Col::OrganisationId, Col::Kind])
            .update_columns([
                Col::Config,
                Col::Ciphertext,
                Col::Nonce,
                Col::KekVersion,
                Col::Status,
            ])
            .value(Col::UpdatedAt, now())
            .to_owned();
        integrations::Entity::insert(row)
            .on_conflict(upsert)
            .exec_without_returning(self.db())
            .await
            .map(|_| ())
            .map_err(|e| match e.sql_err() {
                Some(SqlErr::UniqueConstraintViolation(m))
                    if m.contains("integrations_slack_team_uniq") =>
                {
                    RepoError::Conflict("slack_workspace")
                }
                _ => db_err(e),
            })
    }

    async fn list(&self, organisation_id: Uuid) -> RepoResult<Vec<Integration>> {
        let rows = integrations::Entity::find()
            .filter(Col::OrganisationId.eq(organisation_id))
            .order_by_asc(Col::CreatedAt)
            .all(self.db())
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(integration).collect())
    }

    async fn active_slack(&self, organisation_id: Uuid) -> RepoResult<Option<Integration>> {
        let m = integrations::Entity::find()
            .filter(Col::OrganisationId.eq(organisation_id))
            .filter(Col::Kind.eq(SLACK))
            .filter(Col::Status.eq(ACTIVE))
            .one(self.db())
            .await
            .map_err(db_err)?;
        Ok(m.map(integration))
    }

    async fn mark_revoked(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        _at: DateTime<Utc>,
    ) -> RepoResult<()> {
        // SQL now(), not `at`: `revoke_notice_due` compares it with `deliveries.sent_at`, also
        // SQL now().
        integrations::Entity::update_many()
            .col_expr(Col::Status, REVOKED.into())
            .col_expr(Col::UpdatedAt, Expr::current_timestamp())
            .filter(Col::OrganisationId.eq(organisation_id))
            .filter(Col::Id.eq(id))
            .exec(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn delete(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<bool> {
        let gone = integrations::Entity::delete_many()
            .filter(Col::OrganisationId.eq(organisation_id))
            .filter(Col::Id.eq(id))
            .exec(self.db())
            .await
            .map_err(db_err)?;
        Ok(gone.rows_affected == 1)
    }
}
