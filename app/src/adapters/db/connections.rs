use async_trait::async_trait;
use opsagent_core::{
    connection::{
        Connection, ConnectionPatch, ConnectionStatus, ConnectionsRepo, NewConnection, SealedCreds,
        Verification,
    },
    repo::{RepoError, RepoResult},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    QuerySelect, Set,
};
use serde_json::json;
use uuid::Uuid;

use super::{db_err, utc, Conn, Pg};
use crate::models::{
    _entities::{
        connection_credentials as creds, connection_verifications as verifications, connections,
    },
    enum_of, enum_str, now,
};

/// The stored status; `Storage` for a name the domain does not know.
pub fn status_of(c: &connections::Model) -> RepoResult<ConnectionStatus> {
    enum_of(&c.status)
        .ok_or_else(|| RepoError::Storage(format!("unknown connection status {:?}", c.status)))
}

fn connection(m: connections::Model) -> RepoResult<Connection> {
    Ok(Connection {
        status: status_of(&m)?,
        id: m.id,
        organisation_id: m.organisation_id,
        provider: m.provider,
        display_name: m.display_name,
        status_reason: m.status_reason,
        external_account_id: m.external_account_id,
        template_version: m.template_version,
        scan_time_local: m.scan_time_local,
        briefing_time_local: m.briefing_time_local,
        api_rate_ceiling: m.api_rate_ceiling,
        slack_channel_id: m.slack_channel_id,
        first_connected_at: m.first_connected_at.map(utc),
        billable_from: m.billable_from.map(utc),
        created_at: utc(m.created_at),
        updated_at: utc(m.updated_at),
    })
}

impl<C: Conn> Pg<C> {
    async fn connection_row(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        lock: bool,
    ) -> RepoResult<Option<connections::Model>> {
        let q = connections::Entity::find_by_id(id)
            .filter(connections::Column::OrganisationId.eq(organisation_id));
        let q = if lock { q.lock_exclusive() } else { q };
        q.one(self.db()).await.map_err(db_err)
    }
}

#[async_trait]
impl<C: Conn> ConnectionsRepo for Pg<C> {
    async fn insert(&self, new: NewConnection, sealed: SealedCreds) -> RepoResult<Connection> {
        let id = Uuid::new_v4();
        let row = connections::ActiveModel {
            id: Set(id),
            organisation_id: Set(new.organisation_id),
            provider: Set(new.provider),
            external_account_id: Set(None),
            display_name: Set(Some(new.display_name)),
            status: Set(enum_str(ConnectionStatus::Pending)),
            status_reason: Set(None),
            template_version: Set(new.template_version),
            scan_time_local: Set(None),
            briefing_time_local: Set(None),
            slack_channel_id: Set(None),
            recipients: Set(json!([])),
            api_rate_ceiling: Set(None),
            first_connected_at: Set(None),
            billable_from: Set(None),
            verify_denied_streak: Set(0),
            verify_denied_first_at: Set(None),
            created_at: Set(now()),
            updated_at: Set(now()),
        }
        .insert(self.db())
        .await
        .map_err(db_err)?;
        creds::ActiveModel {
            connection_id: Set(id),
            kind: Set(new.credential_kind),
            ciphertext: Set(sealed.ciphertext),
            nonce: Set(sealed.nonce),
            kek_version: Set(sealed.kek_version),
            created_at: Set(now()),
            updated_at: Set(now()),
        }
        .insert(self.db())
        .await
        .map_err(db_err)?;
        connection(row)
    }

    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Connection>> {
        let row = self.connection_row(organisation_id, id, false).await?;
        row.map(connection).transpose()
    }

    async fn lock(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Connection>> {
        let row = self.connection_row(organisation_id, id, true).await?;
        row.map(connection).transpose()
    }

    async fn last_verification(
        &self,
        organisation_id: Uuid,
        id: Uuid,
    ) -> RepoResult<Option<Verification>> {
        if self
            .connection_row(organisation_id, id, false)
            .await?
            .is_none()
        {
            return Ok(None);
        }
        let row = verifications::Entity::find()
            .filter(verifications::Column::ConnectionId.eq(id))
            .order_by_desc(verifications::Column::CreatedAt)
            .one(self.db())
            .await
            .map_err(db_err)?;
        Ok(row.map(|v| Verification {
            outcome: v.outcome,
            at: utc(v.created_at),
            assume_with_ok: v.assume_with_ok,
            assume_without_denied: v.assume_without_denied,
            policy_matches: v.policy_matches,
            extra_grants: v.extra_grants,
            missing_grants: v.missing_grants,
        }))
    }

    async fn list(&self, organisation_id: Uuid) -> RepoResult<Vec<Connection>> {
        connections::Entity::find()
            .filter(connections::Column::OrganisationId.eq(organisation_id))
            .order_by_asc(connections::Column::CreatedAt)
            .all(self.db())
            .await
            .map_err(db_err)?
            .into_iter()
            .map(connection)
            .collect()
    }

    async fn update(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        p: ConnectionPatch,
    ) -> RepoResult<Connection> {
        let row = self.connection_row(organisation_id, id, false).await?;
        let mut a = row.ok_or(RepoError::NotFound)?.into_active_model();
        if let Some(n) = p.display_name {
            a.display_name = Set(Some(n));
        }
        if let Some(t) = p.scan_time_local {
            a.scan_time_local = Set(Some(t));
        }
        if let Some(t) = p.briefing_time_local {
            a.briefing_time_local = Set(Some(t));
        }
        if let Some(r) = p.api_rate_ceiling {
            a.api_rate_ceiling = Set(Some(r));
        }
        if let Some(ch) = p.slack_channel_id {
            a.slack_channel_id = Set(ch);
        }
        a.updated_at = Set(now());
        connection(a.update(self.db()).await.map_err(db_err)?)
    }

    async fn cas_status(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        from: ConnectionStatus,
        to: ConnectionStatus,
        reason: Option<&str>,
    ) -> RepoResult<bool> {
        use connections::Column as Col;
        let q = connections::Entity::update_many()
            .col_expr(Col::Status, enum_str(to).into())
            .col_expr(Col::UpdatedAt, now().into())
            .filter(Col::OrganisationId.eq(organisation_id))
            .filter(Col::Id.eq(id))
            .filter(Col::Status.eq(enum_str(from)));
        let q = match reason {
            Some(r) => q.col_expr(Col::StatusReason, r.into()),
            None => q,
        };
        let r = q.exec(self.db()).await.map_err(db_err)?;
        Ok(r.rows_affected == 1)
    }

    async fn load_creds(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<SealedCreds> {
        let row = creds::Entity::find_by_id(id)
            .inner_join(connections::Entity)
            .filter(connections::Column::OrganisationId.eq(organisation_id))
            .one(self.db())
            .await
            .map_err(db_err)?
            .ok_or(RepoError::NotFound)?;
        Ok(SealedCreds {
            ciphertext: row.ciphertext,
            nonce: row.nonce,
            kek_version: row.kek_version,
        })
    }

    async fn save_creds(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        sealed: SealedCreds,
    ) -> RepoResult<()> {
        if self
            .connection_row(organisation_id, id, false)
            .await?
            .is_none()
        {
            return Err(RepoError::NotFound);
        }
        let r = creds::Entity::update_many()
            .col_expr(creds::Column::Ciphertext, sealed.ciphertext.into())
            .col_expr(creds::Column::Nonce, sealed.nonce.into())
            .col_expr(creds::Column::KekVersion, sealed.kek_version.into())
            .col_expr(creds::Column::UpdatedAt, now().into())
            .filter(creds::Column::ConnectionId.eq(id))
            .exec(self.db())
            .await
            .map_err(db_err)?;
        if r.rows_affected == 0 {
            return Err(RepoError::NotFound);
        }
        Ok(())
    }

    async fn by_id_unscoped(&self, id: Uuid) -> RepoResult<Option<Connection>> {
        // tenancy: operator tasks name a connection by id alone; the row names its organisation.
        let row = connections::Entity::find_by_id(id)
            .one(self.db())
            .await
            .map_err(db_err)?;
        row.map(connection).transpose()
    }
}
