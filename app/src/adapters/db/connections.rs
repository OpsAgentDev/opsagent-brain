use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    connection::{
        Connection, ConnectionPatch, ConnectionStatus, ConnectionsRepo, NewConnection, SealedCreds,
        Verification, Verified,
    },
    repo::{RepoError, RepoResult},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    QuerySelect, Set, SqlErr,
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

/// The only unique index a connection update can hit is the claimed-account one.
fn claim_err(e: DbErr) -> RepoError {
    match e.sql_err() {
        Some(SqlErr::UniqueConstraintViolation(_)) => RepoError::Conflict("account"),
        _ => db_err(e),
    }
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
        verify_denied_streak: m.verify_denied_streak,
        verify_denied_first_at: m.verify_denied_first_at.map(utc),
        urgent_alerts: m.urgent_alerts,
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

    /// Applies `a` to the organisation's connection `id`; `NotFound` when there is none.
    async fn write(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        mut a: connections::ActiveModel,
    ) -> RepoResult<()> {
        a.updated_at = Set(now());
        let r = connections::Entity::update_many()
            .set(a)
            .filter(connections::Column::OrganisationId.eq(organisation_id))
            .filter(connections::Column::Id.eq(id))
            .exec(self.db())
            .await
            .map_err(claim_err)?;
        if r.rows_affected == 0 {
            return Err(RepoError::NotFound);
        }
        Ok(())
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
            urgent_alerts: Set(true),
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
        if let Some(u) = p.urgent_alerts {
            a.urgent_alerts = Set(u);
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
        let r = q.exec(self.db()).await.map_err(claim_err)?;
        Ok(r.rows_affected == 1)
    }

    async fn record_verification(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        run_id: Uuid,
        v: &Verification,
    ) -> RepoResult<()> {
        if self
            .connection_row(organisation_id, id, false)
            .await?
            .is_none()
        {
            return Err(RepoError::NotFound);
        }
        verifications::ActiveModel {
            id: Set(Uuid::new_v4()),
            connection_id: Set(id),
            run_id: Set(Some(run_id)),
            assume_with_ok: Set(v.assume_with_ok),
            assume_without_denied: Set(v.assume_without_denied),
            policy_matches: Set(v.policy_matches),
            extra_grants: Set(v.extra_grants.clone()),
            missing_grants: Set(v.missing_grants.clone()),
            outcome: Set(v.outcome.clone()),
            created_at: Set(v.at.into()),
            updated_at: Set(v.at.into()),
        }
        .insert(self.db())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn record_verified(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        v: Verified,
    ) -> RepoResult<()> {
        let mut a = <connections::ActiveModel as ActiveModelTrait>::default();
        a.status_reason = Set(v.reason);
        a.verify_denied_streak = Set(0);
        a.verify_denied_first_at = Set(None);
        if let Some(account) = v.account {
            a.external_account_id = Set(Some(account));
        }
        if let Some(at) = v.first_connected_at {
            a.first_connected_at = Set(Some(at.into()));
            a.billable_from = Set(Some(at.into()));
        }
        self.write(organisation_id, id, a).await
    }

    async fn record_denial(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        streak: i32,
        first_at: DateTime<Utc>,
    ) -> RepoResult<()> {
        let mut a = <connections::ActiveModel as ActiveModelTrait>::default();
        a.verify_denied_streak = Set(streak);
        a.verify_denied_first_at = Set(Some(first_at.into()));
        self.write(organisation_id, id, a).await
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
