use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    passkey::{PasskeysRepo, StoredPasskey},
    repo::{RepoError, RepoResult},
};
use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    SqlErr,
};
use uuid::Uuid;

use super::{db_err, utc, Conn, Pg};
use crate::models::_entities::passkeys;

fn passkey(m: passkeys::Model) -> StoredPasskey {
    StoredPasskey {
        id: m.id,
        user_id: m.user_id,
        credential_id: m.credential_id,
        credential: m.credential,
        name: m.name,
        created_at: utc(m.created_at),
        last_used_at: m.last_used_at.map(utc),
    }
}

#[async_trait]
impl<C: Conn> PasskeysRepo for Pg<C> {
    async fn add(&self, p: &StoredPasskey) -> RepoResult<()> {
        passkeys::ActiveModel {
            id: Set(p.id),
            user_id: Set(p.user_id),
            credential_id: Set(p.credential_id.clone()),
            credential: Set(p.credential.clone()),
            name: Set(p.name.clone()),
            created_at: Set(p.created_at.into()),
            last_used_at: Set(p.last_used_at.map(Into::into)),
        }
        .insert(self.db())
        .await
        .map_err(|e| match e.sql_err() {
            Some(SqlErr::UniqueConstraintViolation(_)) => RepoError::Conflict("passkey_exists"),
            _ => db_err(e),
        })?;
        Ok(())
    }

    async fn for_user(&self, user_id: Uuid) -> RepoResult<Vec<StoredPasskey>> {
        let rows = passkeys::Entity::find()
            .filter(passkeys::Column::UserId.eq(user_id))
            .order_by_asc(passkeys::Column::CreatedAt)
            .order_by_asc(passkeys::Column::Id)
            .all(self.db())
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(passkey).collect())
    }

    async fn by_credential_id(&self, cred_id: &[u8]) -> RepoResult<Option<StoredPasskey>> {
        let row = passkeys::Entity::find()
            .filter(passkeys::Column::CredentialId.eq(cred_id.to_vec()))
            .one(self.db())
            .await
            .map_err(db_err)?;
        Ok(row.map(passkey))
    }

    async fn update_after_use(
        &self,
        id: Uuid,
        credential: &serde_json::Value,
        at: DateTime<Utc>,
    ) -> RepoResult<()> {
        let done = passkeys::Entity::update_many()
            .col_expr(
                passkeys::Column::Credential,
                Expr::value(credential.clone()),
            )
            .col_expr(passkeys::Column::LastUsedAt, Expr::value(at.fixed_offset()))
            .filter(passkeys::Column::Id.eq(id))
            .exec(self.db())
            .await
            .map_err(db_err)?;
        if done.rows_affected == 0 {
            return Err(RepoError::NotFound);
        }
        Ok(())
    }

    async fn remove(&self, user_id: Uuid, id: Uuid) -> RepoResult<bool> {
        let done = passkeys::Entity::delete_many()
            .filter(passkeys::Column::Id.eq(id))
            .filter(passkeys::Column::UserId.eq(user_id))
            .exec(self.db())
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected > 0)
    }
}
