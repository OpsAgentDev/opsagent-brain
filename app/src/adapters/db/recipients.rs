use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use opsagent_core::repo::{PageOf, PageRequest, RepoError, RepoResult};
use opsagent_deliver::{
    repo::{
        NewRecipient, RecipientRow, RecipientsRepo, Suppression, ACTIVE, PENDING, SUPPRESSION_DAYS,
    },
    route::Recipient,
};
use sea_orm::{
    prelude::DateTimeWithTimeZone, sea_query::OnConflict, ColumnTrait, Condition, ConnectionTrait,
    EntityTrait, QueryFilter, QueryResult, Set,
};
use uuid::Uuid;

use super::{db_err, ledger_storage::stmt, page, utc, Conn, Pg};
use crate::models::{
    _entities::{
        email_suppressions::{self, Column as S},
        recipients::{self, Column as Col},
    },
    now,
};

fn row(m: recipients::Model) -> RecipientRow {
    RecipientRow {
        id: m.id,
        organisation_id: m.organisation_id,
        connection_id: m.connection_id,
        email: m.email,
        member_id: m.member_id,
        status: m.status,
        unsubscribed_at: m.unsubscribed_at.map(utc),
        created_at: utc(m.created_at),
    }
}

fn recipient(r: &QueryResult, member: bool) -> RepoResult<Recipient> {
    Ok(Recipient {
        id: r.try_get("", "id").map_err(db_err)?,
        email: r
            .try_get::<String>("", "email")
            .map_err(db_err)?
            .to_lowercase(),
        member: member || r.try_get("", "member").map_err(db_err)?,
    })
}

#[async_trait]
impl<C: Conn> RecipientsRepo for Pg<C> {
    async fn list(
        &self,
        organisation_id: Uuid,
        req: PageRequest,
    ) -> RepoResult<PageOf<RecipientRow>> {
        let q = recipients::Entity::find().filter(Col::OrganisationId.eq(organisation_id));
        let got = page(
            self.db(),
            q,
            (Col::CreatedAt, Col::Id),
            |m| (m.created_at, m.id),
            req,
        )
        .await?;
        Ok(PageOf {
            items: got.items.into_iter().map(row).collect(),
            next: got.next,
        })
    }

    async fn insert(&self, organisation_id: Uuid, new: NewRecipient) -> RepoResult<RecipientRow> {
        let id = Uuid::new_v4();
        let (hash, expires) = new.confirm.unzip();
        let m = recipients::ActiveModel {
            id: Set(id),
            organisation_id: Set(organisation_id),
            connection_id: Set(new.connection_id),
            email: Set(new.email),
            member_id: Set(new.member_id),
            status: Set(if hash.is_some() { PENDING } else { ACTIVE }.into()),
            confirm_token_hash: Set(hash),
            confirm_expires_at: Set(expires.map(Into::into)),
            unsubscribed_at: Set(None),
            created_at: Set(now()),
            updated_at: Set(now()),
        };
        // DO NOTHING keeps an enclosing transaction usable after a duplicate.
        let done = recipients::Entity::insert(m)
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .exec_without_returning(self.db())
            .await
            .map_err(db_err)?;
        if done == 0 {
            return Err(RepoError::Conflict("recipient"));
        }
        let m = recipients::Entity::find_by_id(id)
            .filter(Col::OrganisationId.eq(organisation_id))
            .one(self.db())
            .await
            .map_err(db_err)?
            .ok_or_else(|| RepoError::Storage("recipient missing after insert".into()))?;
        Ok(row(m))
    }

    async fn delete(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<bool> {
        let gone = recipients::Entity::delete_many()
            .filter(Col::OrganisationId.eq(organisation_id))
            .filter(Col::Id.eq(id))
            .exec(self.db())
            .await
            .map_err(db_err)?;
        Ok(gone.rows_affected == 1)
    }

    async fn confirm(
        &self,
        token_hash: &str,
        at: DateTime<Utc>,
    ) -> RepoResult<Option<RecipientRow>> {
        let none: Option<DateTimeWithTimeZone> = None;
        // tenancy: the token is the lookup key; the row names its organisation.
        let done = recipients::Entity::update_many()
            .col_expr(Col::Status, ACTIVE.into())
            .col_expr(Col::ConfirmTokenHash, Option::<String>::None.into())
            .col_expr(Col::ConfirmExpiresAt, none.into())
            .col_expr(Col::UpdatedAt, now().into())
            .filter(Col::ConfirmTokenHash.eq(token_hash))
            .filter(Col::Status.eq(PENDING))
            .filter(Col::ConfirmExpiresAt.gt(at))
            .exec_with_returning(self.db())
            .await
            .map_err(db_err)?;
        Ok(done.into_iter().next().map(row))
    }

    async fn by_id_unscoped(&self, id: Uuid) -> RepoResult<Option<RecipientRow>> {
        // tenancy: a verified unsubscribe token names the row; the row names its organisation.
        let m = recipients::Entity::find_by_id(id)
            .one(self.db())
            .await
            .map_err(db_err)?;
        Ok(m.map(row))
    }

    async fn unsubscribe(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        at: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let done = recipients::Entity::update_many()
            .col_expr(
                Col::UnsubscribedAt,
                Some(DateTimeWithTimeZone::from(at)).into(),
            )
            .col_expr(Col::UpdatedAt, now().into())
            .filter(Col::OrganisationId.eq(organisation_id))
            .filter(Col::Id.eq(id))
            .filter(Col::UnsubscribedAt.is_null())
            .exec(self.db())
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected == 1)
    }

    async fn for_connection(
        &self,
        organisation_id: Uuid,
        connection_id: Option<Uuid>,
    ) -> RepoResult<Vec<Recipient>> {
        let rows = self
            .db()
            .query_all_raw(stmt(
                "SELECT id, email, member_id IS NOT NULL AS member FROM recipients \
                 WHERE organisation_id = $1 AND connection_id IS NOT DISTINCT FROM $2 \
                 AND status = 'active' AND unsubscribed_at IS NULL ORDER BY created_at",
                vec![organisation_id.into(), connection_id.into()],
            ))
            .await
            .map_err(db_err)?;
        rows.iter().map(|r| recipient(r, false)).collect()
    }

    async fn owners(&self, organisation_id: Uuid) -> RepoResult<Vec<Recipient>> {
        let rows = self
            .db()
            .query_all_raw(stmt(
                "SELECT u.id, u.email FROM members m JOIN users u ON u.id = m.user_id \
                 WHERE m.organisation_id = $1 AND m.role = 'owner' ORDER BY m.created_at",
                vec![organisation_id.into()],
            ))
            .await
            .map_err(db_err)?;
        rows.iter().map(|r| recipient(r, true)).collect()
    }

    async fn suppress(
        &self,
        organisation_id: Option<Uuid>,
        email_hash: &str,
        kind: Suppression,
    ) -> RepoResult<()> {
        let (sql, expires) = match kind {
            Suppression::Unsubscribed => (
                "INSERT INTO email_suppressions (id, organisation_id, email_hash, reason, expires_at) \
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (organisation_id, email_hash) \
                 DO UPDATE SET reason = EXCLUDED.reason, expires_at = NULL",
                None,
            ),
            Suppression::Ignored | Suppression::ConfirmBlocked => (
                "INSERT INTO email_suppressions (id, organisation_id, email_hash, reason, expires_at) \
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (organisation_id, email_hash) \
                 DO UPDATE SET expires_at = EXCLUDED.expires_at \
                 WHERE email_suppressions.reason = EXCLUDED.reason",
                Some((Utc::now() + Duration::days(SUPPRESSION_DAYS)).fixed_offset()),
            ),
        };
        let values = vec![
            Uuid::new_v4().into(),
            organisation_id.into(),
            email_hash.into(),
            kind.as_str().into(),
            expires.into(),
        ];
        self.db()
            .execute_raw(stmt(sql, values))
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn suppressed(
        &self,
        organisation_id: Uuid,
        email_hash: &str,
    ) -> RepoResult<Vec<Suppression>> {
        let live = Condition::any()
            .add(S::ExpiresAt.is_null())
            .add(S::ExpiresAt.gt(now()));
        let rows = email_suppressions::Entity::find()
            .filter(S::EmailHash.eq(email_hash))
            .filter(
                Condition::any()
                    .add(S::OrganisationId.is_null())
                    .add(S::OrganisationId.eq(organisation_id)),
            )
            .filter(live)
            .all(self.db())
            .await
            .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                Suppression::parse(&r.reason).ok_or_else(|| {
                    RepoError::Storage(format!("unknown suppression {:?}", r.reason))
                })
            })
            .collect()
    }

    async fn ids_by_email(
        &self,
        organisation_id: Uuid,
        emails: &[String],
    ) -> RepoResult<HashMap<String, Uuid>> {
        let mut map = HashMap::new();
        if emails.is_empty() {
            return Ok(map);
        }
        let rows = self
            .db()
            .query_all_raw(stmt(
                "SELECT DISTINCT ON (lower(email)) lower(email) AS email, id FROM recipients \
                 WHERE organisation_id = $1 AND lower(email) = ANY($2) \
                 ORDER BY lower(email), created_at, id",
                vec![organisation_id.into(), emails.to_vec().into()],
            ))
            .await
            .map_err(db_err)?;
        for r in rows {
            let email: String = r.try_get("", "email").map_err(db_err)?;
            map.insert(email, r.try_get("", "id").map_err(db_err)?);
        }
        Ok(map)
    }
}
