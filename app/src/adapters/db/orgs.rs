use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    billing::BillingStatus,
    org::{
        Invite, Member, NewOrganisation, Organisation, OrganisationPatch, OrganisationsRepo, Role,
    },
    repo::{RepoError, RepoResult},
    user::Email,
};
use sea_orm::{
    prelude::DateTimeWithTimeZone, ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait,
    QueryFilter, QuerySelect, Set, TryInsertResult,
};
use uuid::Uuid;

use super::{db_err, email, role, utc, Conn, Pg};
use crate::models::{
    _entities::{invites, members, organisations, users},
    now,
};

fn org(m: organisations::Model) -> Organisation {
    Organisation {
        id: m.id,
        slug: m.slug,
        name: m.name,
        timezone: m.timezone,
        kek_version: m.kek_version,
        wrapped_dek: m.wrapped_dek,
        created_at: utc(m.created_at),
        deleted_at: m.deleted_at.map(utc),
    }
}

fn member((m, u): (members::Model, Option<users::Model>)) -> RepoResult<Member> {
    let u = u.ok_or_else(|| RepoError::Storage("member without user".into()))?;
    Ok(Member {
        id: m.id,
        organisation_id: m.organisation_id,
        user_id: m.user_id,
        email: email(&u.email)?,
        name: u.name,
        role: role(&m.role)?,
        created_at: utc(m.created_at),
    })
}

fn invite(m: invites::Model) -> RepoResult<Invite> {
    Ok(Invite {
        id: m.id,
        organisation_id: m.organisation_id,
        email: email(&m.email)?,
        role: role(&m.role)?,
        expires_at: utc(m.expires_at),
        accepted_at: (m.status == "accepted").then(|| utc(m.updated_at)),
    })
}

impl<C: Conn> Pg<C> {
    async fn org_row(&self, organisation_id: Uuid) -> RepoResult<Option<organisations::Model>> {
        organisations::Entity::find_by_id(organisation_id)
            .one(self.db())
            .await
            .map_err(db_err)
    }

    async fn member_in(&self, organisation_id: Uuid, user_id: Uuid) -> RepoResult<Option<Member>> {
        members::Entity::find()
            .filter(members::Column::OrganisationId.eq(organisation_id))
            .filter(members::Column::UserId.eq(user_id))
            .find_also_related(users::Entity)
            .one(self.db())
            .await
            .map_err(db_err)?
            .map(member)
            .transpose()
    }
}

#[async_trait]
impl<C: Conn> OrganisationsRepo for Pg<C> {
    async fn insert(&self, new: NewOrganisation) -> RepoResult<Organisation> {
        let row = organisations::ActiveModel {
            id: Set(new.id),
            name: Set(new.name),
            slug: Set(new.slug),
            timezone: Set(new.timezone),
            plan: Set(None),
            stripe_customer_id: Set(None),
            stripe_subscription_id: Set(None),
            billing_tier: Set(None),
            billing_quantity: Set(None),
            trial_ends_at: Set(None),
            current_period_start: Set(None),
            current_period_end: Set(None),
            past_due_since: Set(None),
            billing_event_at: Set(None),
            payment_event_at: Set(None),
            kek_version: Set(Some(new.kek_version)),
            wrapped_dek: Set(Some(new.wrapped_dek)),
            deleted_at: Set(None),
            billing_status: Set(BillingStatus::None.as_str().into()),
            created_at: Set(now()),
            updated_at: Set(now()),
        };
        let id = new.id;
        // DO NOTHING, not an error: a taken slug must not abort the caller's transaction.
        match organisations::Entity::insert(row)
            .on_conflict_do_nothing_on([organisations::Column::Slug])
            .exec_without_returning(self.db())
            .await
            .map_err(db_err)?
        {
            TryInsertResult::Inserted(1) => {}
            _ => return Err(RepoError::Conflict("slug")),
        }
        let gone = || RepoError::Storage("organisation missing after insert".into());
        self.get(id).await?.ok_or_else(gone)
    }

    async fn get(&self, organisation_id: Uuid) -> RepoResult<Option<Organisation>> {
        Ok(self.org_row(organisation_id).await?.map(org))
    }

    async fn lock(&self, organisation_id: Uuid) -> RepoResult<()> {
        organisations::Entity::find_by_id(organisation_id)
            .lock_exclusive()
            .one(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn membership(
        &self,
        slug: &str,
        user_id: Uuid,
    ) -> RepoResult<Option<(Organisation, Member)>> {
        let Some(o) = organisations::Entity::find()
            .filter(organisations::Column::Slug.eq(slug))
            .filter(organisations::Column::DeletedAt.is_null())
            .one(self.db())
            .await
            .map_err(db_err)?
        else {
            return Ok(None);
        };
        Ok(self.member_in(o.id, user_id).await?.map(|m| (org(o), m)))
    }

    async fn list_for_user(&self, user_id: Uuid) -> RepoResult<Vec<(Organisation, Role)>> {
        // tenancy: the caller's own memberships, across organisations.
        let rows = members::Entity::find()
            .filter(members::Column::UserId.eq(user_id))
            .find_also_related(organisations::Entity)
            .all(self.db())
            .await
            .map_err(db_err)?;
        rows.into_iter()
            .filter_map(|(m, o)| o.filter(|o| o.deleted_at.is_none()).map(|o| (m, o)))
            .map(|(m, o)| Ok((org(o), role(&m.role)?)))
            .collect()
    }

    async fn update(
        &self,
        organisation_id: Uuid,
        patch: OrganisationPatch,
    ) -> RepoResult<Organisation> {
        let row = self
            .org_row(organisation_id)
            .await?
            .ok_or(RepoError::NotFound)?;
        let mut a: organisations::ActiveModel = row.into();
        if let Some(n) = patch.name {
            a.name = Set(n);
        }
        if let Some(t) = patch.timezone {
            a.timezone = Set(t);
        }
        a.updated_at = Set(now());
        Ok(org(a.update(self.db()).await.map_err(db_err)?))
    }

    async fn soft_delete(&self, organisation_id: Uuid, at: DateTime<Utc>) -> RepoResult<()> {
        let res = organisations::Entity::update_many()
            .col_expr(
                organisations::Column::DeletedAt,
                DateTimeWithTimeZone::from(at).into(),
            )
            .col_expr(organisations::Column::UpdatedAt, now().into())
            .filter(organisations::Column::Id.eq(organisation_id))
            .exec(self.db())
            .await
            .map_err(db_err)?;
        if res.rows_affected == 0 {
            return Err(RepoError::NotFound);
        }
        Ok(())
    }

    async fn is_deleted(&self, organisation_id: Uuid) -> RepoResult<bool> {
        let row = self.org_row(organisation_id).await?;
        Ok(row.is_none_or(|o| o.deleted_at.is_some()))
    }

    async fn add_member(
        &self,
        organisation_id: Uuid,
        user_id: Uuid,
        role: Role,
    ) -> RepoResult<Member> {
        let row = members::ActiveModel {
            id: Set(Uuid::new_v4()),
            organisation_id: Set(organisation_id),
            user_id: Set(user_id),
            role: Set(role.as_str().into()),
            created_at: Set(now()),
            updated_at: Set(now()),
        };
        // DO NOTHING, not an error: a double accept must not abort the caller's transaction.
        let cols = [members::Column::OrganisationId, members::Column::UserId];
        match members::Entity::insert(row)
            .on_conflict_do_nothing_on(cols)
            .exec_without_returning(self.db())
            .await
            .map_err(db_err)?
        {
            TryInsertResult::Inserted(1) => {}
            _ => return Err(RepoError::Conflict("member")),
        }
        let gone = || RepoError::Storage("member missing after insert".into());
        self.member_in(organisation_id, user_id)
            .await?
            .ok_or_else(gone)
    }

    async fn members(&self, organisation_id: Uuid) -> RepoResult<Vec<Member>> {
        members::Entity::find()
            .filter(members::Column::OrganisationId.eq(organisation_id))
            .find_also_related(users::Entity)
            .all(self.db())
            .await
            .map_err(db_err)?
            .into_iter()
            .map(member)
            .collect()
    }

    async fn remove_member(&self, organisation_id: Uuid, member_id: Uuid) -> RepoResult<bool> {
        let db = self.db();
        let Some((_, u)) = members::Entity::find_by_id(member_id)
            .filter(members::Column::OrganisationId.eq(organisation_id))
            .find_also_related(users::Entity)
            .one(db)
            .await
            .map_err(db_err)?
        else {
            return Ok(false);
        };
        members::Entity::delete_many()
            .filter(members::Column::OrganisationId.eq(organisation_id))
            .filter(members::Column::Id.eq(member_id))
            .exec(db)
            .await
            .map_err(db_err)?;
        if let Some(u) = u {
            invites::Entity::update_many()
                .col_expr(invites::Column::Status, "cancelled".into())
                .col_expr(invites::Column::UpdatedAt, now().into())
                .filter(invites::Column::OrganisationId.eq(organisation_id))
                .filter(invites::Column::Email.eq(u.email.to_lowercase()))
                .filter(invites::Column::Status.eq("pending"))
                .exec(db)
                .await
                .map_err(db_err)?;
        }
        Ok(true)
    }

    async fn owner_count(&self, organisation_id: Uuid) -> RepoResult<u64> {
        members::Entity::find()
            .filter(members::Column::OrganisationId.eq(organisation_id))
            .filter(members::Column::Role.eq(Role::Owner.as_str()))
            .count(self.db())
            .await
            .map_err(db_err)
    }

    async fn insert_invite(
        &self,
        organisation_id: Uuid,
        email: &Email,
        role: Role,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> RepoResult<Invite> {
        let row = invites::ActiveModel {
            id: Set(Uuid::new_v4()),
            organisation_id: Set(organisation_id),
            email: Set(email.as_str().into()),
            role: Set(role.as_str().into()),
            token_hash: Set(token_hash.into()),
            expires_at: Set(expires_at.into()),
            status: Set("pending".into()),
            created_at: Set(now()),
            updated_at: Set(now()),
        }
        .insert(self.db())
        .await
        .map_err(db_err)?;
        invite(row)
    }

    async fn pending_invites(&self, organisation_id: Uuid, now: DateTime<Utc>) -> RepoResult<u64> {
        invites::Entity::find()
            .filter(invites::Column::OrganisationId.eq(organisation_id))
            .filter(invites::Column::Status.eq("pending"))
            .filter(invites::Column::ExpiresAt.gt(DateTimeWithTimeZone::from(now)))
            .count(self.db())
            .await
            .map_err(db_err)
    }

    async fn take_invite(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<Invite>> {
        let db = self.db();
        let at = DateTimeWithTimeZone::from(now);
        // tenancy: the token is the lookup key; the invite names its organisation.
        let Some(row) = invites::Entity::find()
            .filter(invites::Column::TokenHash.eq(token_hash))
            .filter(invites::Column::Status.eq("pending"))
            .filter(invites::Column::ExpiresAt.gt(at))
            .one(db)
            .await
            .map_err(db_err)?
        else {
            return Ok(None);
        };
        // Compare-and-set so a concurrent double take consumes the invite once.
        let claimed = invites::Entity::update_many()
            .col_expr(invites::Column::Status, "accepted".into())
            .col_expr(invites::Column::UpdatedAt, at.into())
            .filter(invites::Column::OrganisationId.eq(row.organisation_id))
            .filter(invites::Column::Id.eq(row.id))
            .filter(invites::Column::Status.eq("pending"))
            .exec(db)
            .await
            .map_err(db_err)?;
        if claimed.rows_affected != 1 {
            return Ok(None);
        }
        let mut taken = invite(row)?;
        taken.accepted_at = Some(now);
        Ok(Some(taken))
    }
}
