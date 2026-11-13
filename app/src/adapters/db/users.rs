use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::{RepoError, RepoResult},
    user::{Email, LiveCode, NewMagicLink, PersonName, SpentLink, User, UsersRepo},
};
use sea_orm::{
    prelude::DateTimeWithTimeZone,
    sea_query::{Expr, OnConflict},
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, ExprTrait, QueryFilter, Set,
};
use uuid::Uuid;

use super::{db_err, email, utc, Conn, Pg};
use crate::models::{
    _entities::{magic_links, passkeys, users},
    now,
};

fn user(m: users::Model) -> RepoResult<User> {
    let github_id = m
        .github_id
        .as_deref()
        .map(|g| {
            g.parse()
                .map_err(|_| RepoError::Storage("stored github_id is not valid".into()))
        })
        .transpose()?;
    Ok(User {
        id: m.id,
        email: email(&m.email)?,
        name: m.name,
        github_id,
        google_id: m.google_id,
        created_at: utc(m.created_at),
        terms_accepted_at: m.terms_accepted_at.map(utc),
    })
}

fn new_user(
    email: &Email,
    name: Option<String>,
    github_id: Option<i64>,
    google_id: Option<String>,
) -> users::ActiveModel {
    users::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email.as_str().into()),
        name: Set(name),
        github_id: Set(github_id.map(|g| g.to_string())),
        google_id: Set(google_id),
        created_at: Set(now()),
        updated_at: Set(now()),
        deleted_at: Set(None),
        terms_accepted_at: Set(None),
    }
}

impl<C: Conn> Pg<C> {
    async fn user_where(
        &self,
        filter: impl sea_orm::sea_query::IntoCondition + Send,
    ) -> RepoResult<Option<User>> {
        users::Entity::find()
            .filter(filter)
            .filter(users::Column::DeletedAt.is_null())
            .one(self.db())
            .await
            .map_err(db_err)?
            .map(user)
            .transpose()
    }
}

#[async_trait]
impl<C: Conn> UsersRepo for Pg<C> {
    async fn get(&self, id: Uuid) -> RepoResult<Option<User>> {
        self.user_where(users::Column::Id.eq(id)).await
    }

    async fn find_by_email(&self, email: &Email) -> RepoResult<Option<User>> {
        self.user_where(users::Column::Email.eq(email.as_str()))
            .await
    }

    async fn erase(&self, id: Uuid, at: DateTime<Utc>) -> RepoResult<()> {
        let db = self.db();
        passkeys::Entity::delete_many()
            .filter(passkeys::Column::UserId.eq(id))
            .exec(db)
            .await
            .map_err(db_err)?;
        magic_links::Entity::delete_many()
            .filter(magic_links::Column::UserId.eq(id))
            .exec(db)
            .await
            .map_err(db_err)?;
        users::Entity::update_many()
            .col_expr(
                users::Column::Email,
                Expr::value(format!("deleted+{id}@deleted.invalid")),
            )
            .col_expr(users::Column::Name, Expr::value(Option::<String>::None))
            .col_expr(users::Column::GithubId, Expr::value(Option::<String>::None))
            .col_expr(users::Column::GoogleId, Expr::value(Option::<String>::None))
            .col_expr(users::Column::DeletedAt, Expr::value(at.fixed_offset()))
            .col_expr(users::Column::UpdatedAt, Expr::value(now()))
            .filter(users::Column::Id.eq(id))
            .exec(db)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn find_or_create_by_email(&self, email: &Email) -> RepoResult<User> {
        if let Some(u) = self.find_by_email(email).await? {
            return Ok(u);
        }
        // A concurrent first use inserts nothing here (any conflict: the email index is on
        // `lower(email)`) and is found below.
        let inserted = users::Entity::insert(new_user(email, None, None, None))
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .exec_without_returning(self.db())
            .await;
        match inserted {
            Ok(_) | Err(DbErr::RecordNotInserted) => {}
            Err(e) => return Err(db_err(e)),
        }
        self.find_by_email(email).await?.ok_or(RepoError::NotFound)
    }

    async fn set_name_if_missing(&self, id: Uuid, name: &PersonName) -> RepoResult<()> {
        users::Entity::update_many()
            .col_expr(users::Column::Name, Expr::value(name.as_str()))
            .col_expr(users::Column::UpdatedAt, Expr::value(now()))
            .filter(users::Column::Id.eq(id))
            .filter(users::Column::Name.is_null())
            .exec(self.db())
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn accept_terms(&self, id: Uuid, at: DateTime<Utc>) -> RepoResult<()> {
        users::Entity::update_many()
            .col_expr(
                users::Column::TermsAcceptedAt,
                Expr::value(at.fixed_offset()),
            )
            .col_expr(users::Column::UpdatedAt, Expr::value(now()))
            .filter(users::Column::Id.eq(id))
            .filter(users::Column::TermsAcceptedAt.is_null())
            .exec(self.db())
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn find_or_create_github(
        &self,
        github_id: i64,
        email: &Email,
        name: Option<String>,
        may_create: bool,
    ) -> RepoResult<User> {
        let gh = github_id.to_string();
        if let Some(u) = self.user_where(users::Column::GithubId.eq(&gh)).await? {
            return Ok(u);
        }
        let db = self.db();
        if let Some(u) = users::Entity::find()
            .filter(users::Column::Email.eq(email.as_str()))
            .one(db)
            .await
            .map_err(db_err)?
        {
            // Link by email only once, like Google: never replace another GitHub account's link.
            if u.github_id.is_some() {
                return Err(RepoError::Conflict("account_exists"));
            }
            let mut a: users::ActiveModel = u.clone().into();
            a.github_id = Set(Some(gh));
            a.name = Set(u.name.or(name));
            a.updated_at = Set(now());
            return user(a.update(db).await.map_err(db_err)?);
        }
        if !may_create {
            return Err(RepoError::Conflict("signup_closed"));
        }
        user(
            new_user(email, name, Some(github_id), None)
                .insert(db)
                .await
                .map_err(db_err)?,
        )
    }

    async fn find_or_create_google(
        &self,
        google_id: &str,
        email: &Email,
        name: Option<String>,
        authoritative: bool,
        may_create: bool,
    ) -> RepoResult<User> {
        if let Some(u) = self
            .user_where(users::Column::GoogleId.eq(google_id))
            .await?
        {
            return Ok(u);
        }
        let db = self.db();
        if let Some(u) = users::Entity::find()
            .filter(users::Column::Email.eq(email.as_str()))
            .one(db)
            .await
            .map_err(db_err)?
        {
            if !authoritative || u.google_id.is_some() {
                return Err(RepoError::Conflict("account_exists"));
            }
            let mut a: users::ActiveModel = u.clone().into();
            a.google_id = Set(Some(google_id.to_owned()));
            a.name = Set(u.name.or(name));
            a.updated_at = Set(now());
            return user(a.update(db).await.map_err(db_err)?);
        }
        if !authoritative {
            return Err(RepoError::Conflict("google_email_unmanaged"));
        }
        if !may_create {
            return Err(RepoError::Conflict("signup_closed"));
        }
        user(
            new_user(email, name, None, Some(google_id.to_owned()))
                .insert(db)
                .await
                .map_err(db_err)?,
        )
    }

    async fn issue_magic_link(&self, link: NewMagicLink<'_>) -> RepoResult<()> {
        magic_links::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(Some(link.user_id)),
            email: Set(Some(link.email.as_str().into())),
            token_hash: Set(link.token_hash.into()),
            return_to: Set(link.return_to.map(Into::into)),
            expires_at: Set(link.expires_at.into()),
            used_at: Set(None),
            code_hash: Set(Some(link.code_hash.into())),
            code_attempts: Set(0),
            name: Set(link.name.map(|n| n.as_str().into())),
            created_at: Set(now()),
            updated_at: Set(now()),
        }
        .insert(self.db())
        .await
        .map(|_| ())
        .map_err(db_err)
    }

    async fn consume_magic_link(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<SpentLink>> {
        let at = DateTimeWithTimeZone::from(now);
        let res = magic_links::Entity::update_many()
            .col_expr(magic_links::Column::UsedAt, at.into())
            .filter(magic_links::Column::TokenHash.eq(token_hash))
            .filter(magic_links::Column::UsedAt.is_null())
            .filter(magic_links::Column::ExpiresAt.gt(at))
            .exec(self.db())
            .await
            .map_err(db_err)?;
        if res.rows_affected != 1 {
            return Ok(None);
        }
        Ok(magic_links::Entity::find()
            .filter(magic_links::Column::TokenHash.eq(token_hash))
            .one(self.db())
            .await
            .map_err(db_err)?
            .and_then(|l| {
                Some(SpentLink {
                    user_id: l.user_id?,
                    return_to: l.return_to,
                    name: l.name,
                })
            }))
    }

    async fn live_codes(&self, email: &Email, now: DateTime<Utc>) -> RepoResult<Vec<LiveCode>> {
        let rows = magic_links::Entity::find()
            .filter(magic_links::Column::Email.eq(email.as_str()))
            .filter(magic_links::Column::UsedAt.is_null())
            .filter(magic_links::Column::ExpiresAt.gt(DateTimeWithTimeZone::from(now)))
            .filter(magic_links::Column::CodeHash.is_not_null())
            .all(self.db())
            .await
            .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .filter_map(|l| {
                Some(LiveCode {
                    id: l.id,
                    user_id: l.user_id?,
                    token_hash: l.token_hash,
                    code_hash: l.code_hash?,
                    return_to: l.return_to,
                    name: l.name,
                })
            })
            .collect())
    }

    async fn spend_code(&self, id: Uuid, now: DateTime<Utc>) -> RepoResult<bool> {
        let at = DateTimeWithTimeZone::from(now);
        let res = magic_links::Entity::update_many()
            .col_expr(magic_links::Column::UsedAt, at.into())
            .filter(magic_links::Column::Id.eq(id))
            .filter(magic_links::Column::UsedAt.is_null())
            .filter(magic_links::Column::ExpiresAt.gt(at))
            .exec(self.db())
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected == 1)
    }

    async fn count_wrong_code(&self, ids: &[Uuid]) -> RepoResult<()> {
        let attempts = Expr::col(magic_links::Column::CodeAttempts).add(1);
        magic_links::Entity::update_many()
            .col_expr(magic_links::Column::CodeAttempts, attempts)
            .col_expr(
                magic_links::Column::CodeHash,
                Expr::cust("CASE WHEN code_attempts + 1 >= 5 THEN NULL ELSE code_hash END"),
            )
            .filter(magic_links::Column::Id.is_in(ids.iter().copied()))
            .exec(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }
}
