use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::{RepoError, RepoResult},
    user::{Email, User, UsersRepo},
};
use sea_orm::{
    prelude::DateTimeWithTimeZone, sea_query::OnConflict, ActiveModelTrait, ColumnTrait, DbErr,
    EntityTrait, QueryFilter, Set,
};
use uuid::Uuid;

use super::{db_err, email, utc, Conn, Pg};
use crate::models::{
    _entities::{magic_links, users},
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
        created_at: utc(m.created_at),
    })
}

fn new_user(email: &Email, name: Option<String>, github_id: Option<i64>) -> users::ActiveModel {
    users::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email.as_str().into()),
        name: Set(name),
        github_id: Set(github_id.map(|g| g.to_string())),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
}

impl<C: Conn> Pg<C> {
    async fn user_where(
        &self,
        filter: impl sea_orm::sea_query::IntoCondition + Send,
    ) -> RepoResult<Option<User>> {
        users::Entity::find()
            .filter(filter)
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

    async fn find_or_create_by_email(&self, email: &Email) -> RepoResult<User> {
        if let Some(u) = self.find_by_email(email).await? {
            return Ok(u);
        }
        // A concurrent first use inserts nothing here (any conflict: the email index is on
        // `lower(email)`) and is found below.
        let inserted = users::Entity::insert(new_user(email, None, None))
            .on_conflict(OnConflict::new().do_nothing().to_owned())
            .exec_without_returning(self.db())
            .await;
        match inserted {
            Ok(_) | Err(DbErr::RecordNotInserted) => {}
            Err(e) => return Err(db_err(e)),
        }
        self.find_by_email(email).await?.ok_or(RepoError::NotFound)
    }

    async fn find_or_create_github(
        &self,
        github_id: i64,
        email: &Email,
        name: Option<String>,
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
            let mut a: users::ActiveModel = u.clone().into();
            a.github_id = Set(Some(gh));
            a.name = Set(u.name.or(name));
            a.updated_at = Set(now());
            return user(a.update(db).await.map_err(db_err)?);
        }
        user(
            new_user(email, name, Some(github_id))
                .insert(db)
                .await
                .map_err(db_err)?,
        )
    }

    async fn issue_magic_link(
        &self,
        user_id: Uuid,
        email: &Email,
        token_hash: &str,
        return_to: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> RepoResult<()> {
        magic_links::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(Some(user_id)),
            email: Set(Some(email.as_str().into())),
            token_hash: Set(token_hash.into()),
            return_to: Set(return_to.map(Into::into)),
            expires_at: Set(expires_at.into()),
            used_at: Set(None),
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
    ) -> RepoResult<Option<(Uuid, Option<String>)>> {
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
            .and_then(|l| Some((l.user_id?, l.return_to))))
    }
}
