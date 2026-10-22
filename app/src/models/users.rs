use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
};
use uuid::Uuid;

use super::{_entities::users, now};

/// Trim, lowercase and sanity-check an address; `None` if it cannot be an email.
pub fn normalize_email(raw: &str) -> Option<String> {
    let e = raw.trim().to_lowercase();
    let (local, domain) = e.split_once('@')?;
    let ok = e.len() <= 254
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    ok.then_some(e)
}

pub async fn find_by_email(
    db: &DatabaseConnection,
    email: &str,
) -> Result<Option<users::Model>, DbErr> {
    users::Entity::find()
        .filter(users::Column::Email.eq(email))
        .one(db)
        .await
}

fn new_user(email: &str, name: Option<String>, github_id: Option<String>) -> users::ActiveModel {
    users::ActiveModel {
        id: Set(Uuid::new_v4()),
        email: Set(email.into()),
        name: Set(name),
        github_id: Set(github_id),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
}

/// `email` must already be normalised. Safe under concurrent first use.
pub async fn find_or_create_by_email(
    db: &DatabaseConnection,
    email: &str,
) -> Result<users::Model, DbErr> {
    if let Some(u) = find_by_email(db, email).await? {
        return Ok(u);
    }
    match new_user(email, None, None).insert(db).await {
        Ok(u) => Ok(u),
        Err(e) => find_by_email(db, email).await?.ok_or(e),
    }
}

/// Sign-in with GitHub: match on github id, else link to the verified email, else create.
pub async fn find_or_create_github(
    db: &DatabaseConnection,
    github_id: &str,
    email: &str,
    name: Option<String>,
) -> Result<users::Model, DbErr> {
    if let Some(u) = users::Entity::find()
        .filter(users::Column::GithubId.eq(github_id))
        .one(db)
        .await?
    {
        return Ok(u);
    }
    if let Some(u) = find_by_email(db, email).await? {
        let mut a: users::ActiveModel = u.clone().into();
        a.github_id = Set(Some(github_id.into()));
        a.name = Set(u.name.or(name));
        a.updated_at = Set(now());
        return a.update(db).await;
    }
    new_user(email, name, Some(github_id.into()))
        .insert(db)
        .await
}
