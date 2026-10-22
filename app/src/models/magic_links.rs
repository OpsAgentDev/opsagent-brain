use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rand::RngCore;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{_entities::magic_links, now};

/// 32 random bytes, base64url. Only the hash is stored.
pub fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    B64.encode(b)
}

pub fn hash_token(token: &str) -> String {
    B64.encode(Sha256::digest(token.as_bytes()))
}

/// Creates a 15-minute link for `user_id`; returns the plaintext token.
pub async fn issue(db: &DatabaseConnection, user_id: Uuid, email: &str) -> Result<String, DbErr> {
    let token = new_token();
    magic_links::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(Some(user_id)),
        email: Set(Some(email.into())),
        token_hash: Set(hash_token(&token)),
        expires_at: Set((chrono::Utc::now() + chrono::Duration::minutes(15)).into()),
        used_at: Set(None),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(db)
    .await?;
    Ok(token)
}

/// Atomically marks the link used; returns its user if it was valid, unused and unexpired.
pub async fn consume(db: &DatabaseConnection, token: &str) -> Result<Option<Uuid>, DbErr> {
    let hash = hash_token(token);
    let res = magic_links::Entity::update_many()
        .col_expr(magic_links::Column::UsedAt, now().into())
        .filter(magic_links::Column::TokenHash.eq(&hash))
        .filter(magic_links::Column::UsedAt.is_null())
        .filter(magic_links::Column::ExpiresAt.gt(now()))
        .exec(db)
        .await?;
    if res.rows_affected != 1 {
        return Ok(None);
    }
    Ok(magic_links::Entity::find()
        .filter(magic_links::Column::TokenHash.eq(hash))
        .one(db)
        .await?
        .and_then(|l| l.user_id))
}
