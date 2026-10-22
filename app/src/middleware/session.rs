use async_trait::async_trait;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use tower_sessions::{
    cookie::SameSite,
    session::{Id, Record},
    session_store::{self, SessionStore},
    Expiry, SessionManagerLayer,
};

use crate::{models::_entities::sessions, models::now, settings::Settings};

pub const COOKIE_NAME: &str = "opsagent_session";
pub const USER_KEY: &str = "user_id";

/// Postgres store on the existing `sessions` table via SeaORM. (tower-sessions-sqlx-store
/// pins sqlx 0.8; this app's sea-orm uses 0.9, so the pools are not interchangeable.)
#[derive(Clone, Debug)]
pub struct DbStore(DatabaseConnection);

fn backend(e: impl std::fmt::Display) -> session_store::Error {
    session_store::Error::Backend(e.to_string())
}

fn to_chrono(t: time::OffsetDateTime) -> chrono::DateTime<chrono::FixedOffset> {
    chrono::DateTime::from_timestamp(t.unix_timestamp(), t.nanosecond())
        .unwrap_or_default()
        .into()
}

fn encode(
    record: &Record,
) -> session_store::Result<(Vec<u8>, chrono::DateTime<chrono::FixedOffset>)> {
    let data = serde_json::to_vec(&record.data)
        .map_err(|e| session_store::Error::Encode(e.to_string()))?;
    Ok((data, to_chrono(record.expiry_date)))
}

#[async_trait]
impl SessionStore for DbStore {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        // 128-bit random ids: regenerate on the (astronomically unlikely) collision.
        while sessions::Entity::find_by_id(record.id.to_string())
            .one(&self.0)
            .await
            .map_err(backend)?
            .is_some()
        {
            record.id = Id::default();
        }
        let (data, expiry) = encode(record)?;
        sessions::Entity::insert(sessions::ActiveModel {
            id: Set(record.id.to_string()),
            data: Set(data),
            expiry_date: Set(expiry),
            created_at: Set(now()),
            updated_at: Set(now()),
        })
        .exec(&self.0)
        .await
        .map(|_| ())
        .map_err(backend)
    }

    /// UPDATE only: with always_save, the end-of-request save must not resurrect a row that
    /// sign-out deleted or that has expired. Inserts happen in `create` only.
    async fn save(&self, record: &Record) -> session_store::Result<()> {
        let (data, expiry) = encode(record)?;
        sessions::Entity::update_many()
            .col_expr(sessions::Column::Data, data.into())
            .col_expr(sessions::Column::ExpiryDate, expiry.into())
            .col_expr(sessions::Column::UpdatedAt, now().into())
            .filter(sessions::Column::Id.eq(record.id.to_string()))
            .filter(sessions::Column::ExpiryDate.gt(now()))
            .exec(&self.0)
            .await
            .map(|_| ())
            .map_err(backend)
    }

    async fn load(&self, id: &Id) -> session_store::Result<Option<Record>> {
        let Some(row) = sessions::Entity::find_by_id(id.to_string())
            .filter(sessions::Column::ExpiryDate.gt(now()))
            .one(&self.0)
            .await
            .map_err(backend)?
        else {
            return Ok(None);
        };
        Ok(Some(Record {
            id: *id,
            data: serde_json::from_slice(&row.data)
                .map_err(|e| session_store::Error::Decode(e.to_string()))?,
            expiry_date: time::OffsetDateTime::from_unix_timestamp(row.expiry_date.timestamp())
                .map_err(backend)?,
        }))
    }

    async fn delete(&self, id: &Id) -> session_store::Result<()> {
        sessions::Entity::delete_by_id(id.to_string())
            .exec(&self.0)
            .await
            .map(|_| ())
            .map_err(backend)
    }
}

pub fn layer(db: DatabaseConnection, s: &Settings) -> SessionManagerLayer<DbStore> {
    let mut l = SessionManagerLayer::new(DbStore(db))
        .with_name(COOKIE_NAME)
        .with_http_only(true)
        // Without this, OnInactivity only slides expiry when session data changes.
        .with_always_save(true)
        .with_same_site(SameSite::Lax)
        .with_secure(s.cookie_secure)
        .with_expiry(Expiry::OnInactivity(time::Duration::days(14)));
    if !s.cookie_domain.is_empty() {
        l = l.with_domain(s.cookie_domain.clone());
    }
    l
}
