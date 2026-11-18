use async_trait::async_trait;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use tower_sessions::{
    cookie::SameSite,
    session::{Id, Record},
    session_store::{self, SessionStore},
    Expiry, SessionManagerLayer,
};

use crate::{config::Config, models::_entities::sessions, models::now};

pub const COOKIE_NAME: &str = "opsagent_session";
pub const USER_KEY: &str = "user_id";
/// Unix seconds of the sign-in that started this session (set in `start_session`).
pub const SIGNED_IN_KEY: &str = "signed_in_at";
/// A session ends this long after it was created, however often it is used. Sign-in rotates
/// the id, which makes a new row, so this counts from the sign-in.
const MAX_AGE_DAYS: i64 = 30;

/// Postgres store on the existing `sessions` table via SeaORM. (tower-sessions-sqlx-store
/// pins sqlx 0.8; this app's sea-orm uses 0.9, so the pools are not interchangeable.)
#[derive(Clone, Debug)]
pub struct DbStore(pub DatabaseConnection);

fn backend(e: impl std::fmt::Display) -> session_store::Error {
    session_store::Error::Backend(e.to_string())
}

fn to_chrono(t: time::OffsetDateTime) -> chrono::DateTime<chrono::FixedOffset> {
    chrono::DateTime::from_timestamp(t.unix_timestamp(), t.nanosecond())
        .unwrap_or_default()
        .into()
}

/// The signed-in user of a session, kept in its own column so all of a person's sessions can be
/// found and ended.
fn user_of(record: &Record) -> Option<uuid::Uuid> {
    serde_json::from_value(record.data.get(USER_KEY)?.clone()).ok()
}

/// Ends every session of `user`, on every device ("sign out everywhere").
pub async fn delete_all_for(
    db: &DatabaseConnection,
    user: uuid::Uuid,
) -> Result<(), sea_orm::DbErr> {
    sessions::Entity::delete_many()
        .filter(sessions::Column::UserId.eq(user))
        .exec(db)
        .await
        .map(|_| ())
}

/// Holds the data as `load` read it, so `save` can tell a request that changed nothing. Never stored.
const LOADED_KEY: &str = "_loaded";

/// The bytes to store, the expiry, and whether the data is still what `load` read.
fn encode(
    record: &Record,
) -> session_store::Result<(Vec<u8>, chrono::DateTime<chrono::FixedOffset>, bool)> {
    let mut data = record.data.clone();
    let loaded = data.remove(LOADED_KEY);
    let unchanged = loaded.is_some_and(|l| serde_json::to_value(&data).is_ok_and(|d| d == l));
    let bytes =
        serde_json::to_vec(&data).map_err(|e| session_store::Error::Encode(e.to_string()))?;
    Ok((bytes, to_chrono(record.expiry_date), unchanged))
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
        let (data, expiry, _) = encode(record)?;
        sessions::Entity::insert(sessions::ActiveModel {
            id: Set(record.id.to_string()),
            data: Set(data),
            expiry_date: Set(expiry),
            created_at: Set(now()),
            updated_at: Set(now()),
            user_id: Set(user_of(record)),
        })
        .exec(&self.0)
        .await
        .map(|_| ())
        .map_err(backend)
    }

    /// UPDATE only: with always_save, the end-of-request save must not resurrect a row that
    /// sign-out deleted or that has expired. Inserts happen in `create` only.
    ///
    /// A request that changed nothing only slides the expiry. Writing its copy of the data back
    /// would undo what a request that overlapped it stored (a passkey or OAuth state in progress).
    /// Two overlapping requests that both change the data are still last write wins.
    async fn save(&self, record: &Record) -> session_store::Result<()> {
        let (data, expiry, unchanged) = encode(record)?;
        let mut update = sessions::Entity::update_many()
            .col_expr(sessions::Column::ExpiryDate, expiry.into())
            .col_expr(sessions::Column::UpdatedAt, now().into());
        if !unchanged {
            update = update
                .col_expr(sessions::Column::Data, data.into())
                .col_expr(sessions::Column::UserId, user_of(record).into());
        }
        update
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
            .filter(sessions::Column::CreatedAt.gt(now() - chrono::Duration::days(MAX_AGE_DAYS)))
            .one(&self.0)
            .await
            .map_err(backend)?
        else {
            return Ok(None);
        };
        let mut data: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_slice(&row.data)
                .map_err(|e| session_store::Error::Decode(e.to_string()))?;
        let loaded = serde_json::to_value(&data).map_err(backend)?;
        data.insert(LOADED_KEY.into(), loaded);
        Ok(Some(Record {
            id: *id,
            data,
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

pub fn layer(db: DatabaseConnection, s: &Config) -> SessionManagerLayer<DbStore> {
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
