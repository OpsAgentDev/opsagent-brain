use async_trait::async_trait;
use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};
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

type Data = std::collections::HashMap<String, serde_json::Value>;

/// The signed-in user of a session, kept in its own column so all of a person's sessions can be
/// found and ended.
fn user_of(data: &Data) -> Option<uuid::Uuid> {
    serde_json::from_value(data.get(USER_KEY)?.clone()).ok()
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

/// Ends every session of `user` except the one with id `keep`.
pub async fn delete_others_for(
    db: &DatabaseConnection,
    user: uuid::Uuid,
    keep: &str,
) -> Result<(), sea_orm::DbErr> {
    sessions::Entity::delete_many()
        .filter(sessions::Column::UserId.eq(user))
        .filter(sessions::Column::Id.ne(keep))
        .exec(db)
        .await
        .map(|_| ())
}

/// Holds the data as `load` read it, so `save` can tell what this request changed. Never stored.
const LOADED_KEY: &str = "_loaded";

fn to_bytes(data: &Data) -> session_store::Result<Vec<u8>> {
    serde_json::to_vec(data).map_err(|e| session_store::Error::Encode(e.to_string()))
}

/// The record's data without the `load` copy, and that copy (none for a session not loaded here).
fn split(record: &Record) -> (Data, Option<Data>) {
    let mut data = record.data.clone();
    let loaded = data
        .remove(LOADED_KEY)
        .and_then(|l| serde_json::from_value(l).ok());
    (data, loaded)
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
        let (data, _) = split(record);
        let expiry = to_chrono(record.expiry_date);
        sessions::Entity::insert(sessions::ActiveModel {
            id: Set(record.id.to_string()),
            user_id: Set(user_of(&data)),
            data: Set(to_bytes(&data)?),
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
    ///
    /// Only the keys this request changed are written, onto the row as it is now. Writing the
    /// whole copy back would undo what an overlapping request stored (seen: a slow GET ending
    /// after passkey register/start, so finish found no ceremony). A request that changed nothing
    /// only slides the expiry. Two requests that change the same key are last write wins.
    async fn save(&self, record: &Record) -> session_store::Result<()> {
        let (data, loaded) = split(record);
        let expiry = to_chrono(record.expiry_date);
        let live = || {
            Condition::all()
                .add(sessions::Column::Id.eq(record.id.to_string()))
                .add(sessions::Column::ExpiryDate.gt(now()))
        };
        let touch = || {
            sessions::Entity::update_many()
                .col_expr(sessions::Column::ExpiryDate, expiry.into())
                .col_expr(sessions::Column::UpdatedAt, now().into())
                .filter(live())
        };
        let write = |data: &Data| -> session_store::Result<_> {
            Ok(touch()
                .col_expr(sessions::Column::Data, to_bytes(data)?.into())
                .col_expr(sessions::Column::UserId, user_of(data).into()))
        };
        let Some(loaded) = loaded else {
            return write(&data)?
                .exec(&self.0)
                .await
                .map(|_| ())
                .map_err(backend);
        };
        let set: Vec<_> = data
            .iter()
            .filter(|(k, v)| loaded.get(*k) != Some(v))
            .collect();
        let removed: Vec<_> = loaded.keys().filter(|k| !data.contains_key(*k)).collect();
        if set.is_empty() && removed.is_empty() {
            return touch().exec(&self.0).await.map(|_| ()).map_err(backend);
        }
        let txn = self.0.begin().await.map_err(backend)?;
        let row = sessions::Entity::find()
            .filter(live())
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(backend)?;
        if let Some(row) = row {
            let mut current: Data = serde_json::from_slice(&row.data)
                .map_err(|e| session_store::Error::Decode(e.to_string()))?;
            for (k, v) in set {
                current.insert(k.clone(), v.clone());
            }
            for k in removed {
                current.remove(k);
            }
            write(&current)?.exec(&txn).await.map_err(backend)?;
        }
        txn.commit().await.map_err(backend)
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
        let mut data: Data = serde_json::from_slice(&row.data)
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
