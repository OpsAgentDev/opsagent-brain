use loco_rs::{Error, Result};
use opsagent_core::connection::ConnectionStatus;
use opsagent_secrets::{open, seal, Aad, Kek, Sealed, WrappedDek};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, Set,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    _entities::{connection_credentials, connections, organisations},
    now,
};

pub use opsagent_connectors::registry::Creds;

pub const TEMPLATE_VERSION: &str = "1";

fn aad(organisation_id: Uuid) -> Aad {
    Aad {
        organisation_id,
        table: "connection_credentials",
        column: "ciphertext",
    }
}

fn secrets_err(e: opsagent_secrets::SecretsError) -> Error {
    Error::string(&e.to_string())
}

pub fn status_of(c: &connections::Model) -> Result<ConnectionStatus> {
    serde_json::from_value(serde_json::Value::String(c.status.clone()))
        .map_err(|e| Error::string(&format!("bad connection status: {e}")))
}

pub fn status_str(s: ConnectionStatus) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The org DEK, unwrapped with the KEK.
pub async fn org_dek(
    db: &impl ConnectionTrait,
    kek: &dyn Kek,
    organisation_id: Uuid,
) -> Result<Dek> {
    let org = organisations::Entity::find_by_id(organisation_id)
        .one(db)
        .await?
        .ok_or_else(|| Error::string("organisation not found"))?;
    let (Some(blob), Some(version)) = (org.wrapped_dek, org.kek_version) else {
        return Err(Error::string("organisation has no DEK"));
    };
    let w = WrappedDek {
        blob,
        version: u32::try_from(version).map_err(|e| Error::string(&e.to_string()))?,
    };
    let key = kek.unwrap(organisation_id, &w).map_err(secrets_err)?;
    Ok(Dek { key, version })
}

/// An unwrapped org DEK and the KEK version that wrapped it.
pub struct Dek {
    pub key: Zeroizing<[u8; 32]>,
    pub version: i32,
}

fn seal_creds(dek: &Dek, organisation_id: Uuid, c: &Creds) -> Result<Sealed> {
    let plain = serde_json::to_vec(c)?;
    Ok(seal(&dek.key, &plain, &aad(organisation_id)))
}

fn open_creds(
    dek: &Dek,
    organisation_id: Uuid,
    row: &connection_credentials::Model,
) -> Result<Creds> {
    let sealed = Sealed {
        ciphertext: row.ciphertext.clone(),
        nonce: row
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| Error::string("bad credential nonce"))?,
    };
    let plain = open(&dek.key, &sealed, &aad(organisation_id)).map_err(secrets_err)?;
    Ok(serde_json::from_slice(&plain)?)
}

/// Decrypts the connection's stored credentials.
pub async fn load_creds(
    db: &impl ConnectionTrait,
    kek: &dyn Kek,
    c: &connections::Model,
) -> Result<Creds> {
    let dek = org_dek(db, kek, c.organisation_id).await?;
    let row = connection_credentials::Entity::find_by_id(c.id)
        .one(db)
        .await?
        .ok_or_else(|| Error::string("connection has no credentials"))?;
    open_creds(&dek, c.organisation_id, &row)
}

/// Seals `creds` into a new credential row for connection `id`.
pub async fn insert_creds(
    db: &impl ConnectionTrait,
    kek: &dyn Kek,
    organisation_id: Uuid,
    id: Uuid,
    kind: &str,
    creds: &Creds,
) -> Result<()> {
    let dek = org_dek(db, kek, organisation_id).await?;
    let sealed = seal_creds(&dek, organisation_id, creds)?;
    connection_credentials::ActiveModel {
        connection_id: Set(id),
        kind: Set(kind.into()),
        ciphertext: Set(sealed.ciphertext),
        nonce: Set(sealed.nonce.to_vec()),
        kek_version: Set(dek.version),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(db)
    .await?;
    Ok(())
}

/// Re-seals `creds` into the connection's existing credential row.
pub async fn save_creds(
    db: &impl ConnectionTrait,
    kek: &dyn Kek,
    c: &connections::Model,
    creds: &Creds,
) -> Result<()> {
    let dek = org_dek(db, kek, c.organisation_id).await?;
    let sealed = seal_creds(&dek, c.organisation_id, creds)?;
    connection_credentials::Entity::update_many()
        .col_expr(
            connection_credentials::Column::Ciphertext,
            sealed.ciphertext.into(),
        )
        .col_expr(
            connection_credentials::Column::Nonce,
            sealed.nonce.to_vec().into(),
        )
        .col_expr(
            connection_credentials::Column::KekVersion,
            dek.version.into(),
        )
        .col_expr(connection_credentials::Column::UpdatedAt, now().into())
        .filter(connection_credentials::Column::ConnectionId.eq(c.id))
        .exec(db)
        .await?;
    Ok(())
}

/// Writes `a` only if the row still has `c.status` (the status the caller read). `false`: it changed.
pub async fn cas(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    a: connections::ActiveModel,
) -> std::result::Result<bool, DbErr> {
    let r = connections::Entity::update_many()
        .set(a)
        .filter(connections::Column::OrganisationId.eq(c.organisation_id))
        .filter(connections::Column::Id.eq(c.id))
        .filter(connections::Column::Status.eq(&c.status))
        .exec(db)
        .await?;
    Ok(r.rows_affected == 1)
}
