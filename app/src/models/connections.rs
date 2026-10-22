use loco_rs::{Error, Result};
use opsagent_core::connection::ConnectionStatus;
use opsagent_secrets::{open, seal, Aad, EnvKek, Kek, Sealed, WrappedDek};
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::_entities::{connection_credentials, connections, organisations};

pub const TEMPLATE_VERSION: &str = "1";

/// Plaintext of `connection_credentials.ciphertext`. Never serialised into an API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Creds {
    pub external_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,
    /// Fixture account for the `fake` provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fake_account: Option<String>,
}

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

/// The org DEK, unwrapped with the env KEK.
pub async fn org_dek(db: &impl ConnectionTrait, organisation_id: Uuid) -> Result<Dek> {
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
    let dek = EnvKek::from_env()
        .and_then(|k| k.unwrap(organisation_id, &w))
        .map_err(secrets_err)?;
    Ok(Dek { key: dek, version })
}

/// An unwrapped org DEK and the KEK version that wrapped it.
pub struct Dek {
    pub key: Zeroizing<[u8; 32]>,
    pub version: i32,
}

pub fn seal_creds(dek: &Dek, organisation_id: Uuid, c: &Creds) -> Result<Sealed> {
    let plain = serde_json::to_vec(c)?;
    Ok(seal(&dek.key, &plain, &aad(organisation_id)))
}

pub fn open_creds(
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

/// The account a role ARN belongs to (`arn:aws:iam::<account>:role/...`).
pub fn account_of(c: &connections::Model, creds: &Creds) -> Option<String> {
    match c.provider.as_str() {
        "fake" => creds.fake_account.clone(),
        _ => creds
            .role_arn
            .as_deref()
            .and_then(|a| opsagent_connectors::aws::client::parse_role_arn(a).ok())
            .map(|a| a.account),
    }
}

/// Writes `a` only if the row still has `c.status` (the status the caller read). `false`: it changed.
pub async fn cas(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    a: connections::ActiveModel,
) -> std::result::Result<bool, DbErr> {
    let r = connections::Entity::update_many()
        .set(a)
        .filter(connections::Column::Id.eq(c.id))
        .filter(connections::Column::Status.eq(&c.status))
        .exec(db)
        .await?;
    Ok(r.rows_affected == 1)
}
