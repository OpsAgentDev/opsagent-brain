//! Integration tokens, sealed with the org DEK (AAD table `integrations`, column `ciphertext`).
use loco_rs::{Error, Result};
use opsagent_secrets::{open, seal, Aad, Kek, Sealed};
use sea_orm::ConnectionTrait;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::_entities::integrations;
use crate::{adapters::db::Pg, creds::Dek};

async fn org_dek(db: &impl ConnectionTrait, kek: &dyn Kek, organisation_id: Uuid) -> Result<Dek> {
    Dek::of(&Pg::new(db), kek, organisation_id)
        .await
        .map_err(|e| Error::string(&e.to_string()))
}

pub const SLACK: &str = "slack";
pub const ACTIVE: &str = "active";
pub const REVOKED: &str = "revoked";

fn aad(organisation_id: Uuid) -> Aad {
    Aad {
        organisation_id,
        table: "integrations",
        column: "ciphertext",
    }
}

/// `token` sealed under the org DEK, and the KEK version to store beside it.
pub async fn seal_token(
    db: &impl ConnectionTrait,
    kek: &dyn Kek,
    organisation_id: Uuid,
    token: &str,
) -> Result<(Sealed, i32)> {
    let dek = org_dek(db, kek, organisation_id).await?;
    Ok((
        seal(&dek.key, token.as_bytes(), &aad(organisation_id)),
        dek.version,
    ))
}

/// The row's plaintext token.
pub async fn open_token(
    db: &impl ConnectionTrait,
    kek: &dyn Kek,
    row: &integrations::Model,
) -> Result<Zeroizing<String>> {
    let dek = org_dek(db, kek, row.organisation_id).await?;
    let sealed = Sealed {
        ciphertext: row.ciphertext.clone(),
        nonce: row
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| Error::string("bad integration nonce"))?,
    };
    let plain = open(&dek.key, &sealed, &aad(row.organisation_id))
        .map_err(|e| Error::string(&e.to_string()))?;
    String::from_utf8(plain.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| Error::string("integration token is not UTF-8"))
}
