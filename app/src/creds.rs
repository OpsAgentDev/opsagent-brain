//! Connection credentials sealed under the org DEK (AAD table `connection_credentials`,
//! column `ciphertext`). Repositories store only the sealed form.
use opsagent_core::{
    connection::SealedCreds,
    org::OrganisationsRepo,
    repo::{RepoError, RepoResult},
};
use opsagent_secrets::{open, seal, Aad, Kek, Sealed, SecretsError, WrappedDek};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use opsagent_connectors::registry::Creds;

use crate::actions::uow::Repos;

fn aad(organisation_id: Uuid) -> Aad {
    Aad {
        organisation_id,
        table: "connection_credentials",
        column: "ciphertext",
    }
}

fn secrets_err(e: SecretsError) -> RepoError {
    RepoError::Storage(e.to_string())
}

fn json_err(e: serde_json::Error) -> RepoError {
    RepoError::Storage(format!("credentials json: {e}"))
}

/// An unwrapped org DEK and the KEK version that wrapped it.
pub struct Dek {
    pub key: Zeroizing<[u8; 32]>,
    pub version: i32,
}

impl Dek {
    /// The org DEK, unwrapped with the KEK.
    pub async fn of(
        orgs: &dyn OrganisationsRepo,
        kek: &dyn Kek,
        organisation_id: Uuid,
    ) -> RepoResult<Self> {
        let org = orgs
            .get(organisation_id)
            .await?
            .ok_or(RepoError::NotFound)?;
        let (Some(blob), Some(version)) = (org.wrapped_dek, org.kek_version) else {
            return Err(RepoError::Storage("organisation has no DEK".into()));
        };
        let w = WrappedDek {
            blob,
            version: u32::try_from(version).map_err(|e| RepoError::Storage(e.to_string()))?,
        };
        let key = kek.unwrap(organisation_id, &w).map_err(secrets_err)?;
        Ok(Self { key, version })
    }

    pub fn seal(&self, organisation_id: Uuid, c: &Creds) -> RepoResult<SealedCreds> {
        let plain = Zeroizing::new(serde_json::to_vec(c).map_err(json_err)?);
        let s = seal(&self.key, &plain, &aad(organisation_id));
        Ok(SealedCreds {
            ciphertext: s.ciphertext,
            nonce: s.nonce.to_vec(),
            kek_version: self.version,
        })
    }

    pub fn open(&self, organisation_id: Uuid, s: &SealedCreds) -> RepoResult<Creds> {
        let sealed = Sealed {
            ciphertext: s.ciphertext.clone(),
            nonce: s
                .nonce
                .as_slice()
                .try_into()
                .map_err(|_| RepoError::Storage("bad credential nonce".into()))?,
        };
        let plain = open(&self.key, &sealed, &aad(organisation_id)).map_err(secrets_err)?;
        serde_json::from_slice(&plain).map_err(json_err)
    }
}

/// The connection's decrypted credentials.
pub async fn load(
    repos: &dyn Repos,
    kek: &dyn Kek,
    organisation_id: Uuid,
    id: Uuid,
) -> RepoResult<Creds> {
    let dek = Dek::of(repos.orgs(), kek, organisation_id).await?;
    dek.open(
        organisation_id,
        &repos.connections().load_creds(organisation_id, id).await?,
    )
}

/// Re-seals `c` into the connection's stored credentials.
pub async fn save(
    repos: &dyn Repos,
    kek: &dyn Kek,
    organisation_id: Uuid,
    id: Uuid,
    c: &Creds,
) -> RepoResult<()> {
    let dek = Dek::of(repos.orgs(), kek, organisation_id).await?;
    let sealed = dek.seal(organisation_id, c)?;
    repos
        .connections()
        .save_creds(organisation_id, id, sealed)
        .await
}
