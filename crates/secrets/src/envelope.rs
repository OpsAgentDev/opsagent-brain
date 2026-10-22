use crate::{Result, SecretsError};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct Aad {
    pub organisation_id: Uuid,
    pub table: &'static str,
    pub column: &'static str,
}

impl Aad {
    /// organisation_id || table || column, no separators (security.md).
    fn bytes(&self) -> Vec<u8> {
        [
            self.organisation_id.as_bytes().as_slice(),
            self.table.as_bytes(),
            self.column.as_bytes(),
        ]
        .concat()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

pub fn generate_dek() -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *k);
    k
}

/// AES-256-GCM with a fresh random 96-bit nonce and `aad` bound in.
pub(crate) fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Sealed {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = Aes256Gcm::new(key.into())
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption cannot fail for in-memory input");
    Sealed { ciphertext, nonce }
}

pub(crate) fn decrypt(key: &[u8; 32], s: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Aes256Gcm::new(key.into())
        .decrypt(
            &Nonce::from(s.nonce),
            Payload {
                msg: &s.ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SecretsError::Decrypt)
}

pub fn seal(dek: &[u8; 32], plaintext: &[u8], aad: &Aad) -> Sealed {
    encrypt(dek, plaintext, &aad.bytes())
}

pub fn open(dek: &[u8; 32], sealed: &Sealed, aad: &Aad) -> Result<Zeroizing<Vec<u8>>> {
    decrypt(dek, sealed, &aad.bytes())
}
