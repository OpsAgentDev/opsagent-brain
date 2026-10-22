use crate::envelope::{decrypt, encrypt, Sealed};
use crate::{Result, SecretsError};
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

/// blob = nonce (12) || ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedDek {
    pub blob: Vec<u8>,
    pub version: u32,
}

pub trait Kek: Send + Sync {
    fn wrap(&self, dek: &[u8; 32]) -> Result<WrappedDek>;
    fn unwrap(&self, w: &WrappedDek) -> Result<Zeroizing<[u8; 32]>>;
    fn current_version(&self) -> u32;
}

pub struct EnvKek {
    version: u32,
    current: Zeroizing<[u8; 32]>,
    prev: Option<Zeroizing<[u8; 32]>>,
}

fn wrapping_key(raw: &[u8; 32], version: u32) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, raw)
        .expand(format!("opsagent-kek-v{version}").as_bytes(), &mut *out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn decode_key(s: &str) -> Result<[u8; 32]> {
    let v = Zeroizing::new(
        STANDARD
            .decode(s.trim())
            .map_err(|_| SecretsError::BadBase64)?,
    );
    v.as_slice()
        .try_into()
        .map_err(|_| SecretsError::BadKeyLength(v.len()))
}

impl EnvKek {
    pub fn new(current: [u8; 32], version: u32, prev: Option<[u8; 32]>) -> Self {
        Self {
            version,
            current: Zeroizing::new(current),
            prev: prev.map(Zeroizing::new),
        }
    }

    pub fn from_env() -> Result<Self> {
        let cur = std::env::var("OPSAGENT_KEK")
            .map_err(|_| SecretsError::BadEnv("OPSAGENT_KEK is not set".into()))?;
        let version = match std::env::var("OPSAGENT_KEK_VERSION") {
            Ok(v) => v
                .trim()
                .parse()
                .map_err(|_| SecretsError::BadEnv("OPSAGENT_KEK_VERSION is not a u32".into()))?,
            Err(_) => 1,
        };
        let prev = std::env::var("OPSAGENT_KEK_PREV")
            .ok()
            .map(|p| decode_key(&p))
            .transpose()?;
        Ok(Self::new(decode_key(&cur)?, version, prev))
    }

    fn raw_for(&self, version: u32) -> Result<&[u8; 32]> {
        if version == self.version {
            return Ok(&self.current);
        }
        match &self.prev {
            Some(p) if version.checked_add(1) == Some(self.version) => Ok(p),
            _ => Err(SecretsError::UnknownVersion(version)),
        }
    }
}

impl Kek for EnvKek {
    fn wrap(&self, dek: &[u8; 32]) -> Result<WrappedDek> {
        let s = encrypt(&wrapping_key(&self.current, self.version), dek, b"");
        Ok(WrappedDek {
            blob: [s.nonce.as_slice(), &s.ciphertext].concat(),
            version: self.version,
        })
    }

    fn unwrap(&self, w: &WrappedDek) -> Result<Zeroizing<[u8; 32]>> {
        let raw = self.raw_for(w.version)?;
        if w.blob.len() < 12 {
            return Err(SecretsError::Decrypt);
        }
        let (nonce, ct) = w.blob.split_at(12);
        let sealed = Sealed {
            ciphertext: ct.to_vec(),
            nonce: nonce.try_into().unwrap(),
        };
        let pt = decrypt(&wrapping_key(raw, w.version), &sealed, b"")?;
        let mut dek = Zeroizing::new([0u8; 32]);
        if pt.len() != 32 {
            return Err(SecretsError::Decrypt);
        }
        dek.copy_from_slice(&pt);
        Ok(dek)
    }

    fn current_version(&self) -> u32 {
        self.version
    }
}
