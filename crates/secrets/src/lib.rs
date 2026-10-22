//! Envelope encryption: per-org DEKs wrapped by a versioned KEK.
mod envelope;
mod kek;

pub use envelope::{generate_dek, open, seal, Aad, Sealed};
pub use kek::{EnvKek, Kek, WrappedDek};

#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    #[error("key must be 32 bytes, got {0}")]
    BadKeyLength(usize),
    #[error("decryption failed")]
    Decrypt,
    #[error("no KEK available for version {0}")]
    UnknownVersion(u32),
    #[error("invalid base64")]
    BadBase64,
    #[error("invalid environment: {0}")]
    BadEnv(String),
}

pub type Result<T> = std::result::Result<T, SecretsError>;
