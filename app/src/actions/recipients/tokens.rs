//! Unsubscribe tokens (stable HMAC per recipient) and the suppression key of an address.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Hex SHA-256 of the lowercased address: the suppression key (no plaintext email stored).
pub fn email_hash(email: &str) -> String {
    format!("{:x}", Sha256::digest(email.to_lowercase()))
}

/// The HMAC key for unsubscribe tokens, derived from `Config::unsubscribe_key`.
fn unsubscribe_mac(secret: &str, id: Uuid) -> Hmac<Sha256> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret.as_bytes())
        .expand(b"opsagent-unsubscribe", &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    let mut m = Hmac::<Sha256>::new_from_slice(&key).expect("hmac accepts any key");
    m.update(id.as_bytes());
    m
}

/// `<recipient id>.<base64url HMAC-SHA256(key, id)>`: stable for the row's lifetime, so every
/// mail carries the same working link.
pub fn unsubscribe_token(secret: &str, id: Uuid) -> String {
    let mac = unsubscribe_mac(secret, id).finalize().into_bytes();
    format!("{}.{}", id.simple(), B64.encode(mac))
}

/// The recipient id a token was issued for, if its HMAC verifies (constant-time compare).
pub(super) fn verify_unsubscribe(secret: &str, token: &str) -> Option<Uuid> {
    let (id, mac) = token.split_once('.')?;
    let id = Uuid::try_parse(id).ok()?;
    let mac = B64.decode(mac).ok()?;
    unsubscribe_mac(secret, id).verify_slice(&mac).ok()?;
    Some(id)
}

/// The footer link for recipient `id`.
pub fn unsubscribe_url(web_base_url: &str, secret: &str, id: Uuid) -> String {
    format!(
        "{}/unsubscribe/{}",
        web_base_url.trim_end_matches('/'),
        unsubscribe_token(secret, id)
    )
}
