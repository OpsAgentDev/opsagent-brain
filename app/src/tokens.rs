//! Single-use link tokens (sign-in, invites, confirmations): random, stored only as a hash.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// 32 random bytes, base64url. Only the hash is stored.
pub fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    B64.encode(b)
}

pub fn hash_token(token: &str) -> String {
    B64.encode(Sha256::digest(token.as_bytes()))
}
