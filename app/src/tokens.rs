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

/// Hex HMAC-SHA256(`secret`, `token_hash` ":" `code`): what is stored for a mailed code.
pub fn code_hash(secret: &str, token_hash: &str, code: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    m.update(format!("{token_hash}:{code}").as_bytes());
    format!("{:x}", m.finalize().into_bytes())
}

/// 6 digits, uniform over `000000`..=`999999`.
pub fn new_code() -> String {
    use rand::Rng;
    format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000))
}
