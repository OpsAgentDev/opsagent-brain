//! The WebAuthn relying party: ID = host of `WEB_BASE_URL`, origin = `WEB_BASE_URL`.
use webauthn_rs::prelude::{Url, Webauthn, WebauthnBuilder};

use crate::error::AppError;

/// The host of `web_base_url`; `None` if it is not a URL with a host.
pub fn rp_id(web_base_url: &str) -> Option<String> {
    Url::parse(web_base_url).ok()?.host_str().map(str::to_owned)
}

/// The relying party for `web_base_url`; fails if it has no host, so boot does.
pub fn build(web_base_url: &str) -> Result<Webauthn, AppError> {
    let bad = |e: String| AppError::Internal(format!("WEB_BASE_URL is not a WebAuthn origin: {e}"));
    let id = rp_id(web_base_url).ok_or_else(|| bad("no host".into()))?;
    let origin = Url::parse(web_base_url).map_err(|e| bad(e.to_string()))?;
    WebauthnBuilder::new(&id, &origin)
        .and_then(|b| b.rp_name("OpsAgent").build())
        .map_err(|e| bad(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_is_web_host() {
        assert_eq!(
            rp_id("https://opsagent.dev").as_deref(),
            Some("opsagent.dev")
        );
        assert_eq!(rp_id("http://localhost:3001").as_deref(), Some("localhost"));
        assert_eq!(rp_id("not a url"), None);
        assert!(build("not a url").is_err());
        build("http://localhost:3000").unwrap();
    }
}
