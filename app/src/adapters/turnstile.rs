//! The Cloudflare Turnstile check on anonymous mail-sending forms. `CloudflareTurnstile` asks
//! siteverify (form POST, short timeout); `NoChallenge` passes everything and is used only
//! when no secret is configured outside production. The secret, the token and the visitor's
//! address are never logged; errors carry only a stable kind.
use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use serde::Deserialize;

pub const API_BASE: &str = "https://challenges.cloudflare.com";
const VERIFY_PATH: &str = "/turnstile/v0/siteverify";
pub const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChallengeError {
    /// The token is missing or Cloudflare rejected it.
    #[error("challenge failed")]
    Failed,
    /// Cloudflare was unreachable, too slow or answered nonsense: fail closed.
    #[error("challenge unavailable")]
    Unavailable,
}

#[async_trait]
pub trait ChallengeVerifier: Send + Sync {
    /// `Ok` only for a token Cloudflare accepts (or any request under `NoChallenge`).
    async fn verify(&self, token: Option<&str>, ip: Option<IpAddr>) -> Result<(), ChallengeError>;
}

pub struct NoChallenge;

#[async_trait]
impl ChallengeVerifier for NoChallenge {
    async fn verify(&self, _: Option<&str>, _: Option<IpAddr>) -> Result<(), ChallengeError> {
        Ok(())
    }
}

/// No `Debug`: it holds the secret key.
pub struct CloudflareTurnstile {
    url: String,
    secret: String,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct Verdict {
    success: bool,
}

impl CloudflareTurnstile {
    /// Fails only if the TLS backend cannot initialise.
    pub fn new(api_base: &str, secret: &str, timeout: Duration) -> Result<Self, reqwest::Error> {
        Ok(Self {
            url: format!("{}{VERIFY_PATH}", api_base.trim_end_matches('/')),
            secret: secret.to_owned(),
            http: reqwest::Client::builder().timeout(timeout).build()?,
        })
    }
}

#[async_trait]
impl ChallengeVerifier for CloudflareTurnstile {
    async fn verify(&self, token: Option<&str>, ip: Option<IpAddr>) -> Result<(), ChallengeError> {
        let Some(token) = token.map(str::trim).filter(|t| !t.is_empty()) else {
            return Err(ChallengeError::Failed);
        };
        let mut form = vec![
            ("secret", self.secret.clone()),
            ("response", token.to_owned()),
        ];
        if let Some(ip) = ip {
            form.push(("remoteip", ip.to_string()));
        }
        let res = self.http.post(&self.url).form(&form).send().await;
        let verdict = match res {
            Ok(r) if r.status().is_success() => r.json::<Verdict>().await.ok(),
            _ => None,
        };
        match verdict {
            Some(Verdict { success: true }) => Ok(()),
            Some(_) => Err(ChallengeError::Failed),
            None => Err(ChallengeError::Unavailable),
        }
    }
}
