pub mod magic_link;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use loco_rs::{Error, Result};

#[derive(Clone, Debug)]
pub struct Mail {
    pub to: String,
    pub subject: String,
    pub text: String,
}

#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, mail: Mail) -> std::result::Result<(), String>;
}

/// Local default when `RESEND_API_KEY` is unset: logs the mail (including its link).
pub struct LogMailer;

#[async_trait]
impl Mailer for LogMailer {
    async fn send(&self, mail: Mail) -> std::result::Result<(), String> {
        tracing::info!(to = %mail.to, subject = %mail.subject, "mail (not sent, no RESEND_API_KEY):\n{}", mail.text);
        Ok(())
    }
}

/// Test double that records every mail.
#[derive(Default)]
pub struct CaptureMailer(Mutex<Vec<Mail>>);

impl CaptureMailer {
    pub fn sent(&self) -> Vec<Mail> {
        self.0.lock().unwrap().clone()
    }
}

#[async_trait]
impl Mailer for CaptureMailer {
    async fn send(&self, mail: Mail) -> std::result::Result<(), String> {
        self.0.lock().unwrap().push(mail);
        Ok(())
    }
}

pub struct ResendMailer {
    key: String,
    from: String,
    http: reqwest::Client,
}

#[async_trait]
impl Mailer for ResendMailer {
    async fn send(&self, mail: Mail) -> std::result::Result<(), String> {
        let res = self
            .http
            .post("https://api.resend.com/emails")
            .bearer_auth(&self.key)
            .json(&serde_json::json!({
                "from": self.from, "to": [mail.to], "subject": mail.subject, "text": mail.text
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        res.error_for_status()
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Resend when `RESEND_API_KEY` is set; otherwise the log mailer, which production refuses.
pub fn from_env(production: bool) -> Result<Arc<dyn Mailer>> {
    match std::env::var("RESEND_API_KEY") {
        Ok(key) if !key.is_empty() => Ok(Arc::new(ResendMailer {
            key,
            from: std::env::var("MAIL_FROM")
                .unwrap_or_else(|_| "OpsAgent <login@opsagent.dev>".into()),
            http: reqwest::Client::new(),
        })),
        _ if production => Err(Error::string("RESEND_API_KEY is required in production")),
        _ => Ok(Arc::new(LogMailer)),
    }
}
