pub mod magic_link;

use std::sync::Arc;

use async_trait::async_trait;
use lettre::{
    address::AddressError, message::Mailbox, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
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

/// Local default when neither `MAILER_SMTP_URL` nor `RESEND_API_KEY` is set: logs recipient and subject only.
/// The body carries a magic-link or invite token, so it is emitted at debug in debug builds only.
pub struct LogMailer;

#[async_trait]
impl Mailer for LogMailer {
    async fn send(&self, mail: Mail) -> std::result::Result<(), String> {
        tracing::info!(to = %mail.to, subject = %mail.subject, "mail not sent (no MAILER_SMTP_URL or RESEND_API_KEY)");
        // Development-only: the body holds a token. Compiled out of release builds.
        #[cfg(debug_assertions)]
        tracing::debug!(to = %mail.to, body = %mail.text, "mail body (development only)");
        Ok(())
    }
}

/// Test double that records every mail.
#[cfg(feature = "test-support")]
#[derive(Default)]
pub struct CaptureMailer(std::sync::Mutex<Vec<Mail>>);

#[cfg(feature = "test-support")]
impl CaptureMailer {
    pub fn sent(&self) -> Vec<Mail> {
        self.0.lock().unwrap().clone()
    }
}

#[cfg(feature = "test-support")]
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

/// SMTP (plain, no TLS) for local delivery to mailpit (`MAILER_SMTP_URL=smtp://localhost:1025`).
/// shortcut: no STARTTLS/TLS features compiled in; enable lettre's rustls features if a real relay is needed.
pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpMailer {
    pub fn new(url: &str, from: &str) -> std::result::Result<Self, String> {
        Ok(Self {
            transport: AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
                .map_err(|e| e.to_string())?
                .build(),
            from: from.parse().map_err(|e: AddressError| e.to_string())?,
        })
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send(&self, mail: Mail) -> std::result::Result<(), String> {
        let msg = Message::builder()
            .from(self.from.clone())
            .to(mail.to.parse().map_err(|e: AddressError| e.to_string())?)
            .subject(mail.subject)
            .body(mail.text)
            .map_err(|e| e.to_string())?;
        self.transport
            .send(msg)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Which mailer the environment asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum MailerChoice {
    Smtp(String),
    Resend(String),
    Log,
}

/// True when the SMTP URL's host is `localhost`, `127.0.0.1` or `::1`; unparseable is false.
fn is_loopback(url: &str) -> bool {
    reqwest::Url::parse(url)
        .is_ok_and(|u| matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
}

/// `MAILER_SMTP_URL` wins (local mailpit; production allows only a loopback relay), then `RESEND_API_KEY`; otherwise the log mailer,
/// which production refuses. Empty values count as unset.
pub fn choose(
    smtp_url: Option<String>,
    resend_key: Option<String>,
    production: bool,
) -> Result<MailerChoice> {
    let set = |v: Option<String>| v.filter(|s| !s.is_empty());
    match (set(smtp_url), set(resend_key)) {
        (Some(url), _) if production && !is_loopback(&url) => Err(Error::string(
            "MAILER_SMTP_URL must point at a loopback host in production (plain SMTP, no TLS)",
        )),
        (Some(url), _) => Ok(MailerChoice::Smtp(url)),
        (None, Some(key)) => Ok(MailerChoice::Resend(key)),
        _ if production => Err(Error::string("RESEND_API_KEY is required in production")),
        _ => Ok(MailerChoice::Log),
    }
}

pub fn from_env(production: bool) -> Result<Arc<dyn Mailer>> {
    let env = |k: &str| std::env::var(k).ok();
    let from = env("MAIL_FROM").unwrap_or_else(|| "OpsAgent <login@opsagent.dev>".into());
    Ok(
        match choose(env("MAILER_SMTP_URL"), env("RESEND_API_KEY"), production)? {
            MailerChoice::Smtp(url) => {
                Arc::new(SmtpMailer::new(&url, &from).map_err(|e| Error::string(&e))?)
            }
            MailerChoice::Resend(key) => Arc::new(ResendMailer {
                key,
                from,
                http: reqwest::Client::new(),
            }),
            MailerChoice::Log => Arc::new(LogMailer),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn log_mailer_at_info_never_logs_the_token() {
        let buf = Buf(Arc::default());
        let sub = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer({
                let b = buf.clone();
                move || b.clone()
            })
            .finish();
        let _g = tracing::subscriber::set_default(sub);
        LogMailer
            .send(Mail {
                to: "a@example.com".into(),
                subject: "Sign in".into(),
                text: "https://x.test/auth/callback?token=SECRET123".into(),
            })
            .await
            .unwrap();
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("a@example.com") && out.contains("Sign in"),
            "{out}"
        );
        assert!(!out.contains("SECRET123"), "{out}");
    }

    fn s(v: &str) -> Option<String> {
        Some(v.into())
    }

    #[test]
    fn smtp_url_selects_smtp_even_with_resend_key() {
        let c = choose(s("smtp://localhost:1025"), s("re_x"), false).unwrap();
        assert_eq!(c, MailerChoice::Smtp("smtp://localhost:1025".into()));
    }

    #[test]
    fn resend_then_log_then_production_refusal() {
        assert_eq!(
            choose(s(""), s("re_x"), false).unwrap(),
            MailerChoice::Resend("re_x".into())
        );
        assert_eq!(choose(None, None, false).unwrap(), MailerChoice::Log);
        assert!(choose(None, None, true).is_err());
    }

    #[test]
    fn production_smtp_only_on_loopback() {
        assert!(choose(s("smtp://user:pass@mail.example.com"), s("re_x"), true).is_err());
        for url in [
            "smtp://127.0.0.1:1025",
            "smtp://localhost:1025",
            "smtp://[::1]:1025",
        ] {
            assert_eq!(
                choose(s(url), None, true).unwrap(),
                MailerChoice::Smtp(url.into())
            );
        }
        let remote = "smtp://user:pass@mail.example.com";
        assert_eq!(
            choose(s(remote), None, false).unwrap(),
            MailerChoice::Smtp(remote.into())
        );
    }

    #[test]
    fn smtp_mailer_parses_url_and_from() {
        assert!(SmtpMailer::new("smtp://localhost:1025", "OpsAgent <login@opsagent.dev>").is_ok());
        assert!(SmtpMailer::new("smtp://localhost:1025", "not an address").is_err());
    }
}
