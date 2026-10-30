//! Owner emails about Dashboard AI: plain text, each owner through `MailGuard::may_deliver`.
use std::sync::Arc;

use uuid::Uuid;

use crate::{
    actions::{recipients::MailGuard, uow::UnitOfWork},
    error::AppResult,
    mailers::{Mail, Mailer},
};

pub struct Notices {
    uow: Arc<dyn UnitOfWork>,
    mailer: Arc<dyn Mailer>,
    guard: Arc<MailGuard>,
}

/// One email to the owners.
pub(super) struct Notice {
    pub subject: String,
    pub text: String,
}

impl Notices {
    pub fn new(uow: Arc<dyn UnitOfWork>, mailer: Arc<dyn Mailer>, guard: Arc<MailGuard>) -> Self {
        Self { uow, mailer, guard }
    }

    /// Mails `n` to the owners the first time `key` is noted for the organisation.
    pub(super) async fn once(&self, org: Uuid, key: &str, n: Notice) -> AppResult<()> {
        if self.uow.ai().notice_once(org, key).await? {
            self.tell(org, key, n).await?;
        }
        Ok(())
    }

    /// Mails `n` to every owner who may get mail. A failed send is logged and not retried:
    /// these are courtesy notices, and `key` keeps a retried call from resending.
    pub(super) async fn tell(&self, org: Uuid, key: &str, n: Notice) -> AppResult<()> {
        for o in self.uow.recipients().owners(org).await? {
            if !self.guard.may_deliver(org, &o.email, true).await? {
                continue;
            }
            let mail = Mail {
                to: o.email,
                subject: n.subject.clone(),
                text: n.text.clone(),
                idempotency_key: Some(format!("ai:{org}:{key}:{}", o.id)),
                ..Default::default()
            };
            if self.mailer.send(mail).await.is_err() {
                tracing::warn!(error_code = "mail_failed", notice = %key, "ai notice mail failed");
            }
        }
        Ok(())
    }
}
