use std::sync::Arc;

use axum::http::StatusCode;
use chrono::Duration;
use opsagent_core::{audit::AuditEntry, repo::Clock, repo::RepoError, user::Email};
use opsagent_deliver::repo::{self as repo, RecipientRow};
use uuid::Uuid;

use super::MailGuard;
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
    mailers::{magic_link as mail, Mailer},
    tokens::{hash_token, new_token},
};

const CONFIRM_DAYS: i64 = 7;

/// Who to add: exactly one of `email` (confirms by mail) or `member_id`.
pub struct NewRecipient {
    pub email: Option<String>,
    pub member_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
}

/// Adds a recipient for owner `actor`; mails the confirm link (`{web}/recipients/confirm?token=`)
/// to an email recipient unless `MailGuard` refuses (answered as if sent either way). 409
/// `recipient_exists` for the same email and connection.
pub struct CreateRecipient {
    uow: Arc<dyn UnitOfWork>,
    guard: Arc<MailGuard>,
    mailer: Arc<dyn Mailer>,
    web_base_url: String,
    clock: Arc<dyn Clock>,
}

impl CreateRecipient {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        guard: Arc<MailGuard>,
        mailer: Arc<dyn Mailer>,
        web_base_url: &str,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let web_base_url = web_base_url.trim_end_matches('/').to_owned();
        Self {
            uow,
            guard,
            mailer,
            web_base_url,
            clock,
        }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        actor: Uuid,
        new: NewRecipient,
    ) -> AppResult<RecipientRow> {
        let (email, member_id) = match (new.email.as_deref(), new.member_id) {
            (Some(e), None) => (
                Email::parse(e).ok_or_else(|| invalid("invalid email"))?,
                None,
            ),
            (None, Some(m)) => (self.member_email(organisation_id, m).await?, Some(m)),
            _ => return Err(invalid("give exactly one of email or member_id")),
        };
        let email = email.as_str().to_lowercase();
        if let Some(c) = new.connection_id {
            let conns = self.uow.connections();
            conns
                .get(organisation_id, c)
                .await?
                .ok_or(AppError::NotFound)?;
        }
        let token = member_id.is_none().then(new_token);
        let expires = self.clock.now() + Duration::days(CONFIRM_DAYS);
        let new = repo::NewRecipient {
            connection_id: new.connection_id,
            email: email.clone(),
            member_id,
            confirm: token.as_deref().map(|t| (hash_token(t), expires)),
        };
        let tx = self.uow.begin().await?;
        let row = tx
            .recipients()
            .insert(organisation_id, new)
            .await
            .map_err(|e| match e {
                RepoError::Conflict(_) => AppError::Refused {
                    status: StatusCode::CONFLICT,
                    code: "recipient_exists",
                    detail: "This recipient is already added.".into(),
                },
                e => e.into(),
            })?;
        let target = Some(("recipient", row.id.to_string()));
        let entry = AuditEntry::member(Some(organisation_id), actor, "recipient.create", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        if let Some(token) = token {
            self.send_confirm(organisation_id, &email, &token).await?;
        }
        Ok(row)
    }

    /// The member's email, for a member of `organisation_id`.
    async fn member_email(&self, organisation_id: Uuid, member_id: Uuid) -> AppResult<Email> {
        let members = self.uow.orgs().members(organisation_id).await?;
        let m = members.into_iter().find(|m| m.id == member_id);
        m.map(|m| m.email)
            .ok_or_else(|| invalid("member_id is not a member of this organisation"))
    }

    async fn send_confirm(&self, organisation_id: Uuid, email: &str, token: &str) -> AppResult<()> {
        if !self.guard.may_send_confirm(organisation_id, email).await? {
            return Ok(());
        }
        let org = self.uow.orgs().get(organisation_id).await?;
        let name = org.map(|o| o.name).unwrap_or_default();
        let link = format!("{}/recipients/confirm?token={token}", self.web_base_url);
        let sent = self
            .mailer
            .send(mail::recipient_confirm(email, &name, &link));
        if sent.await.is_err() {
            tracing::error!(error_code = "mail_failed", "recipient confirm mail failed");
        }
        Ok(())
    }
}

fn invalid(detail: &str) -> AppError {
    AppError::Invalid(detail.into())
}

#[cfg(test)]
mod tests {
    use opsagent_core::org::Role;

    use super::*;
    use crate::{
        actions::{recipients::test_support::*, uow::Repos},
        adapters::memory::MemStore,
        mailers::CaptureMailer,
    };

    #[tokio::test]
    async fn member_recipient_needs_no_confirm() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        let org = org(&store, "Acme").await;
        let owner = member(&store, org, "owner@example.com", Role::Owner).await;
        let m = member(&store, org, "Dev@Example.com", Role::Member).await;
        let new = NewRecipient {
            email: None,
            member_id: Some(m.id),
            connection_id: None,
        };
        let row = create(&store, &mail)
            .run(org, owner.user_id, new)
            .await
            .unwrap();
        assert_eq!(
            (row.email.as_str(), row.status.as_str(), row.member_id),
            ("dev@example.com", "active", Some(m.id))
        );
        assert!(mail.sent().is_empty());
        let actions: Vec<_> = store
            .audit_entries()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions, ["recipient.create"]);
        // Someone outside the organisation is refused.
        let stranger = NewRecipient {
            email: None,
            member_id: Some(Uuid::new_v4()),
            connection_id: None,
        };
        let err = create(&store, &mail)
            .run(org, owner.user_id, stranger)
            .await;
        assert!(matches!(err, Err(AppError::Invalid(_))), "{err:?}");
        let listed = store.recipients().list(org, PAGE).await.unwrap();
        assert_eq!(listed.items.len(), 1);
    }
}
