use std::sync::Arc;

use chrono::Duration;
use opsagent_core::{
    audit::AuditEntry,
    connection::ConnectionStatus,
    human_review::{NewReviewRequest, ReviewKind},
    org::{Member, Organisation},
    repo::Clock,
};
use uuid::Uuid;

use super::offer;
use crate::{
    actions::{uow::UnitOfWork, DAY_SECS},
    error::{AppError, AppResult},
    mailers::{
        human_review::{confirmation, founder_notice, Notice},
        magic_link::mail_safe_name,
        Mailer,
    },
};

/// Requests per organisation per 24 hours.
pub const PER_DAY: u64 = 5;
const NOTE_MAX: usize = 2000;

pub struct ReviewInput {
    pub kind: String,
    pub finding_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    pub note: Option<String>,
}

/// Records a review request for owner `actor` and mails the founder and the requester. A
/// failed send is logged and does not fail the request.
pub struct RequestReview {
    uow: Arc<dyn UnitOfWork>,
    mailer: Arc<dyn Mailer>,
    clock: Arc<dyn Clock>,
    contact_to: String,
}

fn invalid(detail: &str) -> AppError {
    AppError::Invalid(detail.into())
}

impl RequestReview {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        mailer: Arc<dyn Mailer>,
        clock: Arc<dyn Clock>,
        contact_to: String,
    ) -> Self {
        Self {
            uow,
            mailer,
            clock,
            contact_to,
        }
    }

    pub async fn run(
        &self,
        org: &Organisation,
        actor: &Member,
        input: ReviewInput,
    ) -> AppResult<Uuid> {
        let kind = ReviewKind::parse(&input.kind).ok_or_else(|| invalid("unknown kind"))?;
        let note = input
            .note
            .map(|n| n.trim().to_owned())
            .filter(|n| !n.is_empty());
        if note.as_ref().is_some_and(|n| n.chars().count() > NOTE_MAX) {
            return Err(invalid("note is over 2000 characters"));
        }
        let target = match (kind, input.finding_id, input.connection_id) {
            (ReviewKind::Finding, Some(id), _) | (ReviewKind::Account, _, Some(id)) => id,
            (ReviewKind::Finding, ..) => return Err(invalid("finding_id is required")),
            (ReviewKind::Account, ..) => return Err(invalid("connection_id is required")),
        };
        let now = self.clock.now();
        let tx = self.uow.begin().await?;
        // (label, what the founder needs to find it, audit target)
        let (label, reference, audit_target) = match kind {
            ReviewKind::Finding => {
                let f = tx.findings().get(org.id, target).await?;
                let f = f.ok_or(AppError::NotFound)?;
                let r = format!("finding {} ({target})", f.key.check_id);
                (f.title, r, "finding")
            }
            ReviewKind::Account => {
                let c = tx.connections().get(org.id, target).await?;
                let c = c.ok_or(AppError::NotFound)?;
                if c.status == ConnectionStatus::Disconnected {
                    return Err(invalid("the connection is disconnected"));
                }
                let name = c.display_name.unwrap_or_else(|| c.provider.clone());
                (name, format!("connection {target}"), "connection")
            }
        };
        let label = mail_safe_name(&label);
        let recent = tx
            .human_reviews()
            .count_since(org.id, now - Duration::days(1));
        if recent.await? >= PER_DAY {
            return Err(AppError::RateLimited {
                detail: "Too many review requests today. Try again tomorrow.".into(),
                retry_after_secs: DAY_SECS as u64,
            });
        }
        let price_cents = offer(kind).price_cents;
        let id = tx
            .human_reviews()
            .insert(&NewReviewRequest {
                organisation_id: org.id,
                kind,
                finding_id: (kind == ReviewKind::Finding).then_some(target),
                connection_id: (kind == ReviewKind::Account).then_some(target),
                target_label: label.clone(),
                note: note.clone(),
                price_cents,
                requested_by: actor.user_id,
                requester_email: actor.email.as_str().to_owned(),
                created_at: now,
            })
            .await?;
        let entry = AuditEntry::member(
            Some(org.id),
            actor.user_id,
            "human_review.request",
            Some((audit_target, target.to_string())),
        );
        tx.audit().record(entry).await?;
        tx.commit().await?;

        let notice = Notice {
            org_name: &mail_safe_name(&org.name),
            org_slug: &org.slug,
            requester: actor.email.as_str(),
            kind,
            price_cents,
            label: &label,
            reference: &reference,
            note: note.as_deref(),
        };
        for mail in [
            founder_notice(&self.contact_to, &notice),
            confirmation(&notice),
        ] {
            if self.mailer.send(mail).await.is_err() {
                tracing::error!(error_code = "mail_failed", "human review mail failed");
            }
        }
        Ok(id)
    }
}
