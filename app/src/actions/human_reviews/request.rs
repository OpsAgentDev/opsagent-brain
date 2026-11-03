use std::sync::Arc;

use chrono::Duration;
use opsagent_core::{
    audit::AuditEntry,
    billing::{BillingProvider, ReviewCheckout},
    connection::ConnectionStatus,
    human_review::{NewReviewRequest, Payment, ReviewKind},
    repo::Clock,
};
use uuid::Uuid;

use super::{offer, send_all};
use crate::{
    actions::{
        billing::{create_customer, provider_failed, BillingSettings},
        orgs::OrgScope,
        uow::UnitOfWork,
        DAY_SECS,
    },
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

/// A stored request: its id and what its mails say.
struct Stored {
    id: Uuid,
    kind: ReviewKind,
    price_cents: i32,
    label: String,
    reference: String,
    note: Option<String>,
}

/// Records a review request for the scope's owner. With Stripe configured it is `pending` and
/// the caller gets a Checkout URL (the webhook mails once paid; 502 `billing_unavailable` if
/// Stripe fails). Without Stripe it is `invoice` and the founder and requester are mailed now;
/// a failed send is logged and does not fail the request.
pub struct RequestReview {
    uow: Arc<dyn UnitOfWork>,
    mailer: Arc<dyn Mailer>,
    provider: Arc<dyn BillingProvider>,
    clock: Arc<dyn Clock>,
    settings: BillingSettings,
    contact_to: String,
}

fn invalid(detail: &str) -> AppError {
    AppError::Invalid(detail.into())
}

impl RequestReview {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        mailer: Arc<dyn Mailer>,
        provider: Arc<dyn BillingProvider>,
        clock: Arc<dyn Clock>,
        settings: BillingSettings,
        contact_to: String,
    ) -> Self {
        Self {
            uow,
            mailer,
            provider,
            clock,
            settings,
            contact_to,
        }
    }

    /// The request id and, when paid through Stripe, its Checkout URL.
    pub async fn run(
        &self,
        scope: &OrgScope,
        input: ReviewInput,
    ) -> AppResult<(Uuid, Option<String>)> {
        if self.settings.stripe_configured {
            let r = self.record(scope, input, Payment::Pending).await?;
            let url = self.checkout(scope, &r).await?;
            return Ok((r.id, Some(url)));
        }
        let r = self.record(scope, input, Payment::Invoice).await?;
        let org = &scope.organisation;
        let notice = Notice {
            org_name: &mail_safe_name(&org.name),
            org_slug: &org.slug,
            requester: scope.member.email.as_str(),
            kind: r.kind,
            price_cents: r.price_cents,
            label: &r.label,
            reference: &r.reference,
            note: r.note.as_deref(),
        };
        let mails = [
            founder_notice(&self.contact_to, &notice),
            confirmation(&notice),
        ];
        send_all(&*self.mailer, mails).await;
        Ok((r.id, None))
    }

    async fn checkout(&self, scope: &OrgScope, r: &Stored) -> AppResult<String> {
        let org = scope.organisation.id;
        let uow = &*self.uow;
        let customer_id = match uow.billing().billing(org).await?.customer_id {
            Some(c) => c,
            None => create_customer(uow, &*self.provider, scope).await?,
        };
        let page = |q: &str| {
            let base = self.settings.web_base_url.trim_end_matches('/');
            format!("{base}/settings/human-review?{q}")
        };
        let req = ReviewCheckout {
            organisation_id: org,
            customer_id,
            review_request_id: r.id,
            kind: r.kind,
            price_cents: r.price_cents,
            success_url: page("paid=1"),
            cancel_url: page("canceled=1"),
        };
        let idem = format!("human_review:{}", r.id);
        let url = self.provider.human_review_session(&req, &idem).await;
        url.map_err(provider_failed)
    }

    /// Validates, rate-limits, stores and audits one request.
    async fn record(
        &self,
        scope: &OrgScope,
        input: ReviewInput,
        payment: Payment,
    ) -> AppResult<Stored> {
        let (org, actor) = (&scope.organisation, &scope.member);
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
                payment,
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
        Ok(Stored {
            id,
            kind,
            price_cents,
            label,
            reference,
            note,
        })
    }
}
