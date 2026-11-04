//! Paid human reviews (human-review.md): an owner asks the founder to review a finding or a
//! whole connected account. Stored and audited, then paid through Stripe Checkout (two emails
//! once the webhook sees it paid), or without Stripe two emails at once and an invoice.
mod list;
mod request;

pub use list::ListReviews;
pub use request::{RequestReview, ReviewInput};

use opsagent_core::{
    human_review::{ReviewKind, ReviewRequest},
    org::Organisation,
};

use crate::mailers::{
    human_review::{founder_paid, paid_confirmation, Notice},
    magic_link::mail_safe_name,
    Mail, Mailer,
};

/// Sends each mail; a failed send is logged. True when every mail went out.
async fn send_all(mailer: &dyn Mailer, mails: [Mail; 2]) -> bool {
    let mut all = true;
    for mail in mails {
        if mailer.send(mail).await.is_err() {
            tracing::error!(error_code = "mail_failed", "human review mail failed");
            all = false;
        }
    }
    all
}

/// The founder and requester mails for a request the webhook just marked paid. False when a
/// send failed: the webhook then rolls back so Stripe redelivers and the mail is retried.
pub(crate) async fn mail_paid(
    mailer: &dyn Mailer,
    contact_to: &str,
    org: &Organisation,
    r: &ReviewRequest,
    check_id: Option<String>,
) -> bool {
    let reference = match (r.finding_id, r.connection_id) {
        (Some(id), _) => match check_id {
            Some(c) => format!("finding {c} ({id})"),
            None => format!("finding {id}"),
        },
        (_, Some(id)) => format!("connection {id}"),
        _ => String::new(),
    };
    let notice = Notice {
        org_name: &mail_safe_name(&org.name),
        org_slug: &org.slug,
        requester: &r.requester_email,
        kind: r.kind,
        price_cents: r.price_cents,
        // Stored through `mail_safe_name` when asked.
        label: &r.target_label,
        reference: &reference,
        note: r.note.as_deref(),
    };
    let mails = [
        founder_paid(contact_to, &notice),
        paid_confirmation(&notice),
    ];
    send_all(mailer, mails).await
}

pub struct HumanReviews {
    pub request: RequestReview,
    pub list: ListReviews,
}

/// What a product costs and gives; web never hardcodes these.
pub struct Offer {
    pub kind: ReviewKind,
    pub price_cents: i32,
    pub title: &'static str,
    pub description: &'static str,
}

pub const OFFERS: [Offer; 2] = [
    Offer {
        kind: ReviewKind::Finding,
        price_cents: 9900,
        title: "Finding review",
        description: "Harun reviews the finding and its evidence and sends a written fix plan for your setup. Pay securely with Stripe. Harun replies within 1 business day.",
    },
    Offer {
        kind: ReviewKind::Account,
        price_cents: 49900,
        title: "Account review",
        description: "Harun reviews the whole connected account and sends a prioritised report. Pay securely with Stripe. Harun replies within 1 business day.",
    },
];

pub fn offer(kind: ReviewKind) -> &'static Offer {
    OFFERS
        .iter()
        .find(|o| o.kind == kind)
        .expect("every kind has an offer")
}
