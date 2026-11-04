//! Paid human reviews (human-review.md): an owner asks the founder to review a finding or a
//! whole connected account. Stored and audited, then paid through Stripe Checkout (the webhook
//! queues a notice job that sends two emails), or without Stripe two emails at once and an
//! invoice.
mod list;
mod notice;
mod request;

pub use list::ListReviews;
pub use notice::{enqueue_notice, DeliverReviewNotice};
pub use request::{RequestReview, ReviewInput};

use opsagent_core::human_review::ReviewKind;

use crate::mailers::{Mail, Mailer};

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

pub struct HumanReviews {
    pub request: RequestReview,
    pub list: ListReviews,
    pub deliver_notice: DeliverReviewNotice,
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
