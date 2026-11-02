//! Paid human reviews (human-review.md): an owner asks the founder to review a finding or a
//! whole connected account. Stored and audited, then two emails; invoiced outside the product.
mod list;
mod request;

pub use list::ListReviews;
pub use request::{RequestReview, ReviewInput};

use opsagent_core::human_review::ReviewKind;

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
        description: "Harun reviews the finding and its evidence and sends a written fix plan for your setup.",
    },
    Offer {
        kind: ReviewKind::Account,
        price_cents: 49900,
        title: "Account review",
        description: "Harun reviews the whole connected account and sends a prioritised report.",
    },
];

pub fn offer(kind: ReviewKind) -> &'static Offer {
    OFFERS
        .iter()
        .find(|o| o.kind == kind)
        .expect("every kind has an offer")
}
