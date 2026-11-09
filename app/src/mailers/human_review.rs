use opsagent_core::human_review::ReviewKind;

use super::Mail;

/// A stored request, with names already passed through `mail_safe_name`.
pub struct Notice<'a> {
    pub org_name: &'a str,
    pub org_slug: &'a str,
    pub requester: &'a str,
    pub kind: ReviewKind,
    pub price_cents: i32,
    pub label: &'a str,
    /// Finding check id and id, or connection id: how the founder finds it.
    pub reference: &'a str,
    /// Body only: free text, never a subject or header.
    pub note: Option<&'a str>,
}

fn price(cents: i32) -> String {
    format!("${}", cents / 100)
}

/// To the fixed `to` (CONTACT_TO), Reply-To the requester. No dashboard link.
pub fn founder_notice(to: &str, n: &Notice) -> Mail {
    founder(to, n, "Human review requested")
}

/// `founder_notice` once Stripe Checkout has been paid.
pub fn founder_paid(to: &str, n: &Notice) -> Mail {
    founder(to, n, "Human review paid")
}

fn founder(to: &str, n: &Notice, heading: &str) -> Mail {
    let text = format!(
            "Organisation: {} ({})\nRequester: {}\nProduct: {} review, {}\nTarget: {} ({})\n\nNote:\n{}\n",
            n.org_name,
            n.org_slug,
            n.requester,
            n.kind.as_str(),
            price(n.price_cents),
            n.label,
            n.reference,
            n.note.unwrap_or("(none)"),
    );
    Mail {
        to: to.into(),
        subject: format!("{heading}: {} · {}", n.kind.as_str(), n.org_name),
        html: Some(super::branded(heading, &text, None)),
        text,
        reply_to: Some(n.requester.into()),
        ..Default::default()
    }
}

/// To the requester.
pub fn confirmation(n: &Notice) -> Mail {
    confirm(
        n,
        "Harun will reply within 1 business day with a confirmation and an invoice.",
        "We got your human review request",
    )
}

/// `confirmation` once Stripe Checkout has been paid.
pub fn paid_confirmation(n: &Notice) -> Mail {
    confirm(
        n,
        "Payment received. Harun will reply within 1 business day.",
        "Payment received for your human review",
    )
}

fn confirm(n: &Notice, next: &str, subject: &str) -> Mail {
    let what = match n.kind {
        ReviewKind::Finding => "a human review of a finding",
        ReviewKind::Account => "a human review of a cloud account",
    };
    let text = format!(
        "You requested {what}: {} ({}).\n\n{next} Nothing is changed in your account.\n",
        n.label,
        price(n.price_cents),
    );
    Mail {
        to: n.requester.into(),
        subject: subject.into(),
        html: Some(super::branded("We got your request", &text, None)),
        text,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(kind: ReviewKind) -> Notice<'static> {
        Notice {
            org_name: "Acme",
            org_slug: "acme",
            requester: "o@example.com",
            kind,
            price_cents: 9900,
            label: "prod",
            reference: "connection x",
            note: None,
        }
    }

    #[test]
    fn confirmations_read_well_and_the_paid_one_has_its_own_subject() {
        let ask = confirmation(&notice(ReviewKind::Account));
        let paid = paid_confirmation(&notice(ReviewKind::Account));
        assert!(ask
            .text
            .starts_with("You requested a human review of a cloud account: prod ($99)."));
        assert!(!ask.text.contains("a account"));
        assert_ne!(ask.subject, paid.subject);
        assert!(paid.text.contains("Payment received."));
        let finding = confirmation(&notice(ReviewKind::Finding));
        assert!(finding.text.contains("a human review of a finding"));
    }
}
