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
    Mail {
        to: to.into(),
        subject: format!("Human review requested: {} · {}", n.kind.as_str(), n.org_name),
        text: format!(
            "Organisation: {} ({})\nRequester: {}\nProduct: {} review, {}\nTarget: {} ({})\n\nNote:\n{}\n",
            n.org_name,
            n.org_slug,
            n.requester,
            n.kind.as_str(),
            price(n.price_cents),
            n.label,
            n.reference,
            n.note.unwrap_or("(none)"),
        ),
        reply_to: Some(n.requester.into()),
        ..Default::default()
    }
}

/// To the requester.
pub fn confirmation(n: &Notice) -> Mail {
    Mail {
        to: n.requester.into(),
        subject: "We got your human review request".into(),
        text: format!(
            "You asked for a {} review of {} for {}.\n\nHarun will reply within 1 business day with a confirmation and invoice. Nothing is changed in your account.\n",
            n.kind.as_str(),
            n.label,
            price(n.price_cents),
        ),
        ..Default::default()
    }
}
