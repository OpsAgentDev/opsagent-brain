use super::Mail;

pub fn waitlist_confirmation(to: &str) -> Mail {
    let text = "Thanks for joining the OpsAgent waitlist. The alpha opens in small groups, and we'll email you once when your spot is ready. Reply to this email if you have questions.";
    Mail {
        to: to.into(),
        subject: "You're on the OpsAgent waitlist".into(),
        html: Some(super::branded("You're on the waitlist", text, None)),
        text: text.into(),
        ..Default::default()
    }
}

/// The one-time announcement to a waitlist entry that sign-ups are open.
pub fn signups_open(to: &str, web_base_url: &str, idempotency_key: String) -> Mail {
    let link = format!("{}/sign-up", web_base_url.trim_end_matches('/'));
    let text = format!(
        "Sign-ups for OpsAgent are open. You joined the waitlist, so here is your invitation: \
         create your account at {link}"
    );
    let subject = "OpsAgent sign-ups are open";
    Mail {
        to: to.into(),
        subject: subject.into(),
        html: Some(super::branded(subject, &text, Some(("Sign up", &link)))),
        text,
        idempotency_key: Some(idempotency_key),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::waitlist_confirmation;

    #[test]
    fn confirmation_text_has_no_links() {
        let m = waitlist_confirmation("a@b.io");
        assert_eq!(m.to, "a@b.io");
        assert!(!m.text.contains("http"));
    }
}
