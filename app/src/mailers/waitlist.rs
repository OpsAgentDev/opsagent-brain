use super::Mail;

/// The double opt-in mail: the link opens a page that confirms on a click (mail scanners open
/// links on their own, so the page never confirms on load).
pub fn waitlist_verify(to: &str, link: &str) -> Mail {
    let text = format!(
        "Confirm your email to join the OpsAgent waitlist: {link}\n\nWe'll email you once when \
         sign-ups open. If you didn't ask to join, ignore this email and you won't hear from us."
    );
    let subject = "Confirm your email for the OpsAgent waitlist";
    Mail {
        to: to.into(),
        subject: subject.into(),
        html: Some(super::branded(
            "Confirm your email",
            &text,
            Some(("Confirm my email", link)),
        )),
        text,
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
    use super::waitlist_verify;

    #[test]
    fn verify_mail_carries_the_link_once_in_text_and_as_the_button() {
        let link = "https://web.test/waitlist/verify#tok";
        let m = waitlist_verify("a@b.io", link);
        assert_eq!(m.to, "a@b.io");
        assert_eq!(m.text.matches(link).count(), 1);
        assert!(m.html.unwrap().contains("Confirm my email"));
    }
}
