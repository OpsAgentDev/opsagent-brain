use super::Mail;
pub use opsagent_deliver::mail_safe_name;

pub fn magic_link(to: &str, link: &str, code: &str) -> Mail {
    let text = format!(
        "Sign in to OpsAgent:\n\n{link}\n\nOr enter this code: {code}\n\nThe link and code work once and expire in 15 minutes."
    );
    Mail {
        to: to.into(),
        subject: format!("Your OpsAgent sign-in code: {code}"),
        html: Some(opsagent_deliver::render_notice(
            &opsagent_deliver::NoticeEmail {
                preheader: "Sign in to OpsAgent".into(),
                heading: "Sign in to OpsAgent".into(),
                paragraphs: vec![
                    "Enter this code on the sign-in page, or use the button below.".into(),
                ],
                button: Some(("Sign in".into(), link.into())),
                footnote: Some("The link and code work once and expire in 15 minutes.".into()),
                unsubscribe_url: None,
                code: Some(code.into()),
            },
        )),
        text,
        ..Default::default()
    }
}

/// Sent instead of a link when sign-ups are closed to the address's domain.
pub fn signup_closed(to: &str, web_base_url: &str) -> Mail {
    let text = "OpsAgent is in private alpha. Sign-ups are closed for now; join the waitlist at opsagent.dev.";
    Mail {
        to: to.into(),
        subject: "OpsAgent sign-ups are closed for now".into(),
        html: Some(super::branded(
            "Sign-ups are closed for now",
            text,
            Some(("Join the waitlist", web_base_url)),
        )),
        text: text.into(),
        ..Default::default()
    }
}

/// The code that proves the new sign-in address, mailed to that address. No link: the code is
/// entered in the session that asked for it.
pub fn email_change_code(to: &str, code: &str) -> Mail {
    let text = format!(
        "Enter this code in OpsAgent to make this address your sign-in email: {code}\n\nThe code works once and expires in 15 minutes. If you did not ask for this, ignore this email."
    );
    Mail {
        to: to.into(),
        subject: format!("Your OpsAgent email change code: {code}"),
        html: Some(opsagent_deliver::render_notice(
            &opsagent_deliver::NoticeEmail {
                preheader: "Confirm your new sign-in email".into(),
                heading: "Confirm your new sign-in email".into(),
                paragraphs: vec![
                    "Enter this code in OpsAgent to make this address your sign-in email.".into(),
                ],
                button: None,
                footnote: Some(
                    "The code works once and expires in 15 minutes. If you did not ask for this, ignore this email."
                        .into(),
                ),
                unsubscribe_url: None,
                code: Some(code.into()),
            },
        )),
        text,
        ..Default::default()
    }
}

/// Sent instead of a code when the requested address already signs in to an account, so the
/// request answers and takes as long either way.
pub fn email_change_taken(to: &str) -> Mail {
    let text = "Someone asked to make this address their OpsAgent sign-in email, but it already signs in to an OpsAgent account, so nothing was changed. If this was you, sign in with this address instead. If it was not, you can ignore this email.";
    Mail {
        to: to.into(),
        subject: "This address already signs in to OpsAgent".into(),
        html: Some(super::branded(
            "This address already signs in to OpsAgent",
            text,
            None,
        )),
        text: text.into(),
        ..Default::default()
    }
}

/// `j***@example.com`: enough for the owner to recognise the address, not to learn it.
fn masked(email: &str) -> String {
    let (local, domain) = email.split_once('@').unwrap_or((email, ""));
    let first: String = local.chars().take(1).collect();
    format!("{first}***@{domain}")
}

/// Tells the old address that the account now signs in with `new_email` (shown masked).
pub fn email_changed(to: &str, new_email: &str, web_base_url: &str) -> Mail {
    let text = format!(
        "Your OpsAgent sign-in email was changed to {}. If this was not you, contact us through {}/contact.",
        masked(new_email),
        web_base_url.trim_end_matches('/')
    );
    Mail {
        to: to.into(),
        subject: "Your OpsAgent sign-in email was changed".into(),
        html: Some(super::branded(
            "Your sign-in email was changed",
            &text,
            None,
        )),
        text,
        ..Default::default()
    }
}

/// `inviter` is `(name, email)`: the name when there is one, else the address they signed in with.
pub fn invite(to: &str, org_name: &str, inviter: (Option<&str>, &str), link: &str) -> Mail {
    let org_name = &mail_safe_name(org_name);
    let name = inviter.0.map(mail_safe_name).filter(|n| !n.is_empty());
    let inviter = name.unwrap_or_else(|| inviter.1.to_owned());
    let text = format!("{inviter} invited you to join {org_name} on OpsAgent:\n\n{link}\n\nSign in with this email address to accept. The invite expires in 7 days.");
    Mail {
        to: to.into(),
        subject: format!("You are invited to {org_name} on OpsAgent"),
        html: Some(super::branded(
            &format!("You are invited to {org_name}"),
            &text,
            Some(("Accept invite", link)),
        )),
        text,
        ..Default::default()
    }
}

pub fn recipient_confirm(to: &str, org_name: &str, link: &str) -> Mail {
    let org_name = &mail_safe_name(org_name);
    let text = format!("{org_name} wants to send you OpsAgent reports by email. Confirm here:\n\n{link}\n\nIf you do not want these reports, ignore this email and nothing will be sent. The link expires in 7 days.");
    Mail {
        to: to.into(),
        subject: format!("Confirm OpsAgent reports for {org_name}"),
        html: Some(super::branded(
            "Confirm your email",
            &text,
            Some(("Confirm email", link)),
        )),
        text,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{invite, magic_link, recipient_confirm};

    #[test]
    fn magic_link_shows_the_code_in_a_block() {
        let m = magic_link("a@example.com", "https://x.test/l", "123456");
        let html = m.html.unwrap();
        assert!(html.contains("letter-spacing:8px"), "{html}");
        let block = html.split("letter-spacing:8px").nth(1).unwrap();
        assert!(block.contains("123456"), "{block}");
        assert_eq!(
            m.text,
            "Sign in to OpsAgent:\n\nhttps://x.test/l\n\nOr enter this code: 123456\n\nThe link and code work once and expire in 15 minutes."
        );
    }

    #[test]
    fn email_changed_masks_the_new_address() {
        let m = super::email_changed(
            "old@example.com",
            "jane.doe@new.example",
            "https://opsagent.dev/",
        );
        assert_eq!(m.to, "old@example.com");
        assert_eq!(
            m.text,
            "Your OpsAgent sign-in email was changed to j***@new.example. If this was not you, contact us through https://opsagent.dev/contact."
        );
        assert!(!m.html.unwrap().contains("jane.doe"));
    }

    #[test]
    fn invite_mail_uses_the_safe_name() {
        let m = invite(
            "a@example.com",
            &format!("Org\u{202E}{}", "b".repeat(100)),
            (Some("Ann <ann@example.com>"), "ann@example.com"),
            "https://x",
        );
        assert!(!m.subject.contains('\u{202E}') && !m.text.contains(&"b".repeat(60)));
        // An address typed into the name is not one; the one they signed in with stands in
        // for a missing name.
        assert!(
            m.text
                .starts_with("Ann <ann@example[.]com> invited you to join"),
            "{}",
            m.text
        );
        let m = invite(
            "a@example.com",
            "Acme",
            (None, "ann@example.com"),
            "https://x",
        );
        assert!(m
            .text
            .starts_with("ann@example.com invited you to join Acme"));
    }

    #[test]
    fn names_cannot_carry_a_link_into_invites_and_confirmations() {
        let org = "Pay at https://evil.example/now";
        let who = (Some("www.evil.example"), "ann@example.com");
        let ours = "https://opsagent.dev/invite/t";
        for m in [
            invite("a@example.com", org, who, ours),
            recipient_confirm("a@example.com", org, ours),
        ] {
            let html = m.html.unwrap();
            for part in [&m.subject, &m.text, &html] {
                assert!(!part.contains("evil.example"), "{part}");
                assert!(!part.contains("https://evil"), "{part}");
            }
            assert!(m.subject.contains("Pay at https evil[.]example now"));
            assert!(m.text.contains(ours));
        }
    }
}
