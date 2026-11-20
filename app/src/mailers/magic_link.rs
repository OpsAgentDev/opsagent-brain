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
