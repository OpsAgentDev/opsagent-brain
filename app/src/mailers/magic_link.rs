use super::Mail;
use opsagent_core::org::is_bidi;

pub fn magic_link(to: &str, link: &str, code: &str) -> Mail {
    let text = format!(
        "Sign in to OpsAgent:\n\n{link}\n\nOr enter this code: {code}\n\nThe link and code work once and expire in 15 minutes."
    );
    Mail {
        to: to.into(),
        subject: format!("Your OpsAgent sign-in code: {code}"),
        html: Some(super::branded(
            "Sign in to OpsAgent",
            &format!(
                "Or enter this code:\n\n{code}\n\nThe link and code work once and expire in 15 minutes."
            ),
            Some(("Sign in", link)),
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

pub fn invite(to: &str, org_name: &str, link: &str) -> Mail {
    let org_name = &mail_safe_name(org_name);
    let text = format!("Join {org_name} on OpsAgent:\n\n{link}\n\nSign in with this email address to accept. The invite expires in 7 days.");
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

/// An organisation name for mail text: control and bidi-override characters dropped (no header
/// injection or spoofed line breaks), at most 60 characters.
pub fn mail_safe_name(raw: &str) -> String {
    const MAX: usize = 60;
    let clean: String = raw
        .chars()
        .map(|c| if c.is_control() || is_bidi(c) { ' ' } else { c })
        .collect();
    let clean = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.chars().count() > MAX {
        format!("{}…", clean.chars().take(MAX - 1).collect::<String>())
    } else {
        clean
    }
}

pub fn recipient_confirm(to: &str, org_name: &str, link: &str) -> Mail {
    let org_name = &mail_safe_name(org_name);
    let text = format!("{org_name} wants to send you OpsAgent reports by email. Confirm here:\n\n{link}\n\nIgnore this mail to receive nothing. The link expires in 7 days.");
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
    use super::{invite, mail_safe_name};

    #[test]
    fn org_name_is_capped_and_has_no_control_chars() {
        let n = mail_safe_name(&format!("Evil\r\nBcc: x@y.z\u{202E}{}", "a".repeat(100)));
        assert!(!n.contains(['\r', '\n', '\u{202E}']), "{n}");
        assert_eq!(n.chars().count(), 60);
        assert_eq!(mail_safe_name("  Acme  Ltd "), "Acme Ltd");
    }

    #[test]
    fn invite_mail_uses_the_safe_name() {
        let m = invite(
            "a@example.com",
            &format!("Org\u{202E}{}", "b".repeat(100)),
            "https://x",
        );
        assert!(!m.subject.contains('\u{202E}') && !m.text.contains(&"b".repeat(60)));
    }
}
