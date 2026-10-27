use super::Mail;

/// What the visitor submitted, already validated.
pub struct ContactForward<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub topic: &'a str,
    pub message: &'a str,
}

const SUBJECT_NAME_MAX: usize = 80;

/// `[Contact/General] name`: topic capitalised, line breaks in the name collapsed to one space,
/// the name cut to 80 characters.
fn subject(topic: &str, name: &str) -> String {
    let mut t = topic.chars();
    let topic: String = t
        .next()
        .map(|c| c.to_uppercase().chain(t).collect())
        .unwrap_or_default();
    let name = name
        .split(['\r', '\n'])
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let name: String = name.chars().take(SUBJECT_NAME_MAX).collect();
    format!("[Contact/{topic}] {name}")
}

/// Mail to the fixed `to` (CONTACT_TO) with the visitor as Reply-To. Plain text only.
pub fn contact_forward(to: &str, c: &ContactForward) -> Mail {
    Mail {
        to: to.into(),
        subject: subject(c.topic, c.name),
        text: format!(
            "Name: {}\nEmail: {}\nTopic: {}\n\n{}\n",
            c.name, c.email, c.topic, c.message
        ),
        reply_to: Some(c.email.into()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd<'a>(name: &'a str) -> ContactForward<'a> {
        ContactForward {
            name,
            email: "v@x.io",
            topic: "security",
            message: "Hello there, audit please.",
        }
    }

    #[test]
    fn goes_to_the_fixed_address_with_visitor_as_reply_to() {
        let m = contact_forward("info@opsagent.dev", &fwd("Ann"));
        assert_eq!(m.to, "info@opsagent.dev");
        assert_eq!(m.reply_to.as_deref(), Some("v@x.io"));
        assert_eq!(m.html, None);
        for part in ["Ann", "v@x.io", "security", "Hello there, audit please."] {
            assert!(m.text.contains(part), "{part}");
        }
    }

    #[test]
    fn subject_strips_line_breaks_and_caps_the_name() {
        assert_eq!(
            contact_forward("t@x.io", &fwd("Ann\r\nEvil")).subject,
            "[Contact/Security] Ann Evil"
        );
        let long = "n".repeat(120);
        let s = contact_forward("t@x.io", &fwd(&long)).subject;
        assert_eq!(s, format!("[Contact/Security] {}", "n".repeat(80)));
    }
}
