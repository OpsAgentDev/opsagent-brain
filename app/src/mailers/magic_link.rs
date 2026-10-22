use super::Mail;

pub fn magic_link(to: &str, link: &str) -> Mail {
    Mail {
        to: to.into(),
        subject: "Your OpsAgent sign-in link".into(),
        text: format!(
            "Sign in to OpsAgent:\n\n{link}\n\nThe link works once and expires in 15 minutes."
        ),
    }
}

pub fn invite(to: &str, org_name: &str, link: &str) -> Mail {
    Mail {
        to: to.into(),
        subject: format!("You are invited to {org_name} on OpsAgent"),
        text: format!("Join {org_name} on OpsAgent:\n\n{link}\n\nSign in with this email address to accept. The invite expires in 7 days."),
    }
}

pub fn recipient_confirm(to: &str, org_name: &str, link: &str) -> Mail {
    Mail {
        to: to.into(),
        subject: format!("Confirm OpsAgent reports for {org_name}"),
        text: format!("{org_name} wants to send you OpsAgent reports by email. Confirm here:\n\n{link}\n\nIgnore this mail to receive nothing. The link expires in 7 days."),
    }
}
