use super::Mail;

pub fn waitlist_confirmation(to: &str) -> Mail {
    Mail {
        to: to.into(),
        subject: "You're on the OpsAgent waitlist".into(),
        text: "Thanks for joining the OpsAgent waitlist. The alpha opens in small groups, and we'll email you once when your spot is ready. Reply to this email if you have questions.".into(),
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
