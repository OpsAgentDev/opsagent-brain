use chrono::{Duration, Utc};
use opsagent_core::user::Email;
use uuid::Uuid;

use super::contract_suite;

fn email(s: &str) -> Email {
    Email::parse(s).unwrap()
}

contract_suite! {
    async fn find_or_create_by_email_is_idempotent(s) {
        let e = email("ada@example.com");
        let a = s.users().find_or_create_by_email(&e).await.unwrap();
        let b = s.users().find_or_create_by_email(&e).await.unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.email, e);
        assert_eq!(s.users().find_by_email(&e).await.unwrap().map(|u| u.id), Some(a.id));
        assert_eq!(s.users().get(a.id).await.unwrap().map(|u| u.id), Some(a.id));
        assert!(s.users().find_by_email(&email("bob@example.com")).await.unwrap().is_none());
        assert!(s.users().get(Uuid::new_v4()).await.unwrap().is_none());
    }

    async fn github_links_existing_email_user(s) {
        let e = email("ada@example.com");
        let u = s.users().find_or_create_by_email(&e).await.unwrap();
        let g = s.users().find_or_create_github(42, &e, Some("Ada".into())).await.unwrap();
        assert_eq!((g.id, g.github_id, g.name.as_deref()), (u.id, Some(42), Some("Ada")));
        // Matched on the GitHub id from now on, whatever the email.
        let again = s.users().find_or_create_github(42, &email("new@example.com"), None).await.unwrap();
        assert_eq!((again.id, again.name.as_deref()), (u.id, Some("Ada")));
        let other = s.users().find_or_create_github(43, &email("bob@example.com"), None).await.unwrap();
        assert_ne!(other.id, u.id);
        assert_eq!((other.github_id, other.email.as_str()), (Some(43), "bob@example.com"));
    }

    async fn magic_link_consumed_once_and_not_after_expiry(s) {
        let e = email("ada@example.com");
        let u = s.users().find_or_create_by_email(&e).await.unwrap();
        let now = Utc::now();
        s.users().issue_magic_link(u.id, &e, "h1", None, now + Duration::minutes(15)).await.unwrap();
        assert_eq!(s.users().consume_magic_link("h1", now).await.unwrap(), Some((u.id, None)));
        assert_eq!(s.users().consume_magic_link("h1", now).await.unwrap(), None);
        s.users().issue_magic_link(u.id, &e, "h2", Some("/oauth/consent?request_id=x"), now + Duration::minutes(1)).await.unwrap();
        let later = now + Duration::minutes(2);
        assert_eq!(s.users().consume_magic_link("h2", later).await.unwrap(), None);
        assert_eq!(s.users().consume_magic_link("unknown", now).await.unwrap(), None);
        // The stored destination comes back with the user.
        s.users().issue_magic_link(u.id, &e, "h3", Some("/oauth/consent?request_id=x"), now + Duration::minutes(1)).await.unwrap();
        let back = s.users().consume_magic_link("h3", now).await.unwrap();
        assert_eq!(back, Some((u.id, Some("/oauth/consent?request_id=x".into()))));
    }
}
