use chrono::{Duration, Utc};
use opsagent_core::{
    repo::{RepoError, RepoResult},
    user::{Email, NewMagicLink, PersonName, SpentLink, User},
};
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
        let g = s.users().find_or_create_github(42, &e, Some("Ada".into()), true).await.unwrap();
        assert_eq!((g.id, g.github_id, g.name.as_deref()), (u.id, Some(42), Some("Ada")));
        // Matched on the GitHub id from now on, whatever the email.
        let again = s.users().find_or_create_github(42, &email("new@example.com"), None, true).await.unwrap();
        assert_eq!((again.id, again.name.as_deref()), (u.id, Some("Ada")));
        let other = s.users().find_or_create_github(43, &email("bob@example.com"), None, true).await.unwrap();
        assert_ne!(other.id, u.id);
        assert_eq!((other.github_id, other.email.as_str()), (Some(43), "bob@example.com"));
        // A second GitHub account with the same email never takes over the linked user.
        let takeover = s.users().find_or_create_github(44, &e, None, true).await;
        assert!(matches!(takeover, Err(RepoError::Conflict("account_exists"))), "{takeover:?}");
        assert_eq!(s.users().get(u.id).await.unwrap().unwrap().github_id, Some(42));
    }

    async fn google_links_existing_email_user_then_matches_sub(s) {
        let e = email("ada@example.com");
        let u = s.users().find_or_create_by_email(&e).await.unwrap();
        let g = s.users().find_or_create_google("sub-1", &e, Some("Ada".into()), true, true).await.unwrap();
        assert_eq!((g.id, g.google_id.as_deref(), g.name.as_deref()), (u.id, Some("sub-1"), Some("Ada")));
        let again = s.users().find_or_create_google("sub-1", &email("new@example.com"), None, false, true).await.unwrap();
        assert_eq!(again.id, u.id);
        let other = s.users().find_or_create_google("sub-2", &email("bob@example.com"), None, true, true).await.unwrap();
        assert_ne!(other.id, u.id);
        assert_eq!((other.google_id.as_deref(), other.email.as_str()), (Some("sub-2"), "bob@example.com"));
    }

    async fn google_refuses_unauthoritative_link_and_other_sub(s) {
        let e = email("eve@corp.com");
        s.users().find_or_create_by_email(&e).await.unwrap();
        let refused = s.users().find_or_create_google("s1", &e, None, false, true).await;
        assert!(matches!(refused, Err(RepoError::Conflict("account_exists"))));
        s.users().find_or_create_google("s1", &e, None, true, true).await.unwrap();
        let other = s.users().find_or_create_google("s2", &e, None, true, true).await;
        assert!(matches!(other, Err(RepoError::Conflict("account_exists"))));
    }

    async fn google_refuses_to_create_for_unmanaged_address(s) {
        let e = email("mallory@corp.com");
        let refused = s.users().find_or_create_google("s1", &e, None, false, true).await;
        assert!(matches!(refused, Err(RepoError::Conflict("google_email_unmanaged"))));
        assert!(s.users().find_by_email(&e).await.unwrap().is_none());
    }

    async fn closed_signup_refuses_create_but_not_match_or_link(s) {
        let closed = |r: RepoResult<User>| matches!(r, Err(RepoError::Conflict("signup_closed")));
        let e = email("new@corp.com");
        assert!(closed(s.users().find_or_create_github(7, &e, None, false).await));
        assert!(closed(s.users().find_or_create_google("g7", &e, None, true, false).await));
        assert!(s.users().find_by_email(&e).await.unwrap().is_none());
        let u = s.users().find_or_create_by_email(&e).await.unwrap();
        // Linking by email, then matching on the provider id, is not a sign-up.
        assert_eq!(s.users().find_or_create_github(7, &e, None, false).await.unwrap().id, u.id);
        assert_eq!(s.users().find_or_create_github(7, &email("o@x.com"), None, false).await.unwrap().id, u.id);
        assert_eq!(s.users().find_or_create_google("g7", &e, None, true, false).await.unwrap().id, u.id);
        assert_eq!(s.users().find_or_create_google("g7", &email("o@x.com"), None, true, false).await.unwrap().id, u.id);
    }

    async fn magic_link_consumed_once_and_not_after_expiry(s) {
        let e = email("ada@example.com");
        let u = s.users().find_or_create_by_email(&e).await.unwrap();
        let now = Utc::now();
        s.users().issue_magic_link(NewMagicLink::new(u.id, &e, "h1", "ch1", now + Duration::minutes(15))).await.unwrap();
        assert_eq!(s.users().consume_magic_link("h1", now).await.unwrap(), Some(SpentLink { user_id: u.id, return_to: None, name: None }));
        assert_eq!(s.users().consume_magic_link("h1", now).await.unwrap(), None);
        s.users().issue_magic_link(NewMagicLink { return_to: Some("/oauth/consent?request_id=x"), ..NewMagicLink::new(u.id, &e, "h2", "ch2", now + Duration::minutes(1)) }).await.unwrap();
        let later = now + Duration::minutes(2);
        assert_eq!(s.users().consume_magic_link("h2", later).await.unwrap(), None);
        assert_eq!(s.users().consume_magic_link("unknown", now).await.unwrap(), None);
        // The stored destination comes back with the user.
        s.users().issue_magic_link(NewMagicLink { return_to: Some("/oauth/consent?request_id=x"), ..NewMagicLink::new(u.id, &e, "h3", "ch3", now + Duration::minutes(1)) }).await.unwrap();
        let back = s.users().consume_magic_link("h3", now).await.unwrap().unwrap();
        assert_eq!((back.user_id, back.return_to.as_deref()), (u.id, Some("/oauth/consent?request_id=x")));
        // The sign-up name rides on the link, in both redeem paths, and is not applied by the repo.
        let ada = PersonName::parse("Ada").unwrap();
        s.users().issue_magic_link(NewMagicLink { name: Some(&ada), ..NewMagicLink::new(u.id, &e, "h4", "ch4", now + Duration::minutes(1)) }).await.unwrap();
        let live = s.users().live_codes(&e, now).await.unwrap();
        assert_eq!(live.iter().find(|l| l.token_hash == "h4").unwrap().name.as_deref(), Some("Ada"));
        let back = s.users().consume_magic_link("h4", now).await.unwrap().unwrap();
        assert_eq!(back.name.as_deref(), Some("Ada"));
        assert_eq!(s.users().get(u.id).await.unwrap().unwrap().name, None);
    }

    async fn live_codes_spend_once_and_die_after_five_wrong(s) {
        let e = email("ada@example.com");
        let u = s.users().find_or_create_by_email(&e).await.unwrap();
        let now = Utc::now();
        let soon = now + Duration::minutes(15);
        s.users().issue_magic_link(NewMagicLink { return_to: Some("/x"), ..NewMagicLink::new(u.id, &e, "t1", "c1", soon) }).await.unwrap();
        let live = s.users().live_codes(&e, now).await.unwrap();
        assert_eq!(live.len(), 1);
        let one = live[0].clone();
        assert_eq!((one.user_id, one.token_hash.as_str(), one.code_hash.as_str(), one.return_to.as_deref()), (u.id, "t1", "c1", Some("/x")));
        // A newer link retires the older code, for that address only: one live code per address.
        let other = email("grace@example.com");
        let g = s.users().find_or_create_by_email(&other).await.unwrap();
        s.users().issue_magic_link(NewMagicLink::new(g.id, &other, "o1", "oc1", soon)).await.unwrap();
        s.users().issue_magic_link(NewMagicLink::new(u.id, &e, "t2", "c2", now + Duration::minutes(1))).await.unwrap();
        let live = s.users().live_codes(&e, now).await.unwrap();
        assert_eq!(live.iter().map(|l| l.token_hash.as_str()).collect::<Vec<_>>(), ["t2"]);
        assert_eq!(s.users().live_codes(&other, now).await.unwrap().len(), 1);
        // Expired rows are not live.
        assert!(s.users().live_codes(&e, now + Duration::minutes(2)).await.unwrap().is_empty());
        // Four wrong guesses keep the code, the fifth disables it; the links still redeem.
        let ids: Vec<_> = live.iter().map(|l| l.id).collect();
        for _ in 0..4 {
            s.users().count_wrong_code(&ids).await.unwrap();
        }
        assert_eq!(s.users().live_codes(&e, now).await.unwrap().len(), 1);
        s.users().count_wrong_code(&ids).await.unwrap();
        assert!(s.users().live_codes(&e, now).await.unwrap().is_empty());
        assert!(s.users().consume_magic_link("t1", now).await.unwrap().is_some());
        assert!(s.users().consume_magic_link("t2", now).await.unwrap().is_some());
        // Spending is once only, and not after expiry.
        s.users().issue_magic_link(NewMagicLink::new(u.id, &e, "t3", "c3", soon)).await.unwrap();
        let id = s.users().live_codes(&e, now).await.unwrap()[0].id;
        assert!(!s.users().spend_code(id, soon).await.unwrap());
        assert!(s.users().spend_code(id, now).await.unwrap());
        assert!(!s.users().spend_code(id, now).await.unwrap());
        assert!(s.users().consume_magic_link("t3", now).await.unwrap().is_none());
    }

    async fn set_name_fills_a_missing_name_only(s) {
        let e = email("ada@example.com");
        let u = s.users().find_or_create_by_email(&e).await.unwrap();
        assert_eq!(u.name, None);
        let ada = PersonName::parse("Ada").unwrap();
        s.users().set_name_if_missing(u.id, &ada).await.unwrap();
        let got = s.users().get(u.id).await.unwrap().unwrap();
        assert_eq!(got.name.as_deref(), Some("Ada"));
        // Never renamed.
        let eve = PersonName::parse("Eve").unwrap();
        s.users().set_name_if_missing(u.id, &eve).await.unwrap();
        assert_eq!(s.users().get(u.id).await.unwrap().unwrap().name.as_deref(), Some("Ada"));
        // An unknown user is a no-op, not an error.
        s.users().set_name_if_missing(Uuid::new_v4(), &eve).await.unwrap();
    }

    async fn set_name_renames_a_named_user(s) {
        let u = s.users().find_or_create_by_email(&email("ada@example.com")).await.unwrap();
        let other = s.users().find_or_create_by_email(&email("eve@example.com")).await.unwrap();
        for name in ["Ada", "Ada Lovelace"] {
            s.users().set_name(u.id, &PersonName::parse(name).unwrap()).await.unwrap();
            assert_eq!(s.users().get(u.id).await.unwrap().unwrap().name.as_deref(), Some(name));
        }
        assert_eq!(s.users().get(other.id).await.unwrap().unwrap().name, None);
        // An unknown user is a no-op, not an error.
        s.users().set_name(Uuid::new_v4(), &PersonName::parse("Eve").unwrap()).await.unwrap();
    }

    async fn accept_terms_keeps_the_first_time(s) {
        let u = s.users().find_or_create_by_email(&email("ada@example.com")).await.unwrap();
        assert_eq!(u.terms_accepted_at, None);
        // Whole seconds: Postgres keeps microseconds, not nanoseconds.
        let first = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        s.users().accept_terms(u.id, first).await.unwrap();
        assert_eq!(s.users().get(u.id).await.unwrap().unwrap().terms_accepted_at, Some(first));
        s.users().accept_terms(u.id, first + Duration::hours(1)).await.unwrap();
        assert_eq!(s.users().get(u.id).await.unwrap().unwrap().terms_accepted_at, Some(first));
        // An unknown user is a no-op, not an error.
        s.users().accept_terms(Uuid::new_v4(), first).await.unwrap();
    }

    async fn email_change_is_no_sign_in_link_and_set_email_respects_other_users(s) {
        let (old, new) = (email("ada@example.com"), email("ada@new.example"));
        let u = s.users().find_or_create_by_email(&old).await.unwrap();
        let now = Utc::now();
        let soon = now + Duration::minutes(15);
        s.users().issue_magic_link(NewMagicLink::new(u.id, &old, "l1", "lc1", soon)).await.unwrap();
        s.users().issue_email_change(u.id, &new, "e1", "ec1", soon).await.unwrap();
        // Not a sign-in code for either address, and the sign-in code stays live.
        assert!(s.users().live_codes(&new, now).await.unwrap().is_empty());
        assert_eq!(s.users().live_codes(&old, now).await.unwrap().len(), 1);
        let live = s.users().live_email_changes(u.id, now).await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!((live[0].token_hash.as_str(), live[0].code_hash.as_str(), &live[0].new_email), ("e1", "ec1", &new));
        // Only the owner's, only until expiry, and a newer one retires the older.
        assert!(s.users().live_email_changes(Uuid::new_v4(), now).await.unwrap().is_empty());
        assert!(s.users().live_email_changes(u.id, soon).await.unwrap().is_empty());
        s.users().issue_email_change(u.id, &new, "e2", "ec2", soon).await.unwrap();
        let live = s.users().live_email_changes(u.id, now).await.unwrap();
        assert_eq!(live.iter().map(|l| l.token_hash.as_str()).collect::<Vec<_>>(), ["e2"]);
        assert_eq!(s.users().live_codes(&old, now).await.unwrap().len(), 1);
        // The fifth wrong guess disables it.
        for _ in 0..5 {
            s.users().count_wrong_code(&[live[0].id]).await.unwrap();
        }
        assert!(s.users().live_email_changes(u.id, now).await.unwrap().is_empty());
        // Spent once.
        s.users().issue_email_change(u.id, &new, "e3", "ec3", soon).await.unwrap();
        let id = s.users().live_email_changes(u.id, now).await.unwrap()[0].id;
        assert!(s.users().spend_code(id, now).await.unwrap());
        assert!(!s.users().spend_code(id, now).await.unwrap());
        assert!(s.users().live_email_changes(u.id, now).await.unwrap().is_empty());

        // Another user's address is refused and nothing moves.
        let other = s.users().find_or_create_by_email(&email("eve@example.com")).await.unwrap();
        let taken = s.users().set_email(u.id, &other.email).await;
        assert!(matches!(taken, Err(RepoError::Conflict("email_taken"))), "{taken:?}");
    }

    async fn set_email_moves_the_user_and_drops_their_unspent_links(s) {
        let (old, new) = (email("ada@example.com"), email("ada@new.example"));
        let u = s.users().find_or_create_by_email(&old).await.unwrap();
        s.users().find_or_create_github(42, &old, None, true).await.unwrap();
        let other = s.users().find_or_create_by_email(&email("eve@example.com")).await.unwrap();
        let now = Utc::now();
        let soon = now + Duration::minutes(15);
        s.users().issue_magic_link(NewMagicLink::new(u.id, &old, "l1", "lc1", soon)).await.unwrap();
        s.users().issue_magic_link(NewMagicLink::new(other.id, &other.email, "o1", "oc1", soon)).await.unwrap();
        s.users().issue_email_change(u.id, &new, "e1", "ec1", soon).await.unwrap();
        s.users().set_email(u.id, &new).await.unwrap();
        let got = s.users().get(u.id).await.unwrap().unwrap();
        assert_eq!((&got.email, got.github_id), (&new, Some(42)));
        assert_eq!(s.users().find_by_email(&new).await.unwrap().map(|x| x.id), Some(u.id));
        assert!(s.users().find_by_email(&old).await.unwrap().is_none());
        // What was mailed to the old address, and the pending change, are gone; others' stay.
        assert!(s.users().consume_magic_link("l1", now).await.unwrap().is_none());
        assert!(s.users().live_email_changes(u.id, now).await.unwrap().is_empty());
        assert!(s.users().consume_magic_link("o1", now).await.unwrap().is_some());
        // The provider id still finds the account; the old address is free for a new one.
        assert_eq!(s.users().find_or_create_github(42, &old, None, true).await.unwrap().id, u.id);
        assert_ne!(s.users().find_or_create_by_email(&old).await.unwrap().id, u.id);
        // Setting the same address again, or an unknown user, is not an error.
        s.users().set_email(u.id, &new).await.unwrap();
        s.users().set_email(Uuid::new_v4(), &email("x@example.com")).await.unwrap();
    }
}
