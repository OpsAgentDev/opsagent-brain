use chrono::{Duration, Utc};
use opsagent_core::repo::RepoError;
use opsagent_deliver::repo::{NewRecipient, Suppression, ACTIVE, PENDING};

use super::{contract_suite, org_id};

fn email(e: &str, confirm: Option<(&str, Duration)>) -> NewRecipient {
    NewRecipient {
        connection_id: None,
        email: e.into(),
        member_id: None,
        confirm: confirm.map(|(h, d)| (h.into(), Utc::now() + d)),
    }
}

contract_suite! {
    async fn recipient_duplicate_is_conflict(s) {
        let o = org_id(s, "acme").await;
        let r = s.recipients().insert(o, email("a@example.com", None)).await.unwrap();
        assert_eq!((r.organisation_id, r.status.as_str()), (o, ACTIVE));
        let err = s.recipients().insert(o, email("a@example.com", None)).await.unwrap_err();
        assert!(matches!(err, RepoError::Conflict("recipient")), "{err:?}");
        // The conflict leaves an enclosing transaction usable.
        let tx = s.begin().await.unwrap();
        assert!(tx.recipients().insert(o, email("a@example.com", None)).await.is_err());
        tx.recipients().insert(o, email("b@example.com", None)).await.unwrap();
        tx.commit().await.unwrap();
        let other = org_id(s, "other").await;
        s.recipients().insert(other, email("a@example.com", None)).await.unwrap();
        let page = opsagent_core::repo::PageRequest { after: None, limit: 10 };
        assert_eq!(s.recipients().list(o, page).await.unwrap().items.len(), 2);
        assert_eq!(s.recipients().for_connection(o, None).await.unwrap().len(), 2);
    }

    async fn confirm_token_once(s) {
        let o = org_id(s, "acme").await;
        let day = Duration::days(1);
        let r = s.recipients().insert(o, email("a@example.com", Some(("h1", day)))).await.unwrap();
        assert_eq!(r.status, PENDING);
        assert!(s.recipients().for_connection(o, None).await.unwrap().is_empty());
        let done = s.recipients().confirm("h1", Utc::now()).await.unwrap().unwrap();
        assert_eq!((done.id, done.status.as_str()), (r.id, ACTIVE));
        assert!(s.recipients().confirm("h1", Utc::now()).await.unwrap().is_none());
        let late = email("b@example.com", Some(("h2", Duration::seconds(-1))));
        s.recipients().insert(o, late).await.unwrap();
        assert!(s.recipients().confirm("h2", Utc::now()).await.unwrap().is_none());
        let to = s.recipients().for_connection(o, None).await.unwrap();
        assert_eq!(to.iter().map(|r| r.id).collect::<Vec<_>>(), [r.id]);
        assert!(s.recipients().unsubscribe(o, r.id, Utc::now()).await.unwrap());
        assert!(!s.recipients().unsubscribe(o, r.id, Utc::now()).await.unwrap());
        assert!(s.recipients().for_connection(o, None).await.unwrap().is_empty());
        let row = s.recipients().by_id_unscoped(r.id).await.unwrap().unwrap();
        assert!(row.unsubscribed_at.is_some());
        let other = org_id(s, "other").await;
        assert!(!s.recipients().delete(other, r.id).await.unwrap());
        assert!(s.recipients().delete(o, r.id).await.unwrap());
        assert!(s.recipients().by_id_unscoped(r.id).await.unwrap().is_none());
    }

    async fn suppression_global_and_per_org_visible_to_org(s) {
        let (a, b) = (org_id(s, "a").await, org_id(s, "b").await);
        let r = s.recipients();
        r.suppress(None, "h", Suppression::Unsubscribed).await.unwrap();
        r.suppress(Some(a), "h2", Suppression::Ignored).await.unwrap();
        assert_eq!(r.suppressed(a, "h").await.unwrap(), [Suppression::Unsubscribed]);
        assert_eq!(r.suppressed(b, "h").await.unwrap(), [Suppression::Unsubscribed]);
        assert_eq!(r.suppressed(a, "h2").await.unwrap(), [Suppression::Ignored]);
        assert!(r.suppressed(b, "h2").await.unwrap().is_empty());
        // An unsubscribe replaces a confirm block; a confirm block never downgrades it.
        r.suppress(None, "h3", Suppression::ConfirmBlocked).await.unwrap();
        assert_eq!(r.suppressed(b, "h3").await.unwrap(), [Suppression::ConfirmBlocked]);
        r.suppress(None, "h3", Suppression::Unsubscribed).await.unwrap();
        r.suppress(None, "h3", Suppression::ConfirmBlocked).await.unwrap();
        assert_eq!(r.suppressed(b, "h3").await.unwrap(), [Suppression::Unsubscribed]);
    }

    async fn ids_by_email_maps_lowercased_addresses_in_the_org(s) {
        let o = org_id(s, "acme").await;
        let a = s.recipients().insert(o, email("a@example.com", None)).await.unwrap();
        let other = org_id(s, "other").await;
        s.recipients().insert(other, email("b@example.com", None)).await.unwrap();
        let ask = vec!["a@example.com".to_owned(), "b@example.com".to_owned()];
        let got = s.recipients().ids_by_email(o, &ask).await.unwrap();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got.get("a@example.com"), Some(&a.id));
        assert!(s.recipients().ids_by_email(o, &[]).await.unwrap().is_empty());
    }

    async fn ids_by_email_ignores_case_and_the_oldest_row_wins(s, seed) {
        let o = org_id(s, "acme").await;
        let conn = seed.connection(o).await;
        let first = s.recipients().insert(o, email("A@Example.com", None)).await.unwrap();
        let mut later = email("a@example.com", None);
        later.connection_id = Some(conn);
        let second = s.recipients().insert(o, later).await.unwrap();
        assert_ne!(first.id, second.id);
        let got = s.recipients().ids_by_email(o, &["a@example.com".to_owned()]).await.unwrap();
        assert_eq!(got.get("a@example.com"), Some(&first.id), "{got:?}");
    }

    async fn move_member_email_follows_the_user_in_every_organisation_only(s, seed) {
        use opsagent_core::{org::Role, user::Email};
        let mail = |e: &str| Email::parse(e).unwrap();
        let ada = s.users().find_or_create_by_email(&mail("ada@example.com")).await.unwrap();
        let eve = s.users().find_or_create_by_email(&mail("eve@example.com")).await.unwrap();
        let (a, b) = (org_id(s, "acme").await, org_id(s, "other").await);
        let conn = seed.connection(a).await;
        let ada_a = s.orgs().add_member(a, ada.id, Role::Owner).await.unwrap().id;
        let ada_b = s.orgs().add_member(b, ada.id, Role::Member).await.unwrap().id;
        let eve_a = s.orgs().add_member(a, eve.id, Role::Member).await.unwrap().id;
        let row = |address: &str, member: Option<uuid::Uuid>, connection_id| NewRecipient {
            connection_id,
            email: address.into(),
            member_id: member,
            confirm: None,
        };
        let r = s.recipients();
        let wide = r.insert(a, row("ada@example.com", Some(ada_a), None)).await.unwrap();
        let on_conn = r.insert(a, row("ada@example.com", Some(ada_a), Some(conn))).await.unwrap();
        let in_b = r.insert(b, row("ada@example.com", Some(ada_b), None)).await.unwrap();
        let eves = r.insert(a, row("eve@example.com", Some(eve_a), None)).await.unwrap();
        // Not a member row: the same address typed in by hand in another organisation stays.
        let c = org_id(s, "third").await;
        let typed = r.insert(c, row("ada@example.com", None, None)).await.unwrap();
        // The new address is already a recipient on the connection in `a`: that row wins there.
        let held = r.insert(a, row("Ada@New.example", None, Some(conn))).await.unwrap();

        r.move_member_email(ada.id, "ada@new.example").await.unwrap();
        let at = |id| async move { r.by_id_unscoped(id).await.unwrap().map(|x| x.email) };
        assert_eq!(at(wide.id).await.as_deref(), Some("ada@new.example"));
        assert_eq!(at(in_b.id).await.as_deref(), Some("ada@new.example"));
        assert_eq!(at(on_conn.id).await, None);
        assert_eq!(at(held.id).await.as_deref(), Some("Ada@New.example"));
        assert_eq!(at(eves.id).await.as_deref(), Some("eve@example.com"));
        assert_eq!(at(typed.id).await.as_deref(), Some("ada@example.com"));
        // Again is a no-op.
        r.move_member_email(ada.id, "ada@new.example").await.unwrap();
        assert_eq!(at(wide.id).await.as_deref(), Some("ada@new.example"));
    }
}
