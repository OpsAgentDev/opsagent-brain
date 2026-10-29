use chrono::{Duration, Utc};
use opsagent_brain::actions::uow::Repos;
use opsagent_core::{
    org::{NewOrganisation, Organisation, Role},
    repo::RepoError,
    user::{Email, User},
};
use uuid::Uuid;

use super::contract_suite;

fn new_org(slug: &str) -> NewOrganisation {
    NewOrganisation {
        id: Uuid::new_v4(),
        slug: slug.into(),
        name: format!("Org {slug}"),
        timezone: "UTC".into(),
        kek_version: 1,
        wrapped_dek: vec![1, 2, 3],
    }
}

async fn user(s: &dyn Repos, email: &str) -> User {
    let e = Email::parse(email).unwrap();
    s.users().find_or_create_by_email(&e).await.unwrap()
}

async fn org(s: &dyn Repos, slug: &str) -> Organisation {
    s.orgs().insert(new_org(slug)).await.unwrap()
}

contract_suite! {
    async fn insert_then_membership_by_slug(s) {
        let (owner, stranger) = (user(s, "o@example.com").await, user(s, "x@example.com").await);
        let o = org(s, "acme").await;
        assert_eq!((o.slug.as_str(), o.wrapped_dek.as_deref()), ("acme", Some(&[1u8, 2, 3][..])));
        assert_eq!(s.orgs().get(o.id).await.unwrap().as_ref(), Some(&o));
        let m = s.orgs().add_member(o.id, owner.id, Role::Owner).await.unwrap();
        let (found, fm) = s.orgs().membership("acme", owner.id).await.unwrap().unwrap();
        assert_eq!((found.id, fm.id, fm.role), (o.id, m.id, Role::Owner));
        assert_eq!(fm.email, owner.email);
        assert!(s.orgs().membership("acme", stranger.id).await.unwrap().is_none());
        assert!(s.orgs().membership("nope", owner.id).await.unwrap().is_none());
        let mine = s.orgs().list_for_user(owner.id).await.unwrap();
        assert_eq!(mine.iter().map(|(o, r)| (o.id, *r)).collect::<Vec<_>>(), [(o.id, Role::Owner)]);
        assert!(s.orgs().list_for_user(stranger.id).await.unwrap().is_empty());
    }

    async fn duplicate_slug_is_conflict(s) {
        org(s, "acme").await;
        let err = s.orgs().insert(new_org("acme")).await.unwrap_err();
        assert!(matches!(err, RepoError::Conflict("slug")), "{err:?}");
        // The conflict leaves an enclosing transaction usable.
        let tx = s.begin().await.unwrap();
        assert!(tx.orgs().insert(new_org("acme")).await.is_err());
        let b = tx.orgs().insert(new_org("acme-2")).await.unwrap();
        tx.commit().await.unwrap();
        assert!(s.orgs().get(b.id).await.unwrap().is_some());
    }

    async fn soft_deleted_org_hidden_from_membership_and_list(s) {
        let u = user(s, "o@example.com").await;
        let o = org(s, "acme").await;
        s.orgs().add_member(o.id, u.id, Role::Owner).await.unwrap();
        assert!(!s.orgs().is_deleted(o.id).await.unwrap());
        s.orgs().soft_delete(o.id, Utc::now()).await.unwrap();
        assert!(s.orgs().is_deleted(o.id).await.unwrap());
        assert!(s.orgs().is_deleted(Uuid::new_v4()).await.unwrap());
        assert!(s.orgs().get(o.id).await.unwrap().unwrap().deleted_at.is_some());
        assert!(s.orgs().membership("acme", u.id).await.unwrap().is_none());
        assert!(s.orgs().list_for_user(u.id).await.unwrap().is_empty());
        let gone = s.orgs().soft_delete(Uuid::new_v4(), Utc::now()).await;
        assert!(matches!(gone, Err(RepoError::NotFound)));
    }

    async fn duplicate_member_is_conflict(s) {
        let u = user(s, "m@example.com").await;
        let o = org(s, "acme").await;
        s.orgs().add_member(o.id, u.id, Role::Member).await.unwrap();
        let err = s.orgs().add_member(o.id, u.id, Role::Owner).await.unwrap_err();
        assert!(matches!(err, RepoError::Conflict("member")), "{err:?}");
        assert_eq!(s.orgs().members(o.id).await.unwrap().len(), 1);
    }

    async fn owner_count_counts_only_owners(s) {
        let (a, b, c) = (user(s, "a@example.com").await, user(s, "b@example.com").await,
            user(s, "c@example.com").await);
        let (o, other) = (org(s, "acme").await, org(s, "other").await);
        s.orgs().add_member(o.id, a.id, Role::Owner).await.unwrap();
        s.orgs().add_member(o.id, b.id, Role::Owner).await.unwrap();
        s.orgs().add_member(o.id, c.id, Role::Member).await.unwrap();
        s.orgs().add_member(other.id, c.id, Role::Owner).await.unwrap();
        assert_eq!(s.orgs().owner_count(o.id).await.unwrap(), 2);
        assert_eq!(s.orgs().members(o.id).await.unwrap().len(), 3);
        assert_eq!(s.orgs().owner_count(other.id).await.unwrap(), 1);
    }

    async fn remove_member_in_other_org_is_false(s) {
        let u = user(s, "m@example.com").await;
        let (a, b) = (org(s, "a").await, org(s, "b").await);
        let m = s.orgs().add_member(a.id, u.id, Role::Member).await.unwrap();
        let soon = Utc::now() + Duration::days(7);
        s.orgs().insert_invite(a.id, &u.email, Role::Owner, "h-pending", soon).await.unwrap();
        assert!(!s.orgs().remove_member(b.id, m.id).await.unwrap());
        assert_eq!(s.orgs().members(a.id).await.unwrap().len(), 1);
        assert!(s.orgs().remove_member(a.id, m.id).await.unwrap());
        assert!(s.orgs().members(a.id).await.unwrap().is_empty());
        // The removed user cannot rejoin through a still-pending invite.
        assert!(s.orgs().take_invite("h-pending", Utc::now()).await.unwrap().is_none());
    }

    async fn take_invite_once(s) {
        let o = org(s, "acme").await;
        let e = Email::parse("Invitee@Example.com").unwrap();
        let now = Utc::now();
        let inv = s.orgs().insert_invite(o.id, &e, Role::Member, "h1", now + Duration::days(7))
            .await.unwrap();
        assert_eq!((inv.organisation_id, inv.email.as_str(), inv.role), (o.id, "invitee@example.com", Role::Member));
        assert!(inv.accepted_at.is_none());
        let taken = s.orgs().take_invite("h1", now).await.unwrap().unwrap();
        assert_eq!(taken.id, inv.id);
        assert!(taken.accepted_at.is_some());
        assert!(s.orgs().take_invite("h1", now).await.unwrap().is_none());
        s.orgs().insert_invite(o.id, &e, Role::Member, "h2", now - Duration::seconds(1))
            .await.unwrap();
        assert!(s.orgs().take_invite("h2", now).await.unwrap().is_none());
        assert!(s.orgs().take_invite("unknown", now).await.unwrap().is_none());
    }

    async fn pending_invites_counts_live_ones(s) {
        let o = org(s, "pend").await;
        let e = opsagent_core::user::Email::parse("p@example.com").unwrap();
        let now = Utc::now();
        assert_eq!(s.orgs().pending_invites(o.id, now).await.unwrap(), 0);
        s.orgs().insert_invite(o.id, &e, Role::Member, "p1", now + Duration::days(7)).await.unwrap();
        s.orgs().insert_invite(o.id, &e, Role::Member, "p2", now + Duration::days(7)).await.unwrap();
        s.orgs().insert_invite(o.id, &e, Role::Member, "p3", now - Duration::seconds(1)).await.unwrap();
        assert_eq!(s.orgs().pending_invites(o.id, now).await.unwrap(), 2);
        s.orgs().take_invite("p1", now).await.unwrap().unwrap();
        assert_eq!(s.orgs().pending_invites(o.id, now).await.unwrap(), 1);
        let other = org(s, "pend-other").await;
        assert_eq!(s.orgs().pending_invites(other.id, now).await.unwrap(), 0);
    }

    async fn rollback_discards_writes(s) {
        let tx = s.begin().await.unwrap();
        let o = tx.orgs().insert(new_org("acme")).await.unwrap();
        assert!(tx.orgs().get(o.id).await.unwrap().is_some());
        drop(tx);
        assert!(s.orgs().get(o.id).await.unwrap().is_none());
        let tx = s.begin().await.unwrap();
        let o = tx.orgs().insert(new_org("acme")).await.unwrap();
        tx.commit().await.unwrap();
        assert!(s.orgs().get(o.id).await.unwrap().is_some());
    }
}
