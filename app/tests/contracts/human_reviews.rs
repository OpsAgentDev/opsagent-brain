use chrono::{Duration, Utc};
use opsagent_core::human_review::{NewReviewRequest, Payment, ReviewKind};
use uuid::Uuid;

use super::{contract_suite, org_id};

fn new(org: Uuid, label: &str, age: Duration) -> NewReviewRequest {
    NewReviewRequest {
        organisation_id: org,
        kind: ReviewKind::Finding,
        finding_id: Some(Uuid::new_v4()),
        connection_id: None,
        target_label: label.into(),
        note: Some("please look".into()),
        price_cents: 4900,
        requested_by: Uuid::new_v4(),
        requester_email: "owner@example.com".into(),
        payment: Payment::Invoice,
        created_at: Utc::now() - age,
    }
}

contract_suite! {
    async fn review_insert_list_and_tenant_scope(s) {
        let (a, b) = (org_id(s, "acme").await, org_id(s, "other").await);
        let r = new(a, "Open bucket", Duration::zero());
        let id = s.human_reviews().insert(&r).await.unwrap();
        let got = s.human_reviews().list(a, 10).await.unwrap();
        assert_eq!(got.len(), 1);
        let g = &got[0];
        assert_eq!((g.id, g.kind, g.finding_id, g.connection_id), (id, ReviewKind::Finding, r.finding_id, None));
        assert_eq!((g.target_label.as_str(), g.note.as_deref(), g.price_cents), ("Open bucket", Some("please look"), 4900));
        assert_eq!((g.requested_by, g.requester_email.as_str()), (r.requested_by, "owner@example.com"));
        assert!(s.human_reviews().list(b, 10).await.unwrap().is_empty());
        assert_eq!(s.human_reviews().count_since(b, Utc::now() - Duration::days(1)).await.unwrap(), 0);
    }

    async fn review_count_since_and_order(s) {
        let o = org_id(s, "acme").await;
        for (label, hours) in [("old", 30), ("mid", 5), ("new", 1)] {
            s.human_reviews().insert(&new(o, label, Duration::hours(hours))).await.unwrap();
        }
        let day_ago = Utc::now() - Duration::hours(24);
        assert_eq!(s.human_reviews().count_since(o, day_ago).await.unwrap(), 2);
        let labels = |v: Vec<opsagent_core::human_review::ReviewRequest>| {
            v.into_iter().map(|r| r.target_label).collect::<Vec<_>>()
        };
        assert_eq!(labels(s.human_reviews().list(o, 10).await.unwrap()), ["new", "mid", "old"]);
        assert_eq!(labels(s.human_reviews().list(o, 2).await.unwrap()), ["new", "mid"]);
    }

    async fn review_account_kind_roundtrip(s) {
        let o = org_id(s, "acme").await;
        let mut r = new(o, "prod account", Duration::zero());
        (r.kind, r.finding_id, r.connection_id, r.note) = (ReviewKind::Account, None, Some(Uuid::new_v4()), None);
        s.human_reviews().insert(&r).await.unwrap();
        let g = s.human_reviews().list(o, 1).await.unwrap().remove(0);
        assert_eq!((g.kind, g.finding_id, g.connection_id, g.note), (ReviewKind::Account, None, r.connection_id, None));
    }

    async fn review_mark_paid_once_and_only_pending(s) {
        let (a, b) = (org_id(s, "acme").await, org_id(s, "other").await);
        let now = chrono::DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap();
        let mut r = new(a, "Open bucket", Duration::zero());
        let invoiced = s.human_reviews().insert(&r).await.unwrap();
        r.payment = Payment::Pending;
        let id = s.human_reviews().insert(&r).await.unwrap();
        let g = s.human_reviews().list(a, 10).await.unwrap();
        assert!(g.iter().all(|x| x.paid_at.is_none()));
        assert_eq!(g.iter().find(|x| x.id == id).unwrap().payment, Payment::Pending);
        // Another org, an unknown id and an invoiced row are never marked.
        assert_eq!(s.human_reviews().mark_paid(b, id, now).await.unwrap(), None);
        assert_eq!(s.human_reviews().mark_paid(a, Uuid::new_v4(), now).await.unwrap(), None);
        assert_eq!(s.human_reviews().mark_paid(a, invoiced, now).await.unwrap(), None);
        let paid = s.human_reviews().mark_paid(a, id, now).await.unwrap().expect("flipped");
        assert_eq!((paid.id, paid.payment, paid.target_label.as_str()), (id, Payment::Paid, "Open bucket"));
        assert_eq!(paid.paid_at, Some(now));
        assert_eq!((paid.requester_email.as_str(), paid.note.as_deref()), ("owner@example.com", Some("please look")));
        assert_eq!(s.human_reviews().mark_paid(a, id, now).await.unwrap(), None);
        let g = s.human_reviews().list(a, 10).await.unwrap();
        let listed = g.iter().find(|x| x.id == id).unwrap();
        assert_eq!((listed.payment, listed.paid_at), (Payment::Paid, paid.paid_at));
        assert_eq!(g.iter().find(|x| x.id == invoiced).unwrap().payment, Payment::Invoice);
    }
}
