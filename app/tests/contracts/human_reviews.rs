use chrono::{Duration, Utc};
use opsagent_core::human_review::{NewReviewRequest, ReviewKind};
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
}
