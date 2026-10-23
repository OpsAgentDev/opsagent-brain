use chrono::{Duration, Utc};
use opsagent_core::repo::PageRequest;
use opsagent_deliver::repo::{DeliveryFilter, NewDelivery, BRIEFING, FAILED, SENT, WEEKLY};
use uuid::Uuid;

use super::{contract_suite, org_id};

const PAGE: PageRequest = PageRequest {
    after: None,
    limit: 10,
};

fn row<'a>(
    conn: Option<Uuid>,
    run: Uuid,
    key: &'a str,
    kind: &'a str,
    status: &'a str,
) -> NewDelivery<'a> {
    NewDelivery {
        connection_id: conn,
        run_id: run,
        key,
        kind,
        channel: "email",
        target: "a@example.com",
        status,
        external_ref: None,
    }
}

contract_suite! {
    async fn delivery_record_is_idempotent_on_run_and_key(s) {
        let o = org_id(s, "acme").await;
        let (d, run) = (s.deliveries(), Uuid::new_v4());
        d.record(o, row(None, run, "weekly:1", WEEKLY, FAILED)).await.unwrap();
        let first = d.list(o, DeliveryFilter::default(), PAGE).await.unwrap().items;
        assert_eq!((first.len(), first[0].status.as_str(), first[0].sent_at), (1, FAILED, None));
        d.record(o, row(None, run, "weekly:1", WEEKLY, SENT)).await.unwrap();
        let got = d.list(o, DeliveryFilter::default(), PAGE).await.unwrap().items;
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].id, got[0].status.as_str(), got[0].attempts), (first[0].id, SENT, 2));
        let sent = got[0].sent_at.expect("sent_at set");
        // A later rewrite keeps the first send time.
        d.record(o, row(None, run, "weekly:1", WEEKLY, SENT)).await.unwrap();
        assert_eq!(d.get(o, got[0].id).await.unwrap().unwrap().sent_at, Some(sent));
        d.record(o, row(None, run, "weekly:2", WEEKLY, SENT)).await.unwrap();
        d.record(o, row(None, Uuid::new_v4(), "weekly:1", WEEKLY, SENT)).await.unwrap();
        assert_eq!(d.list(o, DeliveryFilter::default(), PAGE).await.unwrap().items.len(), 3);
    }

    async fn deliveries_cross_org_get_is_none(s) {
        let (a, b) = (org_id(s, "a").await, org_id(s, "b").await);
        let d = s.deliveries();
        d.record(a, row(None, Uuid::new_v4(), "k", WEEKLY, SENT)).await.unwrap();
        let id = d.list(a, DeliveryFilter::default(), PAGE).await.unwrap().items[0].id;
        assert!(d.get(a, id).await.unwrap().is_some());
        assert!(d.get(b, id).await.unwrap().is_none());
        assert!(d.list(b, DeliveryFilter::default(), PAGE).await.unwrap().items.is_empty());
        let briefings = DeliveryFilter { kind: Some(BRIEFING.into()), ..Default::default() };
        assert!(d.list(a, briefings, PAGE).await.unwrap().items.is_empty());
    }

    async fn last_success_at_respects_before(s, seed) {
        let o = org_id(s, "acme").await;
        let c = seed.connection(o).await;
        let d = s.deliveries();
        let later = Utc::now() + Duration::hours(1);
        d.record(o, row(Some(c), Uuid::new_v4(), "briefing", BRIEFING, FAILED)).await.unwrap();
        d.record(o, row(Some(c), Uuid::new_v4(), "weekly", WEEKLY, SENT)).await.unwrap();
        assert_eq!(d.last_success_at(o, c, BRIEFING, later).await.unwrap(), None);
        d.record(o, row(Some(c), Uuid::new_v4(), "briefing", BRIEFING, SENT)).await.unwrap();
        let t = d.last_success_at(o, c, BRIEFING, later).await.unwrap().expect("sent");
        assert_eq!(d.last_success_at(o, c, BRIEFING, t).await.unwrap(), None);
        let other = org_id(s, "other").await;
        assert_eq!(d.last_success_at(other, c, BRIEFING, later).await.unwrap(), None);
        let mine = DeliveryFilter { connection_id: Some(c), kind: Some(BRIEFING.into()) };
        assert_eq!(d.list(o, mine, PAGE).await.unwrap().items.len(), 2);
    }
}
