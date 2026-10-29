use chrono::{DateTime, Duration, Utc};
use opsagent_brain::actions::uow::Repos;
use opsagent_core::{
    billing::{BillingStatus as B, OrgBilling, SubscriptionState, Tier},
    connection::{ConnectionStatus as S, Verified},
    repo::RepoError,
};
use uuid::Uuid;

use super::connections::{connection, org};
use super::contract_suite;

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
}

fn sub(status: B, quantity: i32) -> SubscriptionState {
    SubscriptionState {
        subscription_id: "sub_1".into(),
        status,
        tier: Some(Tier::Team),
        quantity,
        trial_ends_at: Some(at(14 * 86_400)),
        current_period_start: Some(at(0)),
        current_period_end: Some(at(30 * 86_400)),
    }
}

/// A connection on account `account`, moved to `status` (through `verifying`); connected once
/// unless it stays `verifying`.
async fn conn_in(s: &dyn Repos, o: Uuid, account: &str, status: S) -> Uuid {
    let c = connection(s, o, account).await;
    let repo = s.connections();
    assert!(repo
        .cas_status(o, c.id, S::Pending, S::Verifying, None)
        .await
        .unwrap());
    let v = Verified {
        account: Some(account.into()),
        first_connected_at: (status != S::Verifying).then(Utc::now),
        ..Default::default()
    };
    repo.record_verified(o, c.id, v).await.unwrap();
    if status != S::Verifying {
        assert!(repo
            .cas_status(o, c.id, S::Verifying, status, None)
            .await
            .unwrap());
    }
    c.id
}

contract_suite! {
    async fn billing_defaults_then_customer(s) {
        let o = org(s).await;
        assert_eq!(s.billing().billing(o).await.unwrap(), OrgBilling::default());
        s.billing().set_customer(o, "cus_1").await.unwrap();
        let b = s.billing().billing(o).await.unwrap();
        assert_eq!((b.customer_id.as_deref(), b.status), (Some("cus_1"), B::None));
        let missing = s.billing().billing(Uuid::new_v4()).await;
        assert!(matches!(missing, Err(RepoError::NotFound)), "{missing:?}");
        let missing = s.billing().set_customer(Uuid::new_v4(), "cus_2").await;
        assert!(matches!(missing, Err(RepoError::NotFound)), "{missing:?}");
    }

    async fn apply_subscription_ignores_stale_event(s) {
        let (o, other) = (org(s).await, org(s).await);
        let repo = s.billing();
        assert!(repo.apply_subscription(o, &sub(B::Trialing, 1), at(10)).await.unwrap());
        assert!(repo.apply_subscription(o, &sub(B::Active, 2), at(20)).await.unwrap());
        // An older event delivered late changes nothing.
        assert!(!repo.apply_subscription(o, &sub(B::Trialing, 1), at(15)).await.unwrap());
        let b = repo.billing(o).await.unwrap();
        assert_eq!((b.status, b.subscription), (B::Active, Some(sub(B::Active, 2))));
        // Same second: applied (Stripe stamps whole seconds).
        assert!(repo.apply_subscription(o, &sub(B::Active, 3), at(20)).await.unwrap());
        assert_eq!(repo.billing(o).await.unwrap().subscription.unwrap().quantity, 3);
        // Scoped to the organisation.
        assert_eq!(repo.billing(other).await.unwrap(), OrgBilling::default());
        let gone = repo.apply_subscription(Uuid::new_v4(), &sub(B::Active, 1), at(30)).await;
        assert!(matches!(gone, Err(RepoError::NotFound)), "{gone:?}");
    }

    async fn past_due_since_kept_and_paused_survives_past_due(s) {
        let o = org(s).await;
        let repo = s.billing();
        repo.apply_subscription(o, &sub(B::PastDue, 1), at(10)).await.unwrap();
        repo.apply_subscription(o, &sub(B::PastDue, 1), at(20)).await.unwrap();
        assert_eq!(repo.billing(o).await.unwrap().past_due_since, Some(at(10)));
        let mut paused = sub(B::Paused, 1);
        repo.apply_subscription(o, &paused, at(30)).await.unwrap();
        repo.apply_subscription(o, &sub(B::PastDue, 1), at(40)).await.unwrap();
        let b = repo.billing(o).await.unwrap();
        assert_eq!((b.status, b.past_due_since), (B::Paused, Some(at(10))));
        paused.status = B::Active;
        repo.apply_subscription(o, &paused, at(50)).await.unwrap();
        let b = repo.billing(o).await.unwrap();
        assert_eq!((b.status, b.past_due_since), (B::Active, None));
    }

    async fn record_event_dedupes(s) {
        let repo = s.billing();
        let id = format!("evt_{}", Uuid::new_v4());
        assert!(repo.record_event(&id, "customer.subscription.updated").await.unwrap());
        assert!(!repo.record_event(&id, "customer.subscription.updated").await.unwrap());
        assert!(repo.record_event(&format!("{id}_2"), "invoice.paid").await.unwrap());
    }

    async fn billable_count_includes_disconnected_this_period(s) {
        let (o, other) = (org(s).await, org(s).await);
        for (account, status) in [("1", S::Connected), ("2", S::Degraded), ("3", S::Revoked)] {
            conn_in(s, o, account, status).await;
        }
        // Not billable: still verifying, blocked, or someone else's.
        conn_in(s, o, "4", S::Verifying).await;
        conn_in(s, o, "5", S::Blocked).await;
        connection(s, o, "pending").await;
        // Abandoned before it ever connected, then disconnected in the period.
        let abandoned = conn_in(s, o, "8", S::Verifying).await;
        assert!(s.connections().cas_status(o, abandoned, S::Verifying, S::Disconnected, None).await.unwrap());
        conn_in(s, other, "6", S::Connected).await;
        let gone = conn_in(s, o, "7", S::Connected).await;
        assert!(s.connections().cas_status(o, gone, S::Connected, S::Disconnected, None).await.unwrap());
        let d = s.connections().get(o, gone).await.unwrap().unwrap();
        let when = d.disconnected_at.expect("disconnected_at stamped");
        let count = |start| s.billing().billable_count(o, start);
        assert_eq!(count(when - Duration::hours(1)).await.unwrap(), 4);
        assert_eq!(count(when).await.unwrap(), 4);
        assert_eq!(count(when + Duration::hours(1)).await.unwrap(), 3);
        // Reconnecting the same account in the period is not counted twice.
        conn_in(s, o, "7", S::Connected).await;
        assert_eq!(count(when - Duration::hours(1)).await.unwrap(), 4);
    }
}
