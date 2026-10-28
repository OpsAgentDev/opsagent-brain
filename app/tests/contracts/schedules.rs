use chrono::{Duration, Utc};
use opsagent_brain::actions::uow::{Repos, UnitOfWork};
use uuid::Uuid;

use super::{contract_suite, org_id, Seed};

/// Ids of everything due a week and a day from now, i.e. all enabled schedules.
async fn all_due(s: &dyn Repos) -> Vec<Uuid> {
    s.schedules()
        .due_ids(Utc::now() + Duration::days(8))
        .await
        .unwrap()
}

contract_suite! {
    async fn due_runs_are_queued_runs_with_a_due_marker(s) {
        use opsagent_core::run::RunKey;
        let (live, gone) = (org_id(s, "live").await, org_id(s, "gone").await);
        // Whole seconds, so the markers survive Postgres' microsecond timestamps unchanged.
        let now = chrono::DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap();
        let mut ids = Vec::new();
        for (org, minutes) in [(live, 2), (gone, 1), (live, -5)] {
            let key = RunKey {
                organisation_id: Some(org),
                connection_id: None,
                job_type: "verify".into(),
                scheduled_at: now - Duration::minutes(minutes),
            };
            let id = s.ledger().create_run(key).await.unwrap().run.id;
            let marker = now - Duration::minutes(minutes);
            s.ledger().schedule_retry(id, 0, marker).await.unwrap();
            ids.push((id, marker));
        }
        s.orgs().soft_delete(gone, now).await.unwrap();
        let due = s.schedules().due_runs(now).await.unwrap();
        let got: Vec<_> = due.iter().map(|d| (d.run_id, d.marker, d.organisation_deleted)).collect();
        // Earliest marker first; the run marked in the future is not due.
        assert_eq!(got, [(ids[0].0, ids[0].1, false), (ids[1].0, ids[1].1, true)]);
        assert!(due.iter().all(|d| d.job_type == "verify"));
    }

    async fn advance_none_disables(s, seed) {
        let o = org_id(s, "acme").await;
        let c = seed.connection(o).await;
        let now = Utc::now();
        s.schedules().create_defaults(o, c, (None, None), now).await.unwrap();
        // Idempotent: 5 per connection and the organisation's weekly summary.
        s.schedules().create_defaults(o, c, (None, None), now).await.unwrap();
        let ids = all_due(s).await;
        assert_eq!(ids.len(), 6);
        assert!(s.schedules().due_ids(now).await.unwrap().is_empty());
        s.schedules().advance(ids[0], None).await.unwrap();
        assert!(!all_due(s).await.contains(&ids[0]));
        let far = now + Duration::days(30);
        s.schedules().advance(ids[1], Some(far)).await.unwrap();
        assert!(!all_due(s).await.contains(&ids[1]));
        assert!(s.schedules().due_ids(far).await.unwrap().contains(&ids[1]));
        assert_eq!(s.schedules().disable_for_org(o).await.unwrap(), 6);
        assert!(s.schedules().due_ids(far).await.unwrap().is_empty());
    }

    async fn due_ids_excludes_deleted_orgs(s, seed) {
        let o = org_id(s, "acme").await;
        let c = seed.connection(o).await;
        let now = Utc::now();
        s.schedules().create_defaults(o, c, (None, None), now).await.unwrap();
        let ids = all_due(s).await;
        let soon = now + Duration::days(8);
        let (key, cron, tz) = s.schedules().lock_due(ids[0], soon).await.unwrap().unwrap();
        assert_eq!((key.organisation_id, tz.as_str()), (Some(o), "UTC"));
        assert!(!cron.is_empty());
        assert!(s.schedules().lock_due(ids[0], now).await.unwrap().is_none());
        s.orgs().soft_delete(o, now).await.unwrap();
        assert!(all_due(s).await.is_empty());
        assert!(s.schedules().lock_due(ids[0], soon).await.unwrap().is_none());
    }
}

/// Pg only: MemStore is single-threaded test support and takes no row locks.
#[tokio::test]
#[serial_test::serial]
async fn lock_due_skips_row_locked_by_other_tx() {
    let store = super::pg().await;
    let o = org_id(&store, "acme").await;
    let c = super::PgSeed::new().await.connection(o).await;
    let now = Utc::now();
    store
        .schedules()
        .create_defaults(o, c, (None, None), now)
        .await
        .unwrap();
    let soon = now + Duration::days(8);
    let id = all_due(&store).await[0];
    // The test pool has one connection; the second transaction needs its own.
    let uri = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let other =
        opsagent_brain::adapters::db::Pg::new(sea_orm::Database::connect(uri).await.unwrap());
    let held = store.begin().await.unwrap();
    assert!(held.schedules().lock_due(id, soon).await.unwrap().is_some());
    let tx = other.begin().await.unwrap();
    assert!(tx.schedules().lock_due(id, soon).await.unwrap().is_none());
    drop(tx);
    drop(held);
    let tx = other.begin().await.unwrap();
    assert!(tx.schedules().lock_due(id, soon).await.unwrap().is_some());
}

/// MemStore only: on Pg a connected row needs a verified account id, and the backfill is
/// covered by the scheduler tick tests.
#[tokio::test]
async fn mem_backfill_fills_connected_connections_once() {
    use opsagent_core::connection::ConnectionStatus as S;
    let store = opsagent_brain::adapters::memory::MemStore::default();
    let o = org_id(&store, "acme").await;
    let c = super::connections::connection(&store, o, "prod").await;
    let repo = store.connections();
    assert_eq!(
        store
            .schedules()
            .backfill_defaults(Utc::now())
            .await
            .unwrap(),
        0
    );
    assert!(repo
        .cas_status(o, c.id, S::Pending, S::Verifying, None)
        .await
        .unwrap());
    assert!(repo
        .cas_status(o, c.id, S::Verifying, S::Connected, None)
        .await
        .unwrap());
    assert_eq!(
        store
            .schedules()
            .backfill_defaults(Utc::now())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .schedules()
            .backfill_defaults(Utc::now())
            .await
            .unwrap(),
        0
    );
    // The connection's five, the organisation's weekly and the global retention schedule.
    assert_eq!(all_due(&store).await.len(), 7);
}
