use chrono::{Duration, Utc};
use opsagent_brain::actions::uow::{Repos, UnitOfWork};
use uuid::Uuid;

use super::conn_suite;

/// Ids of everything due a week and a day from now, i.e. all enabled schedules.
async fn all_due(s: &dyn Repos) -> Vec<Uuid> {
    s.schedules()
        .due_ids(Utc::now() + Duration::days(8))
        .await
        .unwrap()
}

conn_suite! {
    async fn advance_none_disables(s, o, c) {
        let now = Utc::now();
        s.schedules().create_defaults(o, c, (None, None), now).await.unwrap();
        // Idempotent: 4 per connection and the organisation's weekly summary.
        s.schedules().create_defaults(o, c, (None, None), now).await.unwrap();
        let ids = all_due(s).await;
        assert_eq!(ids.len(), 5);
        assert!(s.schedules().due_ids(now).await.unwrap().is_empty());
        s.schedules().advance(ids[0], None).await.unwrap();
        assert!(!all_due(s).await.contains(&ids[0]));
        let far = now + Duration::days(30);
        s.schedules().advance(ids[1], Some(far)).await.unwrap();
        assert!(!all_due(s).await.contains(&ids[1]));
        assert!(s.schedules().due_ids(far).await.unwrap().contains(&ids[1]));
        assert_eq!(s.schedules().disable_for_org(o).await.unwrap(), 5);
        assert!(s.schedules().due_ids(far).await.unwrap().is_empty());
    }

    async fn due_ids_excludes_deleted_orgs(s, o, c) {
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
    let (store, db) = super::pg_db().await;
    let o = super::org_id(&store, "acme").await;
    let c = super::pg_connection(&db, o).await;
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
