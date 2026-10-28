use chrono::{DateTime, Duration, Utc};
use opsagent_core::retention::TtlTable;
use opsagent_deliver::schedule::RETENTION_CRON;

use super::{contract_suite, org_id};

/// Whole seconds, so instants survive Postgres' microsecond timestamps unchanged.
fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
}

contract_suite! {
    async fn ttl_deletes_only_rows_past_cutoff(s, seed) {
        let o = org_id(s, "acme").await;
        let cutoff = now();
        for t in TtlTable::ALL {
            for at in [cutoff - Duration::seconds(1), cutoff, cutoff + Duration::hours(1)] {
                seed.expiring(o, t, at).await;
            }
        }
        for (i, t) in TtlTable::ALL.into_iter().enumerate() {
            let n = s.retention().delete_expired(t, cutoff, 100).await.unwrap();
            assert_eq!(n, 1, "{t:?}");
            // The row at the cutoff and the later one stay; tables not yet swept are untouched.
            assert_eq!(seed.expiring_left(t).await, 2, "{t:?}");
            for later in &TtlTable::ALL[i + 1..] {
                assert_eq!(seed.expiring_left(*later).await, 3, "{later:?} after {t:?}");
            }
        }
    }

    async fn ttl_batches_until_empty(s, seed) {
        let o = org_id(s, "acme").await;
        let cutoff = now();
        for i in 1..=5 {
            seed.expiring(o, TtlTable::Sessions, cutoff - Duration::minutes(i)).await;
        }
        let mut got = Vec::new();
        loop {
            let n = s.retention().delete_expired(TtlTable::Sessions, cutoff, 2).await.unwrap();
            got.push(n);
            if n == 0 {
                break;
            }
        }
        assert_eq!(got, [2, 2, 1, 0]);
        assert_eq!(seed.expiring_left(TtlTable::Sessions).await, 0);
    }

    async fn global_retention_schedule_created_once(s) {
        let at = now();
        s.schedules().backfill_defaults(at).await.unwrap();
        s.schedules().backfill_defaults(at).await.unwrap();
        let ids = s.schedules().due_ids(at + Duration::days(2)).await.unwrap();
        assert_eq!(ids.len(), 1);
        let (key, cron, tz) = s.schedules().lock_due(ids[0], at + Duration::days(2)).await.unwrap().unwrap();
        assert_eq!((key.organisation_id, key.connection_id), (None, None));
        assert_eq!((key.job_type.as_str(), cron.as_str(), tz.as_str()), ("retention", RETENTION_CRON, "UTC"));
        // 03:30 UTC, within the next day.
        assert_eq!(key.scheduled_at.format("%H:%M").to_string(), "03:30");
        assert!(key.scheduled_at > at && key.scheduled_at <= at + Duration::days(1));
    }
}

/// Pg only: the partial unique index itself refuses a second global schedule for a job.
#[tokio::test]
#[serial_test::serial]
async fn second_global_schedule_is_refused() {
    use sea_orm::ConnectionTrait;
    let store = super::pg().await;
    let seed = super::PgSeed::new().await;
    let insert = "INSERT INTO schedules (id, job_type, cron_local) VALUES (gen_random_uuid(), 'retention', '30 3 * * *')";
    seed.raw().execute_unprepared(insert).await.unwrap();
    assert!(seed.raw().execute_unprepared(insert).await.is_err());
    drop(store);
}
