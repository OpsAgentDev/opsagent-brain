use chrono::{DateTime, Duration, Utc};
use opsagent_brain::adapters::memory::RunLink;
use opsagent_core::{retention::TtlTable, run::RunStatus};
use opsagent_deliver::schedule::{BILLING_SYNC_CRON, RETENTION_CRON};

use super::{contract_suite, org_id, Seed};

/// Whole seconds, so instants survive Postgres' microsecond timestamps unchanged.
fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
}

/// `(organisation, connection)` for run seeding.
async fn scope(
    s: &dyn opsagent_brain::actions::uow::Repos,
    seed: &dyn Seed,
) -> (uuid::Uuid, uuid::Uuid) {
    let o = org_id(s, "acme").await;
    (o, seed.connection(o).await)
}

/// The instant `days` before `t` (distinct per `nth`); each test takes one `t`, so the
/// instants it compares never straddle a second boundary.
fn ago(t: DateTime<Utc>, days: i64, nth: i64) -> DateTime<Utc> {
    t - Duration::days(days) - Duration::seconds(nth)
}

async fn exists(s: &dyn opsagent_brain::actions::uow::UnitOfWork, run: uuid::Uuid) -> bool {
    s.ledger().load_run(run).await.is_ok()
}

contract_suite! {
    async fn prunes_old_watch_run_and_dependents(s, seed) {
        let (o, c) = scope(s, seed).await;
        let t = now();
        let watch = seed.run_at(o, c, "watch_scan", RunStatus::Done, ago(t, 20, 0)).await;
        for link in [RunLink::Effect("watch:chunk"), RunLink::ApiCallStats, RunLink::ApiCallsRaw, RunLink::ResourceHistory] {
            seed.run_link(o, c, watch, link).await;
        }
        let alert = seed.run_at(o, c, "deliver_alert", RunStatus::Failed, ago(t, 20, 1)).await;
        seed.run_link(o, c, alert, RunLink::Effect("alert:rollup:x")).await;
        let partial = seed.run_at(o, c, "watch_scan", RunStatus::Partial, ago(t, 15, 0)).await;
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 100).await.unwrap(), 3);
        for run in [watch, alert, partial] {
            assert!(!exists(s, run).await);
            assert_eq!(seed.run_links_left(run).await, 0);
        }
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 100).await.unwrap(), 0);
    }

    async fn prunes_in_batches_oldest_first(s, seed) {
        let (o, c) = scope(s, seed).await;
        let t = now();
        let mut runs = Vec::new();
        for i in 0..3 {
            runs.push(seed.run_at(o, c, "watch_scan", RunStatus::Done, ago(t, 20, 10 - i)).await);
        }
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 2).await.unwrap(), 2);
        // The newest of the three is left.
        assert!(!exists(s, runs[0]).await && !exists(s, runs[1]).await && exists(s, runs[2]).await);
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 2).await.unwrap(), 1);
    }

    async fn keeps_watch_run_with_finding_events(s, seed) {
        let (o, c) = scope(s, seed).await;
        let t = now();
        let evented = seed.run_at(o, c, "watch_scan", RunStatus::Done, ago(t, 20, 0)).await;
        seed.run_link(o, c, evented, RunLink::FindingEvent).await;
        let evidenced = seed.run_at(o, c, "watch_scan", RunStatus::Done, ago(t, 20, 1)).await;
        seed.run_link(o, c, evidenced, RunLink::Evidence).await;
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 100).await.unwrap(), 0);
        assert!(exists(s, evented).await && exists(s, evidenced).await);
    }

    async fn keeps_run_referenced_by_finding(s, seed) {
        let (o, c) = scope(s, seed).await;
        let t = now();
        let first = seed.run_at(o, c, "watch_scan", RunStatus::Done, ago(t, 20, 0)).await;
        seed.run_link(o, c, first, RunLink::FirstSeen).await;
        let last = seed.run_at(o, c, "watch_scan", RunStatus::Done, ago(t, 20, 1)).await;
        seed.run_link(o, c, last, RunLink::LastSeen).await;
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 100).await.unwrap(), 0);
        assert!(exists(s, first).await && exists(s, last).await);
    }

    async fn keeps_deliver_alert_with_baseline(s, seed) {
        let (o, c) = scope(s, seed).await;
        let t = now();
        let run = seed.run_at(o, c, "deliver_alert", RunStatus::Done, ago(t, 20, 0)).await;
        seed.run_link(o, c, run, RunLink::Effect("alert:baseline")).await;
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 100).await.unwrap(), 0);
        assert!(exists(s, run).await);
        assert_eq!(seed.run_links_left(run).await, 1);
    }

    async fn keeps_full_scan_runs(s, seed) {
        let (o, c) = scope(s, seed).await;
        let t = now();
        let mut runs = Vec::new();
        for (i, job) in ["full_scan", "deliver_briefing", "deliver_weekly", "verify"].into_iter().enumerate() {
            for (j, st) in [RunStatus::Done, RunStatus::Partial, RunStatus::Failed].into_iter().enumerate() {
                runs.push(seed.run_at(o, c, job, st, ago(t, 40, (i * 3 + j) as i64)).await);
            }
        }
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 100).await.unwrap(), 0);
        for run in runs {
            assert!(exists(s, run).await);
        }
    }

    async fn keeps_unfinished_runs(s, seed) {
        let (o, c) = scope(s, seed).await;
        let t = now();
        let queued = seed.run_at(o, c, "watch_scan", RunStatus::Queued, ago(t, 20, 0)).await;
        let running = seed.run_at(o, c, "deliver_alert", RunStatus::Running, ago(t, 20, 1)).await;
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 100).await.unwrap(), 0);
        assert!(exists(s, queued).await && exists(s, running).await);
    }

    async fn prunes_old_skipped_runs_of_any_type(s, seed) {
        let (o, c) = scope(s, seed).await;
        let t = now();
        let full = seed.run_at(o, c, "full_scan", RunStatus::Skipped, ago(t, 20, 0)).await;
        let brief = seed.run_at(o, c, "deliver_briefing", RunStatus::Skipped, ago(t, 20, 1)).await;
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 100).await.unwrap(), 2);
        assert!(!exists(s, full).await && !exists(s, brief).await);
    }

    async fn prunes_billing_runs_and_old_notice_markers(s, seed) {
        let (o, c) = scope(s, seed).await;
        let t = now();
        let sync = seed.run_at(o, c, "billing_sync", RunStatus::Done, ago(t, 20, 0)).await;
        let old = seed.run_at(o, c, "billing_notice", RunStatus::Done, ago(t, 61, 0)).await;
        // A marker guarding a recent trial's or period's mails stays.
        let kept = seed.run_at(o, c, "billing_notice", RunStatus::Done, ago(t, 59, 0)).await;
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 100).await.unwrap(), 2);
        assert!(!exists(s, sync).await && !exists(s, old).await && exists(s, kept).await);
    }

    async fn keeps_runs_newer_than_14_days(s, seed) {
        let (o, c) = scope(s, seed).await;
        let t = now();
        let watch = seed.run_at(o, c, "watch_scan", RunStatus::Done, ago(t, 13, 0)).await;
        let skipped = seed.run_at(o, c, "full_scan", RunStatus::Skipped, ago(t, 14, 0)).await;
        assert_eq!(s.retention().prune_runs(ago(t, 14, 0), 100).await.unwrap(), 0);
        assert!(exists(s, watch).await && exists(s, skipped).await);
    }

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

    async fn global_schedules_created_once(s) {
        let at = now();
        s.schedules().backfill_defaults(at).await.unwrap();
        s.schedules().backfill_defaults(at).await.unwrap();
        let later = at + Duration::days(2);
        let ids = s.schedules().due_ids(later).await.unwrap();
        assert_eq!(ids.len(), 2);
        let mut got = Vec::new();
        for id in ids {
            let (key, cron, tz) = s.schedules().lock_due(id, later).await.unwrap().unwrap();
            assert_eq!((key.organisation_id, key.connection_id, tz.as_str()), (None, None, "UTC"));
            assert!(key.scheduled_at > at && key.scheduled_at <= at + Duration::days(1));
            got.push((key.job_type, cron, key.scheduled_at.format("%H:%M").to_string()));
        }
        got.sort();
        let want = [
            ("billing_sync".to_owned(), BILLING_SYNC_CRON.to_owned(), "04:00".to_owned()),
            ("retention".to_owned(), RETENTION_CRON.to_owned(), "03:30".to_owned()),
        ];
        assert_eq!(got, want);
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
