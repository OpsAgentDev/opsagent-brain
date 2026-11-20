//! Nightly scans that keep failing (PRD 7.3, launch readiness K3): the third `failed` nightly
//! full scan in a row degrades a connected connection with reason `scans_failing` and queues
//! the owners' notice, once per streak; the next nightly scan that ends `done` puts it back.
//! Manual, first and operator scans (`on_schedule_slot`) and skipped runs count neither way.
//! The streak is read from the runs, never counted here, so a worker killed between a run's
//! end and this rule only delays it to the next nightly scan.
use std::sync::Arc;

use opsagent_core::{
    connection::{transition, ConnectionEvent as E, SCANS_FAILING},
    repo::Clock,
    run::{on_schedule_slot, RunStatus},
};
use opsagent_ledger::RunRow;
use uuid::Uuid;

use super::revoked_notice::enqueue_scans_failing_notice;
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// Nightly scans that must fail in a row before the connection is degraded.
const FAILED_TIMES: u64 = 3;

#[derive(Clone)]
pub(super) struct ScanStreak {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
}

impl ScanStreak {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, clock }
    }

    /// Applies the rule for full scan `run`, read back after it ended.
    pub async fn run(&self, run: &RunRow) -> AppResult<()> {
        let (Some(org), Some(id)) = (run.key.organisation_id, run.key.connection_id) else {
            return Ok(());
        };
        if !on_schedule_slot(run.key.scheduled_at) {
            return Ok(());
        }
        match run.status {
            RunStatus::Failed => self.failed(org, id).await,
            RunStatus::Done => self.recovered(org, id).await,
            _ => Ok(()),
        }
    }

    /// Degrades the connection and queues the notice in one transaction. Only a `connected`
    /// connection moves: one already degraded, revoked, blocked or disconnected is left alone.
    async fn failed(&self, org: Uuid, id: Uuid) -> AppResult<()> {
        let streak = self.uow.runs().failed_scan_streak(org, id).await?;
        let Some((_, since)) = streak.filter(|(n, _)| *n >= FAILED_TIMES) else {
            return Ok(());
        };
        let tx = self.uow.begin().await?;
        let Some(c) = tx.connections().get(org, id).await? else {
            return Ok(());
        };
        let Ok(to) = transition(c.status, E::ScansFailedThrice) else {
            return Ok(());
        };
        let repo = tx.connections();
        let cas = repo.cas_status(org, id, c.status, to, Some(SCANS_FAILING));
        if !cas.await? {
            return Ok(());
        }
        enqueue_scans_failing_notice(&*tx, &c, since, self.clock.now()).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Back to `connected` with no reason, only from `degraded` for `scans_failing`.
    async fn recovered(&self, org: Uuid, id: Uuid) -> AppResult<()> {
        let Some(c) = self.uow.connections().get(org, id).await? else {
            return Ok(());
        };
        if c.status_reason.as_deref() != Some(SCANS_FAILING) {
            return Ok(());
        }
        let Ok(to) = transition(c.status, E::ScanDone) else {
            return Ok(());
        };
        let from = (c.status, SCANS_FAILING);
        let repo = self.uow.connections();
        repo.cas_status_clearing(org, id, from, to).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use opsagent_core::{
        connection::{Connection, ConnectionStatus as S, ConnectionsRepo},
        repo::FixedClock,
        run::RunKey,
    };
    use opsagent_ledger::{JobKind, Storage};

    use super::*;
    use crate::{actions::runs::test_support::connected, adapters::memory::MemStore};

    /// 02:00 on night `n`: a schedule slot.
    fn night(n: i64) -> DateTime<Utc> {
        "2026-11-01T02:00:00Z".parse::<DateTime<Utc>>().unwrap() + Duration::days(n)
    }

    fn streak(store: &MemStore) -> ScanStreak {
        ScanStreak::new(Arc::new(store.clone()), Arc::new(FixedClock(night(30))))
    }

    /// A full scan of `c` scheduled at `at` that ended `status`, with the rule applied.
    async fn ended(store: &MemStore, c: &Connection, at: DateTime<Utc>, status: RunStatus) {
        let key = RunKey {
            organisation_id: Some(c.organisation_id),
            connection_id: Some(c.id),
            job_type: JobKind::FullScan.as_str().into(),
            scheduled_at: at,
        };
        let run = store.create_run(key).await.unwrap().run;
        let set = store.set_status(run.id, run.fence, status, None);
        set.await.unwrap();
        let run = store.load_run(run.id).await.unwrap();
        streak(store).run(&run).await.unwrap();
    }

    async fn state(store: &MemStore, c: &Connection) -> (S, Option<String>) {
        let c = ConnectionsRepo::get(store, c.organisation_id, c.id);
        let c = c.await.unwrap().unwrap();
        (c.status, c.status_reason)
    }

    fn notices(store: &MemStore) -> Vec<Uuid> {
        let jobs = store.jobs().into_iter();
        jobs.filter(|j| j.kind == JobKind::DeliverScansFailingNotice)
            .map(|j| j.run_id)
            .collect()
    }

    fn failing() -> (S, Option<String>) {
        (S::Degraded, Some(SCANS_FAILING.into()))
    }

    #[tokio::test]
    async fn the_third_failed_night_degrades_and_queues_one_notice() {
        let store = MemStore::default();
        let c = connected(&store, Uuid::new_v4()).await;
        for n in 0..2 {
            ended(&store, &c, night(n), RunStatus::Failed).await;
            assert_eq!(state(&store, &c).await, (S::Connected, None), "night {n}");
        }
        assert!(notices(&store).is_empty());
        ended(&store, &c, night(2), RunStatus::Failed).await;
        assert_eq!(state(&store, &c).await, failing());
        let queued = notices(&store);
        assert_eq!(queued.len(), 1);
        // The notice run is keyed to the first failed night of the streak.
        let run = store.load_run(queued[0]).await.unwrap();
        assert_eq!(run.key.scheduled_at, night(0));
        assert_eq!(run.key.connection_id, Some(c.id));
        // A fourth failure, and the rule applied again, queue nothing more.
        ended(&store, &c, night(3), RunStatus::Failed).await;
        assert_eq!(state(&store, &c).await, failing());
        assert_eq!(notices(&store), queued);
    }

    #[tokio::test]
    async fn a_verify_that_reconnects_mid_streak_does_not_mail_the_streak_twice() {
        let store = MemStore::default();
        let c = connected(&store, Uuid::new_v4()).await;
        for n in 0..3 {
            ended(&store, &c, night(n), RunStatus::Failed).await;
        }
        let (org, id) = (c.organisation_id, c.id);
        let back = ConnectionsRepo::cas_status(&store, org, id, S::Degraded, S::Connected, None);
        assert!(back.await.unwrap());
        ended(&store, &c, night(3), RunStatus::Failed).await;
        assert_eq!(state(&store, &c).await, failing());
        assert_eq!(notices(&store).len(), 1);
    }

    #[tokio::test]
    async fn a_done_night_restores_connected_and_starts_a_new_streak() {
        let store = MemStore::default();
        let c = connected(&store, Uuid::new_v4()).await;
        for n in 0..3 {
            ended(&store, &c, night(n), RunStatus::Failed).await;
        }
        // A partial night neither restores nor counts as failed.
        ended(&store, &c, night(3), RunStatus::Partial).await;
        assert_eq!(state(&store, &c).await, failing());
        ended(&store, &c, night(4), RunStatus::Done).await;
        assert_eq!(state(&store, &c).await, (S::Connected, None));
        // Two more failures are not three in a row; the third is, with its own notice.
        for n in 5..7 {
            ended(&store, &c, night(n), RunStatus::Failed).await;
            assert_eq!(state(&store, &c).await, (S::Connected, None), "night {n}");
        }
        ended(&store, &c, night(7), RunStatus::Failed).await;
        assert_eq!(state(&store, &c).await, failing());
        assert_eq!(notices(&store).len(), 2);
    }

    #[tokio::test]
    async fn a_done_night_between_failures_breaks_the_streak() {
        let store = MemStore::default();
        let c = connected(&store, Uuid::new_v4()).await;
        let nights = [RunStatus::Failed, RunStatus::Failed, RunStatus::Done];
        for (n, status) in nights.into_iter().chain(nights).enumerate() {
            ended(&store, &c, night(n as i64), status).await;
        }
        ended(&store, &c, night(6), RunStatus::Failed).await;
        assert_eq!(state(&store, &c).await, (S::Connected, None));
        assert!(notices(&store).is_empty());
    }

    #[tokio::test]
    async fn manual_and_skipped_runs_count_neither_way() {
        let store = MemStore::default();
        let c = connected(&store, Uuid::new_v4()).await;
        // A manual scan is keyed at the instant it was asked for, never on a slot.
        let manual = |n: i64| night(n) + Duration::hours(9) + Duration::microseconds(1_234_567);
        ended(&store, &c, night(0), RunStatus::Failed).await;
        ended(&store, &c, night(1), RunStatus::Failed).await;
        // Failed manual scans and a skipped night do not make it three.
        ended(&store, &c, manual(1), RunStatus::Failed).await;
        ended(&store, &c, manual(2), RunStatus::Failed).await;
        ended(&store, &c, night(2), RunStatus::Skipped).await;
        assert_eq!(state(&store, &c).await, (S::Connected, None));
        // A done manual scan does not break the streak either: the next failed night is the third.
        ended(&store, &c, manual(3), RunStatus::Done).await;
        ended(&store, &c, night(3), RunStatus::Failed).await;
        assert_eq!(state(&store, &c).await, failing());
        // Nor does a done manual scan restore it; a done night does.
        ended(&store, &c, manual(4), RunStatus::Done).await;
        assert_eq!(state(&store, &c).await, failing());
        ended(&store, &c, night(4), RunStatus::Done).await;
        assert_eq!(state(&store, &c).await, (S::Connected, None));
    }

    #[tokio::test]
    async fn revoked_blocked_disconnected_and_already_degraded_are_left_alone() {
        for (status, reason) in [
            (S::Revoked, Some("access_denied")),
            (S::Blocked, Some("policy_superset")),
            (S::Disconnected, None),
            (S::Degraded, Some("policy_subset")),
        ] {
            let store = MemStore::default();
            let c = connected(&store, Uuid::new_v4()).await;
            ended(&store, &c, night(0), RunStatus::Failed).await;
            ended(&store, &c, night(1), RunStatus::Failed).await;
            let (org, id) = (c.organisation_id, c.id);
            let cas = ConnectionsRepo::cas_status(&store, org, id, S::Connected, status, reason);
            assert!(cas.await.unwrap());
            let before = state(&store, &c).await;
            ended(&store, &c, night(2), RunStatus::Failed).await;
            assert_eq!(state(&store, &c).await, before, "{status:?}");
            // A done night restores only what this rule degraded.
            ended(&store, &c, night(3), RunStatus::Done).await;
            assert_eq!(state(&store, &c).await, before, "{status:?}");
            assert!(notices(&store).is_empty(), "{status:?}");
        }
    }

    #[tokio::test]
    async fn another_connections_failures_do_not_count() {
        let store = MemStore::default();
        let org = Uuid::new_v4();
        let (a, b) = (connected(&store, org).await, connected(&store, org).await);
        ended(&store, &a, night(0), RunStatus::Failed).await;
        ended(&store, &a, night(1), RunStatus::Failed).await;
        ended(&store, &b, night(2), RunStatus::Failed).await;
        assert_eq!(state(&store, &a).await, (S::Connected, None));
        assert_eq!(state(&store, &b).await, (S::Connected, None));
    }
}
