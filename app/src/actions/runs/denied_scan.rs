//! A scan that finds the role gone starts the verification that counts the denials (PRD 7.2:
//! "the revocation rules above apply"); without it only the weekly verify would notice.
use chrono::{DateTime, DurationRound, Utc};
use opsagent_core::{
    connection::{transition, ConnectionEvent as E},
    run::RunKey,
};
use opsagent_ledger::{JobKind, NewJob};

use super::{
    classify::{lerr, LResult},
    verify_outcome::DENIED_SPAN,
};
use crate::actions::uow::Tx;

/// The scan run `scan` ended `revoked`: one `verify` run and its job on `tx`. Keyed to the
/// hour, so the scans that keep failing meanwhile (a watch scan every 15 minutes) share the
/// run; the denial streak is on the connection, so a later run adds to it. Nothing for a
/// connection that cannot become `revoked`.
pub(super) async fn enqueue_verify_after_denied_scan(
    tx: &dyn Tx,
    scan: &RunKey,
    now: DateTime<Utc>,
) -> LResult<()> {
    let (Some(org), Some(id)) = (scan.organisation_id, scan.connection_id) else {
        return Ok(());
    };
    // Read here, not at scan start: the customer may have disconnected since.
    let c = tx.connections().get(org, id).await.map_err(lerr)?;
    if !c.is_some_and(|c| transition(c.status, E::AccessDeniedThrice).is_ok()) {
        return Ok(());
    }
    let kind = JobKind::Verify;
    let key = RunKey {
        job_type: kind.as_str().into(),
        scheduled_at: now.duration_trunc(DENIED_SPAN).map_err(lerr)?,
        ..scan.clone()
    };
    let out = tx.ledger().create_run(key).await?;
    if out.created {
        let (run_id, run_at) = (out.run.id, now);
        let job = NewJob {
            kind,
            run_id,
            run_at,
        };
        tx.queue().enqueue(job).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use opsagent_core::connection::{ConnectionStatus as S, ConnectionsRepo};
    use uuid::Uuid;

    use super::*;
    use crate::{
        actions::{runs::test_support::connected, uow::UnitOfWork},
        adapters::memory::MemStore,
    };

    /// The verify jobs in `store` after a scan of connection `id` ended `revoked` at `now`.
    async fn after_scan(store: &MemStore, org: Uuid, id: Uuid, now: DateTime<Utc>) -> usize {
        let scan = RunKey {
            organisation_id: Some(org),
            connection_id: Some(id),
            job_type: JobKind::WatchScan.as_str().into(),
            scheduled_at: now,
        };
        let tx = store.begin().await.unwrap();
        enqueue_verify_after_denied_scan(&*tx, &scan, now)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let jobs = store.jobs();
        assert!(jobs.iter().all(|j| j.kind == JobKind::Verify));
        jobs.len()
    }

    #[tokio::test]
    async fn failing_scans_share_one_verify_per_hour() {
        let (store, org) = (MemStore::default(), Uuid::new_v4());
        let c = connected(&store, org).await;
        let t: DateTime<Utc> = "2026-11-13T10:15:00Z".parse().unwrap();
        assert_eq!(after_scan(&store, org, c.id, t).await, 1);
        for mins in [15, 30] {
            let later = t + Duration::minutes(mins);
            assert_eq!(after_scan(&store, org, c.id, later).await, 1);
        }
        // The next hour's first failing scan asks again: its denials add to the streak.
        let next_hour = t + Duration::minutes(45);
        assert_eq!(after_scan(&store, org, c.id, next_hour).await, 2);
    }

    #[tokio::test]
    async fn a_connection_that_cannot_be_revoked_gets_no_verify() {
        let t: DateTime<Utc> = "2026-11-13T10:15:00Z".parse().unwrap();
        for to in [S::Revoked, S::Disconnected] {
            let (store, org) = (MemStore::default(), Uuid::new_v4());
            let c = connected(&store, org).await;
            let cas = ConnectionsRepo::cas_status(&store, org, c.id, S::Connected, to, None);
            assert!(cas.await.unwrap());
            assert_eq!(after_scan(&store, org, c.id, t).await, 0, "{to:?}");
        }
        // A connection of another organisation is not found: nothing either.
        let (store, org) = (MemStore::default(), Uuid::new_v4());
        let c = connected(&store, org).await;
        assert_eq!(after_scan(&store, Uuid::new_v4(), c.id, t).await, 0);
    }
}
