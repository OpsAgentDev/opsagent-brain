//! Runs: reading them, manual scans, handing runs to the queue, verify runs and the scheduler tick.
pub(crate) mod classify;
mod denied_scan;
mod dispatch;
mod finding_lifecycle;
mod full_scan;
mod full_scan_chunks;
mod get_run;
mod list_runs;
mod operator_notice;
mod request_manual_scan;
mod revoked_notice;
mod scan_now;
mod scheduler_tick;
mod verify_connection;
mod verify_outcome;
mod verify_verdict;
mod watch_scan;

use std::{future::Future, sync::Arc};

use opsagent_core::run::RunStatus;
use opsagent_ledger::{redis, run_chunked, ChunkOutcome, RunChunkedOptions, RunRow};
use uuid::Uuid;

use crate::actions::uow::UnitOfWork;
use classify::LResult;

pub use dispatch::RunDispatcher;
pub use full_scan::FullScan;
pub use full_scan_chunks::Chunk;
pub use get_run::GetRun;
pub use list_runs::ListRuns;
pub use operator_notice::{FailureCounts, Failures, OperatorNotice};
pub use request_manual_scan::{RequestManualScan, WINDOW as SCAN_WINDOW};
pub use revoked_notice::{enqueue_revoked_notice, DeliverRevokedNotice};
pub use scan_now::ScanNow;
pub use scheduler_tick::{SchedulerTick, TickReport};
pub use verify_connection::VerifyConnection;

pub struct Runs {
    /// Shared with the workers and the scheduler tick.
    pub dispatcher: Arc<RunDispatcher>,
    pub request_manual_scan: RequestManualScan,
    pub list_runs: ListRuns,
    pub get_run: GetRun,
    pub verify_connection: VerifyConnection,
    /// Shared with the scheduler loop (`jobs::Scheduler`).
    pub scheduler_tick: Arc<SchedulerTick>,
    pub full_scan: FullScan,
    /// `full_scan.watch()`: the 15-minute urgent-exposure subset.
    pub watch_scan: FullScan,
    pub scan_now: ScanNow,
    pub deliver_revoked_notice: DeliverRevokedNotice,
    pub operator_notice: OperatorNotice,
}

/// Runs `send` as the single chunk of run `run_id` under its ledger lease; a finished run
/// (a duplicate delivery) is left as it is.
async fn one_chunk_run<F, Fut>(
    uow: &dyn UnitOfWork,
    redis: &redis::Client,
    run_id: Uuid,
    opts: RunChunkedOptions,
    send: F,
) -> LResult<RunStatus>
where
    F: Fn(RunRow) -> Fut,
    Fut: Future<Output = LResult<ChunkOutcome>>,
{
    let storage = uow.ledger();
    let run = storage.load_run(run_id).await?;
    if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
        return Ok(run.status);
    }
    let chunks = vec!["mail".to_owned()];
    run_chunked(storage, redis, run_id, chunks, opts, |_, _| {
        send(run.clone())
    })
    .await
}

#[cfg(test)]
pub(crate) mod test_support {
    use opsagent_core::connection::{
        Connection, ConnectionStatus as S, ConnectionsRepo, NewConnection, SealedCreds,
    };
    use uuid::Uuid;

    use crate::adapters::memory::MemStore;

    /// A pending connection of `org` in `store`.
    pub async fn pending(store: &MemStore, org: Uuid) -> Connection {
        let new = NewConnection {
            organisation_id: org,
            provider: "aws".into(),
            display_name: "Prod".into(),
            template_version: Some("1".into()),
            credential_kind: "aws_role".into(),
        };
        let sealed = SealedCreds {
            ciphertext: vec![1; 8],
            nonce: vec![1; 12],
            kek_version: 1,
        };
        ConnectionsRepo::insert(store, new, sealed).await.unwrap()
    }

    /// A connected connection of `org` in `store`.
    pub async fn connected(store: &MemStore, org: Uuid) -> Connection {
        let c = pending(store, org).await;
        let cas = |from, to| ConnectionsRepo::cas_status(store, org, c.id, from, to, None);
        assert!(cas(S::Pending, S::Verifying).await.unwrap());
        assert!(cas(S::Verifying, S::Connected).await.unwrap());
        Connection {
            status: S::Connected,
            ..c
        }
    }
}
