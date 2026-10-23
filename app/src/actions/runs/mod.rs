//! Runs: reading them, manual scans, handing runs to the queue, verify runs and the scheduler tick.
pub(crate) mod classify;
mod dispatch;
mod finding_lifecycle;
mod full_scan;
mod full_scan_chunks;
mod get_run;
mod list_runs;
mod request_manual_scan;
mod scan_now;
mod scheduler_tick;
mod verify_connection;
mod verify_outcome;
mod verify_verdict;

use std::sync::Arc;

pub use dispatch::RunDispatcher;
pub use full_scan::FullScan;
pub use full_scan_chunks::Chunk;
pub use get_run::GetRun;
pub use list_runs::ListRuns;
pub use request_manual_scan::RequestManualScan;
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
    pub scan_now: ScanNow,
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
