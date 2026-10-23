//! shortcut: Loco's Redis queue behind the `Queue` port; deleted when the Postgres queue
//! lands (Task 18). The only place that names a Loco worker for enqueueing.
use async_trait::async_trait;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, environment::Environment};
use opsagent_ledger::{JobKind, LedgerError, NewJob, Queue};

use crate::{
    config::AppEnv,
    error::{AppError, AppResult},
    workers::{
        full_scan::{FullScanArgs, FullScanWorker},
        verify::{VerifyArgs, VerifyWorker},
        DeliverBriefingArgs, DeliverBriefingWorker, DeliverWeeklyArgs, DeliverWeeklyWorker,
    },
};

pub struct LocoQueue(pub AppContext);

impl LocoQueue {
    /// An enqueue-only context for processes our `main` boots (`start`, tasks): the yaml's
    /// queue, no database and an empty shared store, so it holds no `AppState` (no cycle).
    pub async fn connect(env: AppEnv) -> AppResult<Self> {
        let internal = |e: loco_rs::Error| AppError::Internal(e.to_string());
        let env = Environment::from(
            match env {
                AppEnv::Development => "development",
                AppEnv::Test => "test",
                AppEnv::Production => "production",
            }
            .to_owned(),
        );
        let config = env.load().map_err(internal)?;
        let queue = loco_rs::bgworker::create_queue_provider(&config)
            .await
            .map_err(internal)?
            .ok_or_else(|| AppError::Internal("no queue configured".into()))?;
        let ctx = AppContext::builder(env, Default::default(), config)
            .queue_provider(queue)
            .build();
        Ok(Self(ctx))
    }
}

#[async_trait]
impl Queue for LocoQueue {
    /// `run_at` is not passed on: Loco enqueues for now, and every caller's `run_at` is due.
    async fn enqueue(&self, job: NewJob) -> opsagent_ledger::Result<()> {
        let (ctx, run_id) = (&self.0, job.run_id);
        match job.kind {
            JobKind::Verify => VerifyWorker::perform_later(ctx, VerifyArgs { run_id }).await,
            JobKind::FullScan => FullScanWorker::perform_later(ctx, FullScanArgs { run_id }).await,
            JobKind::DeliverBriefing => {
                DeliverBriefingWorker::perform_later(ctx, DeliverBriefingArgs { run_id }).await
            }
            JobKind::DeliverWeekly => {
                DeliverWeeklyWorker::perform_later(ctx, DeliverWeeklyArgs { run_id }).await
            }
        }
        .map(drop)
        .map_err(|e| LedgerError::Storage(e.to_string()))
    }
}
