//! `scheduler:tick`: hands one tick to `SchedulerTick` (run every minute).
use async_trait::async_trait;
use chrono::Utc;
use loco_rs::{
    app::AppContext,
    task::{Task, TaskInfo, Vars},
    Result,
};

use crate::workers::common::err;

pub struct SchedulerTick;

#[async_trait]
impl Task for SchedulerTick {
    fn task(&self) -> TaskInfo {
        TaskInfo {
            name: "scheduler:tick".into(),
            detail: "Enqueue due schedules and retries (run every minute)".into(),
        }
    }

    async fn run(&self, ctx: &AppContext, _vars: &Vars) -> Result<()> {
        let tick = &crate::app::actions(ctx)?.runs.scheduler_tick;
        match tick.run(Utc::now()).await.map_err(err)? {
            Some(r) => tracing::info!(?r, "scheduler tick"),
            None => tracing::info!("scheduler lock held elsewhere, skipping tick"),
        }
        Ok(())
    }
}
