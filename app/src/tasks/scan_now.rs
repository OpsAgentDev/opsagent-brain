//! `cargo loco task scan:now connection:<id>`: runs a full scan inline (local use).
use crate::adapters::db::ledger_storage::PgStorage;
use async_trait::async_trait;
use loco_rs::{
    app::AppContext,
    task::{Task, TaskInfo, Vars},
    Error, Result,
};
use opsagent_core::run::RunKey;
use opsagent_ledger::{RunChunkedOptions, Storage};
use sea_orm::EntityTrait;
use uuid::Uuid;

use crate::{
    models::_entities::connections,
    workers::{
        common::err,
        full_scan::{self, JOB},
    },
};

pub struct ScanNow;

#[async_trait]
impl Task for ScanNow {
    fn task(&self) -> TaskInfo {
        TaskInfo {
            name: "scan:now".into(),
            detail: "Run a full scan now: scan:now connection:<id>".into(),
        }
    }

    async fn run(&self, ctx: &AppContext, vars: &Vars) -> Result<()> {
        let id: Uuid = vars.cli_arg("connection")?.parse().map_err(err)?;
        // tenancy: operator task; the connection id names its organisation.
        let c = connections::Entity::find_by_id(id)
            .one(&ctx.db)
            .await?
            .ok_or_else(|| Error::string("connection not found"))?;
        let run = PgStorage::new(ctx.db.clone())
            .create_run(RunKey {
                organisation_id: Some(c.organisation_id),
                connection_id: Some(id),
                job_type: JOB.into(),
                scheduled_at: chrono::Utc::now(),
            })
            .await
            .map_err(err)?
            .run;
        let status = full_scan::run(ctx, run.id, RunChunkedOptions::default())
            .await
            .map_err(err)?;
        tracing::info!(run_id = %run.id, status = ?status, "scan_now finished");
        Ok(())
    }
}
