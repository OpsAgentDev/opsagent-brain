//! `cargo loco task deliver:briefing connection:<id>`: delivers the briefing inline (local and
//! e2e use).
use async_trait::async_trait;
use loco_rs::{
    app::AppContext,
    task::{Task, TaskInfo, Vars},
    Error, Result,
};
use opsagent_core::run::RunKey;
use opsagent_ledger::Storage;
use sea_orm::EntityTrait;
use uuid::Uuid;

use crate::{
    models::{_entities::connections, ledger_storage::PgStorage},
    workers::{
        common::err,
        deliver_briefing::{self, JOB},
    },
};

pub struct DeliverBriefingNow;

#[async_trait]
impl Task for DeliverBriefingNow {
    fn task(&self) -> TaskInfo {
        TaskInfo {
            name: "deliver:briefing".into(),
            detail: "Deliver the briefing now: deliver:briefing connection:<id>".into(),
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
        let opts = deliver_briefing::options(JOB);
        let status = deliver_briefing::run(ctx, run.id, opts)
            .await
            .map_err(err)?;
        tracing::info!(run_id = %run.id, status = ?status, "deliver_briefing finished");
        Ok(())
    }
}
