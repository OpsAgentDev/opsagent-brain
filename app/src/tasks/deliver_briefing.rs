//! `cargo loco task deliver:briefing connection:<id>`: delivers the briefing inline (local and
//! e2e use).
use async_trait::async_trait;
use loco_rs::{
    app::AppContext,
    task::{Task, TaskInfo, Vars},
    Error, Result,
};
use uuid::Uuid;

use crate::{app::actions, error::AppError, workers::common::err};

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
        match actions(ctx)?.deliveries.deliver_briefing_now.run(id).await {
            Ok(_) => Ok(()),
            Err(AppError::NotFound) => Err(Error::string("connection not found")),
            Err(e) => Err(err(e)),
        }
    }
}
