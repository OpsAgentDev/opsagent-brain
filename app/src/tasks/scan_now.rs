//! `cargo loco task scan:now connection:<id>`: runs a full scan inline (local use).
use async_trait::async_trait;
use loco_rs::{
    app::AppContext,
    task::{Task, TaskInfo, Vars},
    Error, Result,
};
use uuid::Uuid;

use crate::{error::AppError, workers::common::err};

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
        match crate::app::actions(ctx)?.runs.scan_now.run(id).await {
            Ok(_) => Ok(()),
            Err(AppError::NotFound) => Err(Error::string("connection not found")),
            Err(e) => Err(err(e)),
        }
    }
}
