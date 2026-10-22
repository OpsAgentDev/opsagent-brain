//! `cargo loco task openapi:dump [path:<file>]`: writes the OpenAPI document (default: the
//! repo's committed `openapi.json`).
use async_trait::async_trait;
use loco_rs::{
    app::AppContext,
    task::{Task, TaskInfo, Vars},
    Error, Result,
};

use crate::controllers::openapi::document_json;

const COMMITTED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../openapi.json");

pub struct OpenapiDump;

#[async_trait]
impl Task for OpenapiDump {
    fn task(&self) -> TaskInfo {
        TaskInfo {
            name: "openapi:dump".into(),
            detail: "Write openapi.json: openapi:dump [path:<file>]".into(),
        }
    }

    async fn run(&self, _ctx: &AppContext, vars: &Vars) -> Result<()> {
        let path = vars.cli_arg("path").unwrap_or(COMMITTED);
        std::fs::write(path, document_json()).map_err(|e| Error::string(&e.to_string()))
    }
}
