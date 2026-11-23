use async_trait::async_trait;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{owner_only, parse_args, schema_of, Access, Caller, Tool, ToolError, ToolSpec};
use crate::actions::connections::{CreateConnection, QuickCreate, TEMPLATE_VERSION};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Args {
    /// Display name for the account, e.g. `Production`: 1 to 100 characters.
    name: String,
}

const NEXT_STEP: &str = "Ask the person to open launch_url in a browser signed in to the AWS \
    account, create the stack, and give you the stack output RoleArn. Then call \
    verify_connection with this connection_id and that role_arn.";

/// Starts connecting an AWS account: the same Action as REST's create connection.
pub struct ConnectCloudAccountTool {
    create: CreateConnection,
    links: QuickCreate,
}

impl ConnectCloudAccountTool {
    pub fn new(create: CreateConnection, links: QuickCreate) -> Self {
        Self { create, links }
    }
}

#[async_trait]
impl Tool for ConnectCloudAccountTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "connect_cloud_account",
            title: "Connect a cloud account",
            description: "Starts connecting an AWS account to OpsAgent and returns the link that \
                          creates its read-only role. Owners only. Every call makes a new \
                          connection, so call it once per account. Nothing changes in AWS until \
                          the person opens the link and creates the stack themselves.",
            input_schema: schema_of::<Args>(),
            access: Access::Write,
            idempotent: false,
            destructive: false,
            open_world: true,
        }
    }

    async fn call(&self, caller: &Caller, args: Value) -> Result<Value, ToolError> {
        let a: Args = parse_args(args)?;
        let created = self
            .create
            .run(&caller.scope, "aws", &a.name)
            .await
            .map_err(owner_only)?;
        let launch_url = self.links.link(caller.scope.organisation.id, &created)?;
        Ok(json!({
            "connection_id": created.id,
            "launch_url": launch_url,
            "template_version": TEMPLATE_VERSION,
            "next_step": NEXT_STEP,
        }))
    }
}
