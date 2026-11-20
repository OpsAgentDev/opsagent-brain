//! Connection use cases (PRD 7.2): create, read, update, verify, reconnect, disconnect.
mod create_connection;
mod disconnect_connection;
mod end;
mod get_connection;
mod list_connections;
mod reconnect_link;
mod request_verify;
mod update_connection;

use axum::http::StatusCode;
use opsagent_connectors::aws::client::short_id;
pub use opsagent_connectors::aws::policy_diff::TEMPLATE_VERSION;
use uuid::Uuid;

pub use create_connection::{CreateConnection, Created};
pub use disconnect_connection::DisconnectConnection;
pub use end::end_connection;
pub use get_connection::GetConnection;
pub use list_connections::ListConnections;
pub use reconnect_link::ReconnectLink;
pub use request_verify::RequestVerify;
pub use update_connection::{PatchInput, UpdateConnection};

use crate::{
    config::Config,
    error::{AppError, AppResult},
};

pub struct Connections {
    pub create_connection: CreateConnection,
    pub list_connections: ListConnections,
    pub get_connection: GetConnection,
    pub update_connection: UpdateConnection,
    pub request_verify: RequestVerify,
    pub reconnect_link: ReconnectLink,
    pub disconnect_connection: DisconnectConnection,
    pub quick_create: QuickCreate,
}

/// The CloudFormation stack the read role template creates for an organisation.
pub fn stack_name(organisation_id: Uuid) -> String {
    format!("OpsAgent-Read-{}", short_id(&organisation_id))
}

/// What the AWS onboarding link is built from (`Config`).
#[derive(Clone)]
pub struct QuickCreate {
    principal: Option<String>,
    template_base_url: String,
}

impl QuickCreate {
    pub fn new(c: &Config) -> Self {
        Self {
            principal: c.aws_outbound_role_arn.clone(),
            template_base_url: c.template_base_url.clone(),
        }
    }

    /// The CloudFormation quick-create link for a connection just created or being
    /// reconnected; `None` for a provider without a template (test providers).
    pub fn link(&self, organisation_id: Uuid, c: &Created) -> AppResult<Option<String>> {
        if !c.spec.uses_template {
            return Ok(None);
        }
        let principal = self.principal.as_deref().ok_or_else(|| {
            AppError::Internal("OPSAGENT_AWS_OUTBOUND_ROLE_ARN is not set".into())
        })?;
        let template = format!(
            "{}/aws/opsagent-read-role-v{TEMPLATE_VERSION}.yaml",
            self.template_base_url.trim_end_matches('/')
        );
        let e = |s: &str| urlencoding::encode(s).into_owned();
        Ok(Some(format!(
            "https://console.aws.amazon.com/cloudformation/home#/stacks/quickcreate?templateURL={}&stackName={}\
             &param_ExternalId={}&param_OpsAgentPrincipal={}&param_OrgShortId={}&param_TemplateVersion={TEMPLATE_VERSION}",
            e(&template),
            stack_name(organisation_id),
            e(&c.creds.external_id),
            e(principal),
            short_id(&organisation_id),
        )))
    }
}

fn disconnected() -> AppError {
    AppError::Refused {
        status: StatusCode::CONFLICT,
        code: "connection_disconnected",
        detail: "This connection was disconnected. Start a new connection instead.".into(),
    }
}
