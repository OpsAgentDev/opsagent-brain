//! The MCP edge: rmcp's streamable HTTP service over the `ToolRegistry`. It maps specs,
//! results and errors to MCP and owns no tool logic. `auth` resolves the caller first.
pub mod auth;

use std::sync::Arc;

use axum::http::request::Parts;
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, GetPromptRequestParams,
        GetPromptResponse, GetPromptResult, Implementation, ListPromptsResult, ListResourcesResult,
        ListToolsResult, PaginatedRequestParams, Prompt as McpPrompt, PromptArgument,
        PromptMessage, ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult,
        Resource as McpResource, ResourceContents, Role, ServerCapabilities, ServerConfig,
        Tool as McpTool, ToolAnnotations,
    },
    service::RequestContext,
    transport::{
        streamable_http_server::session::never::NeverSessionManager, StreamableHttpServerConfig,
        StreamableHttpService,
    },
    ErrorData, RoleServer, ServerHandler,
};
use serde_json::{json, Value};

use crate::{
    config::{AppEnv, Config},
    middleware::PUBLIC_BODY_LIMIT,
    state::AppState,
    tools::{
        prompts::{PromptMessage as OurMessage, Role as OurRole},
        Access, Caller, PromptRegistry, ResourceRegistry, ToolError, ToolRegistry, ToolSpec,
    },
};

#[derive(Clone)]
pub struct McpServer {
    tools: Arc<ToolRegistry>,
    resources: Arc<ResourceRegistry>,
    prompts: Arc<PromptRegistry>,
}

/// The service mounted at `/mcp` (behind `auth::layer`): stateless for every protocol era,
/// JSON responses (no SSE stream for the request timeout to cut), and the public body limit.
pub fn service(state: &AppState) -> StreamableHttpService<McpServer, NeverSessionManager> {
    let server = McpServer {
        tools: state.tools.clone(),
        resources: state.resources.clone(),
        prompts: state.prompts.clone(),
    };
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(allowed_hosts(&state.config))
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_max_request_body_bytes(PUBLIC_BODY_LIMIT);
    StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(NeverSessionManager::default()),
        config,
    )
}

/// The `APP_BASE_URL` host (validated at config load); loopback too outside production.
fn allowed_hosts(c: &Config) -> Vec<String> {
    let host = reqwest::Url::parse(&c.api_base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .expect("APP_BASE_URL is validated in Config::from_vars");
    let mut hosts = vec![host];
    if c.env != AppEnv::Production {
        hosts.extend(["localhost".into(), "127.0.0.1".into()]);
    }
    hosts
}

fn to_mcp(s: ToolSpec) -> McpTool {
    let schema = match s.input_schema {
        Value::Object(m) => m,
        _ => Default::default(),
    };
    let mut t = McpTool::new(s.name, s.description, schema);
    t.title = Some(s.title.into());
    t.annotations = Some(
        ToolAnnotations::new()
            .read_only(match s.access {
                Access::Read => true,
            })
            .destructive(false)
            .idempotent(s.idempotent)
            .open_world(false),
    );
    t
}

fn error_result(e: &ToolError) -> CallToolResult {
    let message = match e {
        ToolError::Internal(detail) => {
            tracing::error!(error = %detail, "mcp tool failed");
            "Something went wrong. Try again later.".to_owned()
        }
        e => e.to_string(),
    };
    let mut body = json!({ "code": e.code(), "message": message });
    if let ToolError::ScanTooSoon { last_scan_at } = e {
        body["last_scan_at"] = json!(last_scan_at);
    }
    CallToolResult::structured_error(body)
}

fn caller_of(context: &RequestContext<RoleServer>) -> Result<Caller, ErrorData> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|p| p.extensions.get::<Caller>())
        .cloned()
        .ok_or_else(|| ErrorData::internal_error("no caller", None))
}

/// A resource or prompt failure as a JSON-RPC error; the catalogue code rides in `data`.
fn protocol_error(e: &ToolError) -> ErrorData {
    let data = Some(json!({ "code": e.code() }));
    match e {
        ToolError::Internal(detail) => {
            tracing::error!(error = %detail, "mcp request failed");
            ErrorData::internal_error("Something went wrong. Try again later.", None)
        }
        ToolError::Unknown(what) => ErrorData::resource_not_found(format!("Unknown: {what}"), data),
        e => ErrorData::invalid_params(e.to_string(), data),
    }
}

fn to_mcp_prompt(s: crate::tools::prompts::PromptSpec) -> McpPrompt {
    let args = s
        .args
        .iter()
        .map(|a| {
            PromptArgument::new(a.name)
                .with_description(a.description)
                .with_required(a.required)
        })
        .collect();
    McpPrompt::new(s.name, Some(s.description), Some(args)).with_title(s.title)
}

fn to_mcp_message(m: OurMessage) -> PromptMessage {
    let role = match m.role {
        OurRole::User => Role::User,
        OurRole::Assistant => Role::Assistant,
    };
    PromptMessage::new_text(role, m.text)
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new("opsagent", env!("CARGO_PKG_VERSION")))
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = self.tools.specs().into_iter().map(to_mcp).collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    fn get_tool(&self, name: &str) -> Option<McpTool> {
        self.tools.get(name).map(|t| to_mcp(t.spec()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let caller = caller_of(&context)?;
        let args = Value::Object(request.arguments.unwrap_or_default());
        let result = self
            .tools
            .invoke(&caller, request.name.as_ref(), args)
            .await;
        Ok(match result {
            Err(ToolError::Unknown(m)) => return Err(ErrorData::invalid_params(m, None)),
            Ok(v) => CallToolResult::structured(v),
            Err(e) => error_result(&e),
        }
        .into())
    }

    async fn list_resources(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources = self.resources.specs().into_iter().map(|r| {
            McpResource::new(r.uri, r.name)
                .with_description(r.description)
                .with_mime_type("application/json")
        });
        Ok(ListResourcesResult::with_all_items(resources.collect()))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let caller = caller_of(&context)?;
        let doc = self
            .resources
            .read(&caller, &request.uri)
            .await
            .map_err(|e| protocol_error(&e))?;
        let contents =
            ResourceContents::text(doc.to_string(), request.uri).with_mime_type("application/json");
        Ok(ReadResourceResult::new(vec![contents]).into())
    }

    async fn list_prompts(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let prompts = self.prompts.specs().into_iter().map(to_mcp_prompt);
        Ok(ListPromptsResult::with_all_items(prompts.collect()))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let caller = caller_of(&context)?;
        let args = request
            .arguments
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| match v {
                Value::String(s) => (k, s),
                other => (k, other.to_string()),
            })
            .collect();
        let messages = self
            .prompts
            .render(&caller, &request.name, &args)
            .await
            .map_err(|e| protocol_error(&e))?;
        let result = GetPromptResult::new(messages.into_iter().map(to_mcp_message).collect());
        Ok(result.into())
    }
}
