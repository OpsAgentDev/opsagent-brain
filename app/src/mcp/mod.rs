//! The MCP edge: rmcp's streamable HTTP service over the `ToolRegistry`. It maps specs,
//! results and errors to MCP and owns no tool logic. `auth` resolves the caller first.
pub mod auth;

use std::sync::Arc;

use axum::http::request::Parts;
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool as McpTool, ToolAnnotations,
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
    tools::{Access, Caller, ToolError, ToolRegistry, ToolSpec},
};

#[derive(Clone)]
pub struct McpServer {
    tools: Arc<ToolRegistry>,
}

/// The service mounted at `/mcp` (behind `auth::layer`): stateless for every protocol era,
/// JSON responses (no SSE stream for the request timeout to cut), and the public body limit.
pub fn service(state: &AppState) -> StreamableHttpService<McpServer, NeverSessionManager> {
    let server = McpServer {
        tools: state.tools.clone(),
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

/// The `APP_BASE_URL` host; loopback too outside production.
fn allowed_hosts(c: &Config) -> Vec<String> {
    let base = reqwest::Url::parse(&c.api_base_url).ok();
    let mut hosts: Vec<String> = base
        .and_then(|u| u.host_str().map(str::to_owned))
        .into_iter()
        .collect();
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

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
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
        let caller = context
            .extensions
            .get::<Parts>()
            .and_then(|p| p.extensions.get::<Caller>())
            .cloned()
            .ok_or_else(|| ErrorData::internal_error("no caller", None))?;
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
}
