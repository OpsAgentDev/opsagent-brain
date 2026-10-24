use serde_json::{json, Value};
use serial_test::serial;

const BASE: &str = "http://localhost:5150";

#[tokio::test]
#[serial]
async fn protected_resource_metadata_path_and_alias() {
    crate::requests::support::serve(|request, _| async move {
        for path in [
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource",
        ] {
            let res = request.get(path).await;
            assert_eq!(res.status_code(), 200, "{path}");
            let b: Value = res.json();
            assert_eq!(b["resource"], format!("{BASE}/mcp"));
            assert_eq!(b["authorization_servers"], json!([BASE]));
            assert_eq!(b["scopes_supported"], json!(["opsagent.read"]));
            assert_eq!(b["bearer_methods_supported"], json!(["header"]));
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn as_metadata_fields() {
    crate::requests::support::serve(|request, _| async move {
        let b: Value = request
            .get("/.well-known/oauth-authorization-server")
            .await
            .json();
        assert_eq!(
            b,
            json!({
                "issuer": BASE,
                "authorization_endpoint": format!("{BASE}/oauth/authorize"),
                "token_endpoint": format!("{BASE}/oauth/token"),
                "registration_endpoint": format!("{BASE}/oauth/register"),
                "revocation_endpoint": format!("{BASE}/oauth/revoke"),
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": ["opsagent.read"],
                "client_id_metadata_document_supported": true,
                "authorization_response_iss_parameter_supported": true,
            })
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn cors_any_origin_no_credentials() {
    crate::requests::support::serve(|request, _| async move {
        let res = request
            .get("/.well-known/oauth-authorization-server")
            .add_header("origin", "https://claude.ai")
            .await;
        assert_eq!(res.header("access-control-allow-origin"), "*");
        assert!(res
            .headers()
            .get("access-control-allow-credentials")
            .is_none());
        let pre = request
            .method(axum::http::Method::OPTIONS, "/oauth/register")
            .add_header("origin", "https://claude.ai")
            .add_header("access-control-request-method", "POST")
            .add_header(
                "access-control-request-headers",
                "mcp-protocol-version,authorization",
            )
            .await;
        assert_eq!(pre.header("access-control-allow-origin"), "*");
        let allowed = pre.header("access-control-allow-headers");
        assert!(allowed.to_str().unwrap().contains("mcp-protocol-version"));
        assert!(pre
            .headers()
            .get("access-control-allow-credentials")
            .is_none());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn v1_cors_unchanged() {
    crate::requests::support::serve(|request, _| async move {
        let pre = request
            .method(axum::http::Method::OPTIONS, "/v1/orgs")
            .add_header("origin", "https://claude.ai")
            .add_header("access-control-request-method", "GET")
            .await;
        // tower-http always answers with the one allowed origin; the browser refuses claude.ai.
        assert_eq!(
            pre.header("access-control-allow-origin"),
            "http://localhost:3000"
        );
        assert_eq!(pre.header("access-control-allow-credentials"), "true");
    })
    .await;
}

fn reg(uri: &str) -> Value {
    json!({"client_name": "Demo", "redirect_uris": [uri]})
}

#[tokio::test]
#[serial]
async fn register_happy_path() {
    crate::requests::support::serve(|request, _| async move {
        let res = request
            .post("/oauth/register")
            .json(&reg("https://app.example/cb"))
            .await;
        assert_eq!(res.status_code(), 201);
        let b: Value = res.json();
        assert!(b["client_id"].as_str().unwrap().len() > 20);
        assert_eq!(b["token_endpoint_auth_method"], "none");
        assert_eq!(b["redirect_uris"], json!(["https://app.example/cb"]));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn register_rejects_javascript_redirect() {
    crate::requests::support::serve(|request, _| async move {
        let res = request
            .post("/oauth/register")
            .json(&reg("javascript:alert(1)"))
            .await;
        assert_eq!(res.status_code(), 400);
        let b: Value = res.json();
        assert_eq!(b["error"], "invalid_redirect_uri");
        assert!(b["error_description"].is_string());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn register_rate_limited_per_ip() {
    crate::requests::support::serve(|request, _| async move {
        let body = reg("https://app.example/cb");
        for _ in 0..60 {
            let res = request
                .post("/oauth/register")
                .add_header("x-forwarded-for", "198.51.100.9")
                .json(&body)
                .await;
            assert_eq!(res.status_code(), 201);
        }
        let res = request
            .post("/oauth/register")
            .add_header("x-forwarded-for", "198.51.100.9")
            .json(&body)
            .await;
        assert_eq!(res.status_code(), 429);
        assert_eq!(res.json::<Value>()["error"], "slow_down");
    })
    .await;
}
