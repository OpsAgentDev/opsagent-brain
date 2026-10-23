use std::{fmt::Display, future::Future, time::Duration};

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde_json::{json, Value};
use tokio::time::timeout;

use crate::state::AppState;

const DEP_TIMEOUT: Duration = Duration::from_secs(2);

async fn healthz() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

/// Loco's `/_ping` and `/_health`, kept because they answered before the switch.
async fn loco_ok() -> Json<Value> {
    Json(json!({"ok": true}))
}

/// Runs one dependency check under a timeout; logs the cause on failure.
async fn check<T, E: Display>(what: &str, fut: impl Future<Output = Result<T, E>>) -> bool {
    match timeout(DEP_TIMEOUT, fut).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            tracing::warn!(dependency = what, error = %e, "readiness check failed");
            false
        }
        Err(_) => {
            tracing::warn!(dependency = what, "readiness check timed out");
            false
        }
    }
}

async fn ready(app: &AppState) -> bool {
    check("postgres", app.db.ping()).await
        && check("redis", async {
            let mut conn = app.redis.get_multiplexed_async_connection().await?;
            opsagent_ledger::redis::cmd("PING")
                .query_async::<String>(&mut conn)
                .await
        })
        .await
}

fn status(ok: bool) -> StatusCode {
    if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn readyz(State(app): State<AppState>) -> (StatusCode, Json<Value>) {
    let ok = ready(&app).await;
    let body = json!({"status": if ok { "ok" } else { "unavailable" }});
    (status(ok), Json(body))
}

/// Loco's `/_readiness` shape (`{"ok": bool}`) over the same checks as `/readyz`.
async fn loco_readiness(State(app): State<AppState>) -> (StatusCode, Json<Value>) {
    let ok = ready(&app).await;
    (status(ok), Json(json!({"ok": ok})))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/_ping", get(loco_ok))
        .route("/_health", get(loco_ok))
        .route("/_readiness", get(loco_readiness))
}
