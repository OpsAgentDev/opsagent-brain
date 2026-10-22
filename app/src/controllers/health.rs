use std::{fmt::Display, future::Future, time::Duration};

use axum::http::StatusCode;
use loco_rs::{config::QueueConfig, prelude::*};
use tokio::time::timeout;

const DEP_TIMEOUT: Duration = Duration::from_secs(2);

async fn healthz() -> Result<Response> {
    format::json(serde_json::json!({"status": "ok"}))
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

async fn redis_ok(ctx: &AppContext) -> bool {
    let Some(QueueConfig::Redis(cfg)) = &ctx.config.queue else {
        tracing::warn!("readiness: redis queue is not configured");
        return false;
    };
    check("redis", async {
        let client = redis::Client::open(cfg.uri.as_str())?;
        let mut conn = client.get_multiplexed_async_connection().await?;
        redis::cmd("PING").query_async::<String>(&mut conn).await
    })
    .await
}

async fn readyz(State(ctx): State<AppContext>) -> Result<Response> {
    let ok = check("postgres", ctx.db.ping()).await && redis_ok(&ctx).await;
    let (code, status) = if ok {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    };
    Ok((code, axum::Json(serde_json::json!({"status": status}))).into_response())
}

pub fn routes() -> Routes {
    Routes::new()
        .add("/healthz", get(healthz))
        .add("/readyz", get(readyz))
}
