use axum::http::StatusCode;
use loco_rs::{config::QueueConfig, prelude::*};

async fn healthz() -> Result<Response> {
    format::json(serde_json::json!({"status": "ok"}))
}

async fn redis_ok(ctx: &AppContext) -> bool {
    let Some(QueueConfig::Redis(cfg)) = &ctx.config.queue else {
        return false;
    };
    let Ok(client) = redis::Client::open(cfg.uri.as_str()) else {
        return false;
    };
    let Ok(mut conn) = client.get_multiplexed_async_connection().await else {
        return false;
    };
    redis::cmd("PING")
        .query_async::<String>(&mut conn)
        .await
        .is_ok()
}

async fn readyz(State(ctx): State<AppContext>) -> Result<Response> {
    let db_ok = ctx.db.ping().await.is_ok();
    let ok = db_ok && redis_ok(&ctx).await;
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
