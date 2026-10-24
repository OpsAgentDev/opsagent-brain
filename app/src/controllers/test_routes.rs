//! Routes that exist only in test builds (`test-support`), to drive the timeout and panic layers.
use std::time::Duration;

use axum::{routing::get, Router};

use crate::state::AppState;

async fn slow() -> &'static str {
    tokio::time::sleep(Duration::from_secs(31)).await;
    "too late"
}

async fn panic() -> &'static str {
    panic!("test route panicked")
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/_test/slow", get(slow))
        .route("/_test/panic", get(panic))
}
