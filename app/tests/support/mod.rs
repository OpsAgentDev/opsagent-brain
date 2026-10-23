//! The test harness: `TestApp` boots our `AppState` and router.
mod test_app;

pub use test_app::{serve, serve_with, TestApp};
