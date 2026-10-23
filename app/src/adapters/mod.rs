//! Outbound adapters: the database, in-memory fakes, and third-party APIs the app shell
//! talks to directly.
pub mod db;
pub mod loco_queue;
#[cfg(feature = "test-support")]
pub mod memory;
pub mod rate_limiter;
pub mod redact;
pub mod slack;
