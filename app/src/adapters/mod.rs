//! Outbound adapters: the database, in-memory fakes, and third-party APIs the app shell
//! talks to directly.
pub mod client_ip;
pub mod db;
pub mod loco_queue;
#[cfg(feature = "test-support")]
pub mod memory;
pub mod pg_queue;
pub mod rate_limiter;
pub mod redact;
pub mod slack;
#[cfg(feature = "test-support")]
pub mod test_doubles;
