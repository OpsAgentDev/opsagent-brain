//! Outbound adapters: the database, in-memory fakes, and third-party APIs the app shell
//! talks to directly.
pub mod client_ip;
pub mod client_metadata;
pub mod db;
#[cfg(feature = "test-support")]
pub mod memory;
pub mod model;
pub mod pg_queue;
pub mod rate_limiter;
pub mod redact;
pub mod slack;
pub mod stripe;
#[cfg(feature = "test-support")]
pub mod test_doubles;
