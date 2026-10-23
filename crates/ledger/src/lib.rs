//! Idempotency backbone: fenced leases, checkpoints, side-effect ledger, retry. Framework-free.
pub mod effects;
#[cfg(feature = "test-support")]
pub mod harness;
pub mod lease;
pub mod queue;
pub mod retry;
pub mod storage;
#[cfg(feature = "test-support")]
pub mod testing;

pub use lease::{run_chunked, ChunkOutcome, Lease, RunChunkedOptions};
pub use queue::{JobKind, NewJob, Queue};
pub use redis;
pub use storage::{
    Checkpoint, CreateRunOutcome, EffectState, LedgerError, Result, RunRow, Storage,
};
