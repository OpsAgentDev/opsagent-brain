//! Idempotency backbone: fenced leases, checkpoints, side-effect ledger, retry. Framework-free.
pub mod effects;
pub mod harness;
pub mod lease;
pub mod retry;
pub mod storage;
pub mod testing;

pub use lease::{run_chunked, ChunkOutcome, Lease, RunChunkedOptions};
pub use storage::{Checkpoint, EffectState, LedgerError, Result, RunRow, Storage};
