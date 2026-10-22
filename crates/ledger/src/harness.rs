use crate::storage::{LedgerError, Result};
use opsagent_core::run::RunStatus;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

/// Hook called right after each checkpoint write; errors on the first call.
#[derive(Clone)]
pub struct KillSwitch {
    seen: Arc<AtomicUsize>,
}

impl KillSwitch {
    pub fn after_checkpoint(&self) -> Result<()> {
        if self.seen.fetch_add(1, SeqCst) == 0 {
            return Err(LedgerError::Killed);
        }
        Ok(())
    }
}

/// Runs `job`, killing it at the first checkpoint of every run until a run finishes un-killed; returns the run count.
pub async fn kill_after_each_checkpoint<F, Fut>(mut job: F) -> Result<usize>
where
    F: FnMut(KillSwitch) -> Fut,
    Fut: Future<Output = Result<RunStatus>>,
{
    for n in 1.. {
        let ks = KillSwitch {
            seen: Arc::new(AtomicUsize::new(0)),
        };
        match job(ks).await {
            Err(LedgerError::Killed) => continue,
            Err(e) => return Err(e),
            Ok(_) => return Ok(n),
        }
    }
    unreachable!()
}
