use crate::storage::{LedgerError, Result};
use opsagent_core::run::RunStatus;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

/// Hook called right after each checkpoint write; errors on the `kill_at`-th call.
#[derive(Clone)]
pub struct KillSwitch {
    seen: Arc<AtomicUsize>,
    kill_at: usize,
}

impl KillSwitch {
    pub fn after_checkpoint(&self) -> Result<()> {
        if self.seen.fetch_add(1, SeqCst) + 1 == self.kill_at {
            return Err(LedgerError::Killed);
        }
        Ok(())
    }
}

/// Runs `job` with a kill at checkpoint 1, 2, ... until a run finishes un-killed; returns the run count.
pub async fn kill_after_each_checkpoint<F, Fut>(mut job: F) -> Result<usize>
where
    F: FnMut(KillSwitch) -> Fut,
    Fut: Future<Output = Result<RunStatus>>,
{
    for n in 1.. {
        let ks = KillSwitch {
            seen: Arc::new(AtomicUsize::new(0)),
            kill_at: n,
        };
        match job(ks).await {
            Err(LedgerError::Killed) => continue,
            Err(e) => return Err(e),
            Ok(_) => return Ok(n),
        }
    }
    unreachable!()
}
