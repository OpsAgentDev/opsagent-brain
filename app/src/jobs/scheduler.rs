//! The scheduler process: one `SchedulerTick` every `every` (60 s) until shutdown. A tick that
//! overruns skips the missed slots; the tick itself collapses missed schedules (PRD 7.3).
use std::{future::Future, sync::Arc, time::Duration};

use chrono::Utc;
use tokio::time::MissedTickBehavior;

use crate::{actions::runs::SchedulerTick, error::AppError};

pub struct Scheduler {
    pub tick: Arc<SchedulerTick>,
    pub every: Duration,
}

impl Scheduler {
    /// Ticks now and every `every` until `shutdown`; a failed tick is logged and retried at
    /// the next slot.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), AppError> {
        let mut interval = tokio::time::interval(self.every);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                _ = interval.tick() => {}
            }
            match self.tick.run(Utc::now()).await {
                Ok(Some(r)) => tracing::info!(?r, "scheduler tick"),
                Ok(None) => tracing::info!("scheduler lock held elsewhere, skipping tick"),
                Err(e) => tracing::error!(error = %e, "scheduler tick failed"),
            }
        }
        tracing::info!("scheduler stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::{actions::runs::RunDispatcher, adapters::memory::MemStore};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_loop_ticks_on_interval() {
        let store = Arc::new(MemStore::default());
        let dispatcher = Arc::new(RunDispatcher::new(store.clone()));
        let clock = Arc::new(crate::adapters::memory::FixedClock(Utc::now()));
        let gate = crate::actions::billing::BillingGate::new(store.clone(), false, clock);
        let tick = Arc::new(SchedulerTick::new(store, dispatcher, gate));
        let every = Duration::from_secs(60);
        let buf = Buf::default();
        let sub = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer({
                let b = buf.clone();
                move || b.clone()
            })
            .finish();
        let _g = tracing::subscriber::set_default(sub);
        // Slots at 0, 60 and 120 s; shutdown at 150 s.
        let shutdown = tokio::time::sleep(every * 2 + every / 2);
        Scheduler { tick, every }.run(shutdown).await.unwrap();
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out.matches("scheduler tick").count(), 3, "{out}");
        assert!(!out.contains("failed"), "{out}");
        assert!(out.contains("scheduler stopped"), "{out}");
    }
}
