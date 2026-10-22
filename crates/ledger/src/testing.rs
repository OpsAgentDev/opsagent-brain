//! In-memory `Storage` mirroring Postgres semantics (unique run key, fence check) for tests.
use crate::storage::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::run::{RunKey, RunStatus};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Default)]
struct Inner {
    runs: HashMap<Uuid, RunRow>,
    keys: HashMap<RunKey, Uuid>,
    effects: HashMap<(Uuid, String), Option<Option<String>>>, // None = started
}

#[derive(Default)]
pub struct MemoryStorage(Mutex<Inner>);

impl MemoryStorage {
    fn with<T>(&self, id: Uuid, f: impl FnOnce(&mut RunRow) -> Result<T>) -> Result<T> {
        let mut g = self.0.lock().unwrap();
        f(g.runs.get_mut(&id).ok_or(LedgerError::NotFound)?)
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn create_run(&self, key: RunKey) -> Result<CreateRunOutcome> {
        let mut g = self.0.lock().unwrap();
        if let Some(id) = g.keys.get(&key) {
            return Ok(CreateRunOutcome {
                run: g.runs[id].clone(),
                created: false,
            });
        }
        let row = RunRow {
            id: Uuid::now_v7(),
            key: key.clone(),
            status: RunStatus::Queued,
            checkpoint: Checkpoint::default(),
            fence: 0,
            attempts: 0,
            partial_reason: None,
        };
        g.keys.insert(key, row.id);
        g.runs.insert(row.id, row.clone());
        Ok(CreateRunOutcome {
            run: row,
            created: true,
        })
    }
    async fn load_run(&self, id: Uuid) -> Result<RunRow> {
        self.with(id, |r| Ok(r.clone()))
    }
    async fn bump_fence(&self, id: Uuid) -> Result<u64> {
        self.with(id, |r| {
            r.fence += 1;
            Ok(r.fence)
        })
    }
    async fn write_checkpoint(&self, id: Uuid, fence: u64, cp: &Checkpoint) -> Result<()> {
        self.with(id, |r| {
            if r.fence != fence {
                return Err(LedgerError::StaleFence);
            }
            r.checkpoint = cp.clone();
            Ok(())
        })
    }
    async fn set_status(
        &self,
        id: Uuid,
        fence: u64,
        status: RunStatus,
        partial_reason: Option<String>,
    ) -> Result<()> {
        self.with(id, |r| {
            if r.fence != fence {
                return Err(LedgerError::StaleFence);
            }
            r.status = status;
            r.partial_reason = partial_reason;
            Ok(())
        })
    }
    async fn effect_begin(&self, run_id: Uuid, key: &str) -> Result<EffectState> {
        let mut g = self.0.lock().unwrap();
        Ok(match g.effects.get(&(run_id, key.to_string())) {
            None => {
                g.effects.insert((run_id, key.to_string()), None);
                EffectState::New
            }
            Some(None) => EffectState::Started,
            Some(Some(r)) => EffectState::Done(r.clone()),
        })
    }
    async fn effect_done(&self, run_id: Uuid, key: &str, r: Option<String>) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .effects
            .insert((run_id, key.to_string()), Some(r));
        Ok(())
    }
    async fn schedule_retry(&self, id: Uuid, attempts: u32, _next_at: DateTime<Utc>) -> Result<()> {
        self.with(id, |r| {
            r.attempts = attempts;
            Ok(())
        })
    }
}
