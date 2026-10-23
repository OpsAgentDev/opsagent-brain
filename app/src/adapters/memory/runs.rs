//! Runs: the read side (`RunsRepo`) and the ledger write side (`Storage`) on one state, with
//! the Postgres semantics (unique run key, fence checks, status timestamps).
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::{PageOf, PageRequest, RepoResult},
    run::{Run, RunFilter, RunKey, RunStatus, RunsRepo},
};
use opsagent_ledger::{
    Checkpoint, CreateRunOutcome, EffectState, LedgerError, Result, RunRow, Storage,
};
use uuid::Uuid;

use super::{MemState, MemStore};
use crate::workers::full_scan::JOB;

#[derive(Clone)]
pub(super) struct RunEntry {
    row: RunRow,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    next_attempt_at: Option<DateTime<Utc>>,
}

impl RunEntry {
    fn run(&self) -> Run {
        let r = &self.row;
        Run {
            id: r.id,
            organisation_id: r.key.organisation_id,
            connection_id: r.key.connection_id,
            job_type: r.key.job_type.clone(),
            status: r.status,
            scheduled_at: r.key.scheduled_at,
            started_at: self.started_at,
            finished_at: self.finished_at,
            attempts: i32::try_from(r.attempts).unwrap_or(i32::MAX),
            stats: r.checkpoint.stats.clone(),
            partial_reason: r.partial_reason.clone(),
        }
    }

    fn in_org(&self, organisation_id: Uuid) -> bool {
        self.row.key.organisation_id == Some(organisation_id)
    }

    fn fenced(&mut self, fence: u64) -> Result<&mut Self> {
        if self.row.fence != fence {
            return Err(LedgerError::StaleFence);
        }
        Ok(self)
    }
}

impl MemState {
    fn run_mut(&mut self, id: Uuid) -> Result<&mut RunEntry> {
        let r = self.runs.iter_mut().find(|r| r.row.id == id);
        r.ok_or(LedgerError::NotFound)
    }
}

impl MemStore {
    fn with_run<T>(&self, id: Uuid, f: impl FnOnce(&mut RunEntry) -> Result<T>) -> Result<T> {
        f(self.state().run_mut(id)?)
    }
}

#[async_trait]
impl RunsRepo for MemStore {
    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Run>> {
        let s = self.state();
        let r = s
            .runs
            .iter()
            .find(|r| r.row.id == id && r.in_org(organisation_id));
        Ok(r.map(RunEntry::run))
    }

    async fn list(
        &self,
        organisation_id: Uuid,
        f: RunFilter,
        p: PageRequest,
    ) -> RepoResult<PageOf<Run>> {
        let s = self.state();
        let mut all: Vec<Run> = s
            .runs
            .iter()
            .filter(|r| r.in_org(organisation_id))
            .map(RunEntry::run)
            .filter(|r| f.connection_id.is_none_or(|c| r.connection_id == Some(c)))
            .filter(|r| f.job_type.as_ref().is_none_or(|j| &r.job_type == j))
            .filter(|r| {
                p.after
                    .is_none_or(|(ts, id)| (r.scheduled_at, r.id) < (ts.with_timezone(&Utc), id))
            })
            .collect();
        all.sort_by_key(|r| std::cmp::Reverse((r.scheduled_at, r.id)));
        let more = all.len() as u64 > p.limit;
        all.truncate(p.limit as usize);
        let next = more
            .then(|| all.last().map(|r| (r.scheduled_at.fixed_offset(), r.id)))
            .flatten();
        Ok(PageOf { items: all, next })
    }

    async fn last_manual_scan(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<Option<DateTime<Utc>>> {
        let s = self.state();
        let scans = s.runs.iter().filter(|r| {
            r.in_org(organisation_id)
                && r.row.key.connection_id == Some(connection_id)
                && r.row.key.job_type == JOB
        });
        Ok(scans.map(|r| r.row.key.scheduled_at).max())
    }
}

#[async_trait]
impl Storage for MemStore {
    async fn create_run(&self, key: RunKey) -> Result<CreateRunOutcome> {
        let mut s = self.state();
        if let Some(r) = s.runs.iter().find(|r| r.row.key == key) {
            let run = r.row.clone();
            return Ok(CreateRunOutcome {
                run,
                created: false,
            });
        }
        let row = RunRow {
            id: Uuid::now_v7(),
            key,
            status: RunStatus::Queued,
            checkpoint: Checkpoint::default(),
            fence: 0,
            attempts: 0,
            partial_reason: None,
        };
        s.runs.push(RunEntry {
            row: row.clone(),
            started_at: None,
            finished_at: None,
            next_attempt_at: None,
        });
        Ok(CreateRunOutcome {
            run: row,
            created: true,
        })
    }

    async fn load_run(&self, id: Uuid) -> Result<RunRow> {
        self.with_run(id, |r| Ok(r.row.clone()))
    }

    async fn hold_fence(&self, id: Uuid, fence: u64) -> Result<()> {
        self.with_run(id, |r| r.fenced(fence).map(|_| ()))
    }

    async fn bump_fence(&self, id: Uuid) -> Result<u64> {
        self.with_run(id, |r| {
            r.row.fence += 1;
            Ok(r.row.fence)
        })
    }

    async fn write_checkpoint(&self, id: Uuid, fence: u64, cp: &Checkpoint) -> Result<()> {
        self.with_run(id, |r| {
            r.fenced(fence)?.row.checkpoint = cp.clone();
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
        self.with_run(id, |r| {
            let r = r.fenced(fence)?;
            let now = Utc::now();
            if status == RunStatus::Running {
                r.started_at.get_or_insert(now);
            }
            let done = !matches!(status, RunStatus::Queued | RunStatus::Running);
            r.finished_at = done.then_some(now);
            r.row.status = status;
            r.row.partial_reason = partial_reason;
            Ok(())
        })
    }

    async fn skip_run(&self, id: Uuid, reason: &str) -> Result<bool> {
        self.with_run(id, |r| {
            if r.row.status != RunStatus::Queued {
                return Ok(false);
            }
            r.row.status = RunStatus::Skipped;
            r.row.partial_reason = Some(reason.into());
            r.row.fence += 1;
            r.next_attempt_at = None;
            r.finished_at = Some(Utc::now());
            Ok(true)
        })
    }

    async fn effect_begin(&self, run_id: Uuid, key: &str) -> Result<EffectState> {
        let mut s = self.state();
        let k = (run_id, key.to_owned());
        Ok(match s.effects.get(&k) {
            None => {
                s.effects.insert(k, None);
                EffectState::New
            }
            Some(None) => EffectState::Started,
            Some(Some(r)) => EffectState::Done(r.clone()),
        })
    }

    async fn effect_done(&self, run_id: Uuid, key: &str, r: Option<String>) -> Result<()> {
        self.state()
            .effects
            .insert((run_id, key.to_owned()), Some(r));
        Ok(())
    }

    async fn mark_enqueue_pending(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        self.with_run(id, |r| {
            r.next_attempt_at = Some(at);
            Ok(())
        })
    }

    async fn clear_enqueue_marker(&self, id: Uuid, marker_at: DateTime<Utc>) -> Result<bool> {
        self.with_run(id, |r| {
            let hit = r.next_attempt_at == Some(marker_at);
            if hit {
                r.next_attempt_at = None;
            }
            Ok(hit)
        })
    }

    async fn schedule_retry(&self, id: Uuid, attempts: u32, next_at: DateTime<Utc>) -> Result<()> {
        self.with_run(id, |r| {
            r.row.attempts = attempts;
            r.row.status = RunStatus::Queued;
            r.next_attempt_at = Some(next_at);
            Ok(())
        })
    }
}
