use async_trait::async_trait;
use chrono::{DateTime, NaiveTime, Utc};
use opsagent_core::{connection::ConnectionStatus, repo::RepoResult, run::RunKey};
use opsagent_deliver::{
    repo::{DueRun, SchedulesRepo, SinceFn},
    schedule::{
        daily_at, next_after, BRIEFING, FULL_SCAN, RETENTION_CRON, VERIFY_WEEKLY, WATCH_CRON,
        WEEKLY,
    },
};
use uuid::Uuid;

use super::{MemState, MemStore, ScheduleRow};

impl MemState {
    fn org_deleted(&self, organisation_id: Uuid) -> bool {
        let o = self.orgs.iter().find(|o| o.id == organisation_id);
        o.is_some_and(|o| o.deleted_at.is_some())
    }

    fn due(&self, s: &ScheduleRow, now: DateTime<Utc>) -> bool {
        let deleted = s.organisation_id.is_some_and(|o| self.org_deleted(o));
        s.enabled && s.next_due_at.is_some_and(|t| t <= now) && !deleted
    }

    fn schedule_mut(&mut self, id: Uuid) -> Option<&mut ScheduleRow> {
        self.schedules.iter_mut().find(|s| s.id == id)
    }
}

impl MemStore {
    /// How many of the organisation's schedules are enabled.
    pub fn enabled_schedules(&self, organisation_id: Uuid) -> usize {
        let s = self.state();
        let mine = s
            .schedules
            .iter()
            .filter(|r| r.organisation_id == Some(organisation_id));
        mine.filter(|r| r.enabled).count()
    }
}

/// Row locks are not modelled: MemStore is single-threaded test support, so `lock_due` only
/// checks that the schedule is due. Lock behaviour is tested on Pg.
#[async_trait]
impl SchedulesRepo for MemStore {
    async fn create_defaults(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        (scan, briefing): (Option<NaiveTime>, Option<NaiveTime>),
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        let mut s = self.state();
        let tz = s.orgs.iter().find(|o| o.id == organisation_id);
        let tz = tz.map_or_else(|| "UTC".to_owned(), |o| o.timezone.clone());
        let scan = scan.map_or_else(|| FULL_SCAN.to_owned(), daily_at);
        let briefing = briefing.map_or_else(|| BRIEFING.to_owned(), daily_at);
        let jobs = [
            (None, "deliver_weekly", WEEKLY),
            (Some(connection_id), "full_scan", scan.as_str()),
            (Some(connection_id), "watch_scan", WATCH_CRON),
            (Some(connection_id), "verify", VERIFY_WEEKLY),
            (Some(connection_id), "deliver_briefing", briefing.as_str()),
            (Some(connection_id), "deliver_weekly", WEEKLY),
        ];
        for (conn, job, cron) in jobs {
            let exists = s.schedules.iter().any(|r| {
                r.job_type == job
                    && match conn {
                        Some(c) => r.connection_id == Some(c),
                        None => {
                            r.connection_id.is_none() && r.organisation_id == Some(organisation_id)
                        }
                    }
            });
            if !exists {
                s.schedules.push(ScheduleRow {
                    id: Uuid::now_v7(),
                    organisation_id: Some(organisation_id),
                    connection_id: conn,
                    job_type: job.into(),
                    cron_local: cron.into(),
                    timezone: tz.clone(),
                    next_due_at: next_after(cron, &tz, now),
                    enabled: true,
                });
            }
        }
        Ok(())
    }

    async fn set_cron(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        job_type: &str,
        cron: &str,
        from: SinceFn<'_>,
    ) -> RepoResult<()> {
        let mut s = self.state();
        let found = s.schedules.iter_mut().find(|r| {
            (r.organisation_id, r.connection_id, r.job_type.as_str())
                == (Some(organisation_id), Some(connection_id), job_type)
                && r.cron_local != cron
        });
        if let Some(r) = found {
            r.next_due_at = from(&r.timezone).and_then(|t| next_after(cron, &r.timezone, t));
            r.cron_local = cron.into();
        }
        Ok(())
    }

    async fn disable_for_org(&self, organisation_id: Uuid) -> RepoResult<u64> {
        let mut s = self.state();
        let mine = s
            .schedules
            .iter_mut()
            .filter(|r| r.organisation_id == Some(organisation_id));
        Ok(mine.map(|r| r.enabled = false).count() as u64)
    }

    async fn backfill_defaults(&self, now: DateTime<Utc>) -> RepoResult<u64> {
        let todo: Vec<_> = {
            let mut s = self.state();
            let global = |r: &ScheduleRow| r.organisation_id.is_none() && r.connection_id.is_none();
            if !s
                .schedules
                .iter()
                .any(|r| global(r) && r.job_type == "retention")
            {
                s.schedules.push(ScheduleRow {
                    id: Uuid::now_v7(),
                    organisation_id: None,
                    connection_id: None,
                    job_type: "retention".into(),
                    cron_local: RETENTION_CRON.into(),
                    timezone: "UTC".into(),
                    next_due_at: next_after(RETENTION_CRON, "UTC", now),
                    enabled: true,
                });
            }
            // The newest default schedule: a connection without it lacks some defaults.
            let current = |id| {
                s.schedules
                    .iter()
                    .any(|r| r.connection_id == Some(id) && r.job_type == "watch_scan")
            };
            s.connections
                .iter()
                .map(|(c, _)| c)
                .filter(|c| c.status == ConnectionStatus::Connected)
                .filter(|c| {
                    s.orgs
                        .iter()
                        .any(|o| o.id == c.organisation_id && o.deleted_at.is_none())
                })
                .filter(|c| !current(c.id))
                .map(|c| {
                    (
                        c.organisation_id,
                        c.id,
                        (c.scan_time_local, c.briefing_time_local),
                    )
                })
                .collect()
        };
        for &(org, id, times) in &todo {
            self.create_defaults(org, id, times, now).await?;
        }
        Ok(todo.len() as u64)
    }

    async fn due_ids(&self, now: DateTime<Utc>) -> RepoResult<Vec<Uuid>> {
        let s = self.state();
        let mut due: Vec<&ScheduleRow> = s.schedules.iter().filter(|r| s.due(r, now)).collect();
        due.sort_by_key(|r| r.next_due_at);
        Ok(due.into_iter().map(|r| r.id).collect())
    }

    async fn lock_due(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<(RunKey, String, String)>> {
        let s = self.state();
        let found = s.schedules.iter().find(|r| r.id == id && s.due(r, now));
        Ok(found.map(|r| {
            let key = RunKey {
                organisation_id: r.organisation_id,
                connection_id: r.connection_id,
                job_type: r.job_type.clone(),
                scheduled_at: r.next_due_at.unwrap_or(now),
            };
            (key, r.cron_local.clone(), r.timezone.clone())
        }))
    }

    async fn advance(&self, id: Uuid, next: Option<DateTime<Utc>>) -> RepoResult<()> {
        let mut s = self.state();
        if let Some(r) = s.schedule_mut(id) {
            match next {
                Some(t) => r.next_due_at = Some(t),
                None => r.enabled = false,
            }
        }
        Ok(())
    }

    async fn due_runs(&self, now: DateTime<Utc>) -> RepoResult<Vec<DueRun>> {
        let s = self.state();
        let deleted = |org: Option<Uuid>| org.is_some_and(|o| s.org_deleted(o));
        let mut due: Vec<DueRun> = s
            .parked_due(now)
            .into_iter()
            .map(|(run_id, org, job_type, marker)| DueRun {
                run_id,
                job_type,
                marker,
                organisation_deleted: deleted(org),
            })
            .collect();
        due.sort_by_key(|d| d.marker);
        Ok(due)
    }

    /// One scheduler per test: the lock is always free (lock behaviour is tested on Pg).
    async fn try_lock_scheduler(&self) -> RepoResult<bool> {
        Ok(true)
    }
}
