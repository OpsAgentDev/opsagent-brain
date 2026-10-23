use async_trait::async_trait;
use chrono::{DateTime, NaiveTime, Utc};
use opsagent_core::{repo::RepoResult, run::RunKey};
use opsagent_deliver::{
    repo::{SchedulesRepo, SinceFn},
    schedule::{daily_at, next_after, BRIEFING, FULL_SCAN, VERIFY_WEEKLY, WEEKLY},
};
use sea_orm::{ConnectionTrait, QueryResult};
use uuid::Uuid;

use super::{db_err, Conn, Pg};
use crate::models::ledger_storage::stmt;

fn get<T: sea_orm::TryGetable>(r: &QueryResult, col: &str) -> RepoResult<T> {
    r.try_get("", col).map_err(db_err)
}

impl<C: Conn> Pg<C> {
    async fn org_timezone(&self, organisation_id: Uuid) -> RepoResult<String> {
        let r = self
            .db()
            .query_one_raw(stmt(
                "SELECT timezone FROM organisations WHERE id = $1",
                vec![organisation_id.into()],
            ))
            .await
            .map_err(db_err)?;
        Ok(r.map(|r| get(&r, "timezone"))
            .transpose()?
            .unwrap_or_else(|| "UTC".into()))
    }
}

#[async_trait]
impl<C: Conn> SchedulesRepo for Pg<C> {
    async fn create_defaults(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        (scan, briefing): (Option<NaiveTime>, Option<NaiveTime>),
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        let tz = self.org_timezone(organisation_id).await?;
        let scan = scan.map_or_else(|| FULL_SCAN.to_owned(), daily_at);
        let briefing = briefing.map_or_else(|| BRIEFING.to_owned(), daily_at);
        self.db()
            .execute_raw(stmt(
                "INSERT INTO schedules (id, organisation_id, job_type, cron_local, timezone, next_due_at) \
                 VALUES ($1, $2, 'deliver_weekly', $3, $4, $5) \
                 ON CONFLICT (organisation_id, job_type) WHERE connection_id IS NULL DO NOTHING",
                vec![
                    Uuid::now_v7().into(),
                    organisation_id.into(),
                    WEEKLY.into(),
                    tz.clone().into(),
                    next_after(WEEKLY, &tz, now).into(),
                ],
            ))
            .await
            .map_err(db_err)?;
        for (job, cron) in [
            ("full_scan", scan.as_str()),
            ("verify", VERIFY_WEEKLY),
            ("deliver_briefing", briefing.as_str()),
            ("deliver_weekly", WEEKLY),
        ] {
            self.db()
                .execute_raw(stmt(
                    "INSERT INTO schedules (id, organisation_id, connection_id, job_type, cron_local, timezone, next_due_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (connection_id, job_type) DO NOTHING",
                    vec![
                        Uuid::now_v7().into(),
                        organisation_id.into(),
                        connection_id.into(),
                        job.into(),
                        cron.into(),
                        tz.clone().into(),
                        next_after(cron, &tz, now).into(),
                    ],
                ))
                .await
                .map_err(db_err)?;
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
        let Some(row) = self
            .db()
            .query_one_raw(stmt(
                "SELECT id, timezone FROM schedules WHERE organisation_id = $1 AND connection_id = $2 \
                 AND job_type = $3 AND cron_local <> $4",
                vec![
                    organisation_id.into(),
                    connection_id.into(),
                    job_type.into(),
                    cron.into(),
                ],
            ))
            .await
            .map_err(db_err)?
        else {
            return Ok(());
        };
        let (id, tz): (Uuid, String) = (get(&row, "id")?, get(&row, "timezone")?);
        let next = from(&tz).and_then(|t| next_after(cron, &tz, t));
        self.db()
            .execute_raw(stmt(
                "UPDATE schedules SET cron_local = $3, next_due_at = $4, updated_at = now() \
                 WHERE organisation_id = $1 AND id = $2",
                vec![organisation_id.into(), id.into(), cron.into(), next.into()],
            ))
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn disable_for_org(&self, organisation_id: Uuid) -> RepoResult<u64> {
        let done = self
            .db()
            .execute_raw(stmt(
                "UPDATE schedules SET enabled = false, updated_at = now() WHERE organisation_id = $1",
                vec![organisation_id.into()],
            ))
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected())
    }

    async fn backfill_defaults(&self, now: DateTime<Utc>) -> RepoResult<u64> {
        let rows = self
            .db()
            .query_all_raw(stmt(
                // tenancy: the scheduler's global pass; each row's organisation scopes its writes.
                "SELECT c.id, c.organisation_id, c.scan_time_local, c.briefing_time_local \
                 FROM connections c JOIN organisations o ON o.id = c.organisation_id \
                 WHERE c.status = 'connected' AND o.deleted_at IS NULL AND NOT EXISTS \
                 (SELECT 1 FROM schedules s WHERE s.connection_id = c.id AND s.job_type = 'deliver_briefing')",
                vec![],
            ))
            .await
            .map_err(db_err)?;
        for r in &rows {
            let times = (get(r, "scan_time_local")?, get(r, "briefing_time_local")?);
            let (org, id) = (get(r, "organisation_id")?, get(r, "id")?);
            self.create_defaults(org, id, times, now).await?;
        }
        Ok(rows.len() as u64)
    }

    async fn due_ids(&self, now: DateTime<Utc>) -> RepoResult<Vec<Uuid>> {
        let rows = self
            .db()
            .query_all_raw(stmt(
                // tenancy: the scheduler's global pass. Deleted organisations are never
                // scheduled (their schedules are disabled on delete too).
                "SELECT s.id FROM schedules s WHERE s.enabled AND s.next_due_at <= $1 AND NOT EXISTS \
                 (SELECT 1 FROM organisations o WHERE o.id = s.organisation_id AND o.deleted_at IS NOT NULL) \
                 ORDER BY s.next_due_at",
                vec![now.into()],
            ))
            .await
            .map_err(db_err)?;
        rows.iter().map(|r| get(r, "id")).collect()
    }

    async fn lock_due(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<(RunKey, String, String)>> {
        let Some(s) = self
            .db()
            .query_one_raw(stmt(
                // tenancy: the scheduler's global pass, by an id from `due_ids`.
                "SELECT s.organisation_id, s.connection_id, s.job_type, s.cron_local, s.timezone, s.next_due_at \
                 FROM schedules s WHERE s.id = $1 AND s.enabled AND s.next_due_at <= $2 \
                 AND NOT EXISTS (SELECT 1 FROM organisations o WHERE o.id = s.organisation_id AND o.deleted_at IS NOT NULL) \
                 FOR UPDATE OF s SKIP LOCKED",
                vec![id.into(), now.into()],
            ))
            .await
            .map_err(db_err)?
        else {
            return Ok(None);
        };
        let key = RunKey {
            organisation_id: get(&s, "organisation_id")?,
            connection_id: get(&s, "connection_id")?,
            job_type: get(&s, "job_type")?,
            scheduled_at: get(&s, "next_due_at")?,
        };
        Ok(Some((key, get(&s, "cron_local")?, get(&s, "timezone")?)))
    }

    async fn advance(&self, id: Uuid, next: Option<DateTime<Utc>>) -> RepoResult<()> {
        // tenancy: the scheduler serves every organisation; the row was locked by id just before.
        let st = match next {
            Some(t) => stmt(
                "UPDATE schedules SET next_due_at = $2, updated_at = now() WHERE id = $1",
                vec![id.into(), t.into()],
            ),
            // tenancy: as above.
            None => stmt(
                "UPDATE schedules SET enabled = false, updated_at = now() WHERE id = $1",
                vec![id.into()],
            ),
        };
        self.db().execute_raw(st).await.map(|_| ()).map_err(db_err)
    }
}
