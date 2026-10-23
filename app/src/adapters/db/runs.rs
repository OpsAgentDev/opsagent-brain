use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::{PageOf, PageRequest, RepoError, RepoResult},
    run::{Run, RunFilter, RunsRepo},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QueryTrait};
use serde_json::Value;
use uuid::Uuid;

use super::{db_err, page, utc, Conn, Pg};
use crate::{
    models::{_entities::runs, enum_of},
    workers::full_scan::JOB,
};

fn run(m: runs::Model) -> RepoResult<Run> {
    let status = enum_of(&m.status)
        .ok_or_else(|| RepoError::Storage(format!("unknown run status {:?}", m.status)))?;
    Ok(Run {
        id: m.id,
        organisation_id: m.organisation_id,
        connection_id: m.connection_id,
        job_type: m.job_type,
        status,
        scheduled_at: utc(m.scheduled_at),
        started_at: m.started_at.map(utc),
        finished_at: m.finished_at.map(utc),
        attempts: m.attempts,
        stats: m.checkpoint.get("stats").cloned().unwrap_or(Value::Null),
        partial_reason: m.partial_reason,
    })
}

#[async_trait]
impl<C: Conn> RunsRepo for Pg<C> {
    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Run>> {
        runs::Entity::find_by_id(id)
            .filter(runs::Column::OrganisationId.eq(organisation_id))
            .one(self.db())
            .await
            .map_err(db_err)?
            .map(run)
            .transpose()
    }

    async fn list(
        &self,
        organisation_id: Uuid,
        f: RunFilter,
        p: PageRequest,
    ) -> RepoResult<PageOf<Run>> {
        use runs::Column as Col;
        let q = runs::Entity::find()
            .filter(Col::OrganisationId.eq(organisation_id))
            .apply_if(f.connection_id, |q, v| q.filter(Col::ConnectionId.eq(v)))
            .apply_if(f.job_type, |q, v| q.filter(Col::JobType.eq(v)));
        let key = |m: &runs::Model| (m.scheduled_at, m.id);
        let got = page(self.db(), q, (Col::ScheduledAt, Col::Id), key, p).await?;
        Ok(PageOf {
            items: got.items.into_iter().map(run).collect::<RepoResult<_>>()?,
            next: got.next,
        })
    }

    async fn last_manual_scan(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<Option<DateTime<Utc>>> {
        Ok(runs::Entity::find()
            .filter(runs::Column::OrganisationId.eq(organisation_id))
            .filter(runs::Column::ConnectionId.eq(connection_id))
            .filter(runs::Column::JobType.eq(JOB))
            .order_by_desc(runs::Column::ScheduledAt)
            .one(self.db())
            .await
            .map_err(db_err)?
            .map(|r| utc(r.scheduled_at)))
    }
}
