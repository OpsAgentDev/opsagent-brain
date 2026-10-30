//! `FindingsRepo` on SeaORM. Events and evidence have no `organisation_id`; they are reached
//! only through a finding of the organisation.
mod seen;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    finding::{
        Finding, FindingDraft, FindingEvent, FindingFilter, FindingKey, FindingsRepo, PostureRow,
        Severity, StatusChange, StoredEvidence,
    },
    repo::{PageOf, PageRequest, RepoError, RepoResult},
};
use sea_orm::{
    sea_query::Expr, ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder,
    QueryTrait, Value,
};
use uuid::Uuid;

use super::ledger_storage::stmt;
use super::{db_err, page, utc, Conn, Pg};
use crate::models::{
    _entities::{evidence, finding_events, findings},
    enum_of, enum_str,
};

/// The connection whose findings a run touches.
#[derive(Clone, Copy)]
struct Target {
    organisation_id: Uuid,
    id: Uuid,
}

async fn exec(db: &impl ConnectionTrait, sql: &str, values: Vec<Value>) -> RepoResult<()> {
    db.execute_raw(stmt(sql, values))
        .await
        .map(|_| ())
        .map_err(db_err)
}

fn severity(stored: &str) -> RepoResult<Severity> {
    enum_of(stored).ok_or_else(|| RepoError::Storage(format!("unknown severity {stored:?}")))
}

fn finding(m: findings::Model) -> RepoResult<Finding> {
    Ok(Finding {
        id: m.id,
        organisation_id: m.organisation_id,
        connection_id: m.connection_id,
        key: FindingKey {
            connection_id: m.connection_id,
            check_id: m.check_id,
            resource_identity: m.resource_identity,
            variant: m.variant,
        },
        severity: severity(&m.severity)?,
        status: m.status,
        title: m.title,
        summary: m.summary,
        next_step: m.next_step,
        cost_monthly_usd: m.cost_monthly_usd,
        accepted_reason: m.accepted_reason,
        accepted_until: m.accepted_until.map(utc),
        snoozed_until: m.snoozed_until.map(utc),
        first_seen_run_id: m.first_seen_run_id,
        last_seen_run_id: m.last_seen_run_id,
        resolved_at: m.resolved_at.map(utc),
        resolved_reason: m.resolved_reason,
        alerted_at: m.alerted_at.map(utc),
        evidence_hash: m.evidence_hash,
        created_at: utc(m.created_at),
        updated_at: utc(m.updated_at),
    })
}

fn event(m: finding_events::Model) -> RepoResult<FindingEvent> {
    Ok(FindingEvent {
        finding_id: m.finding_id,
        kind: m.event_type,
        run_id: m.run_id,
        from_severity: m.from_severity.as_deref().map(severity).transpose()?,
        to_severity: m.to_severity.as_deref().map(severity).transpose()?,
        at: utc(m.created_at),
    })
}

impl<C: Conn> Pg<C> {
    async fn row(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<findings::Model>> {
        findings::Entity::find_by_id(id)
            .filter(findings::Column::OrganisationId.eq(organisation_id))
            .one(self.db())
            .await
            .map_err(db_err)
    }
}

#[async_trait]
impl<C: Conn> FindingsRepo for Pg<C> {
    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Finding>> {
        self.row(organisation_id, id)
            .await?
            .map(finding)
            .transpose()
    }

    async fn list(
        &self,
        organisation_id: Uuid,
        f: FindingFilter,
        p: PageRequest,
    ) -> RepoResult<PageOf<Finding>> {
        use findings::Column as F;
        let q = findings::Entity::find()
            .filter(F::OrganisationId.eq(organisation_id))
            .apply_if(f.connection_id, |q, v| q.filter(F::ConnectionId.eq(v)))
            .apply_if(f.status, |q, v| q.filter(F::Status.eq(v)))
            .apply_if(f.severity, |q, v| q.filter(F::Severity.eq(enum_str(v))))
            .apply_if(f.check_id, |q, v| q.filter(F::CheckId.eq(v)))
            .apply_if(f.variant, |q, v| q.filter(F::Variant.eq(v)))
            .apply_if(f.last_seen_since, |q, v| q.filter(F::UpdatedAt.gte(v)));
        let rows = page(
            self.db(),
            q,
            (F::CreatedAt, F::Id),
            |m| (m.created_at, m.id),
            p,
        )
        .await?;
        let items = rows
            .items
            .into_iter()
            .map(finding)
            .collect::<RepoResult<_>>()?;
        Ok(PageOf {
            items,
            next: rows.next,
        })
    }

    async fn events(
        &self,
        organisation_id: Uuid,
        finding_id: Uuid,
    ) -> RepoResult<Vec<FindingEvent>> {
        if self.row(organisation_id, finding_id).await?.is_none() {
            return Ok(vec![]);
        }
        finding_events::Entity::find()
            .filter(finding_events::Column::FindingId.eq(finding_id))
            .order_by_desc(finding_events::Column::CreatedAt)
            .order_by_desc(finding_events::Column::Id)
            .all(self.db())
            .await
            .map_err(db_err)?
            .into_iter()
            .map(event)
            .collect()
    }

    async fn evidence(
        &self,
        organisation_id: Uuid,
        finding_id: Uuid,
    ) -> RepoResult<Vec<StoredEvidence>> {
        if self.row(organisation_id, finding_id).await?.is_none() {
            return Ok(vec![]);
        }
        Ok(evidence::Entity::find()
            .filter(evidence::Column::FindingId.eq(finding_id))
            .filter(evidence::Column::ExpiresAt.gt(Utc::now()))
            .order_by_desc(evidence::Column::CreatedAt)
            .all(self.db())
            .await
            .map_err(db_err)?
            .into_iter()
            .map(|e| StoredEvidence {
                source: e.source,
                excerpt: e.excerpt,
                redacted: e.redacted,
                run_id: e.run_id,
                created_at: utc(e.created_at),
            })
            .collect())
    }

    async fn change_status(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        c: StatusChange,
    ) -> RepoResult<Finding> {
        use findings::Column as F;
        let updated = findings::Entity::update_many()
            .col_expr(F::Status, Expr::value(c.status))
            .col_expr(F::AcceptedReason, Expr::value(c.accepted_reason))
            .col_expr(F::AcceptedUntil, Expr::value(c.accepted_until))
            .col_expr(F::SnoozedUntil, Expr::value(c.snoozed_until))
            .col_expr(F::UpdatedAt, Expr::value(c.event.at))
            .filter(F::OrganisationId.eq(organisation_id))
            .filter(F::Id.eq(id))
            .filter(F::Status.eq(c.from_status))
            .exec_with_returning(self.db())
            .await
            .map_err(db_err)?
            .pop();
        let Some(updated) = updated else {
            return Err(match self.row(organisation_id, id).await? {
                Some(_) => RepoError::Conflict("finding_state_changed"),
                None => RepoError::NotFound,
            });
        };
        let e = c.event;
        exec(
            self.db(),
            "INSERT INTO finding_events (id, finding_id, run_id, event_type, from_severity, to_severity, \
             created_at, updated_at) VALUES ($1, $2, NULL, $3, $4, $5, $6, $6)",
            vec![
                Uuid::now_v7().into(),
                id.into(),
                e.kind.into(),
                e.from_severity.map(enum_str).into(),
                e.to_severity.map(enum_str).into(),
                e.at.into(),
            ],
        )
        .await?;
        finding(updated)
    }

    async fn upsert_seen(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        drafts: &[FindingDraft],
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        let c = Target {
            organisation_id,
            id: connection_id,
        };
        seen::upsert_seen(self.db(), c, run_id, drafts, now).await
    }

    /// "Unseen" is judged by `last_seen_run_id` after `upsert_seen`. When a run is applied again
    /// with fewer drafts, a finding stamped by the earlier attempt counts as seen and stays open.
    async fn resolve_unseen(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        except_check_ids: &[String],
        now: DateTime<Utc>,
    ) -> RepoResult<u64> {
        use findings::Column as F;
        let unseen = findings::Entity::find()
            .filter(F::OrganisationId.eq(organisation_id))
            .filter(F::ConnectionId.eq(connection_id))
            .filter(F::CheckId.is_not_in(except_check_ids.iter().cloned()))
            .filter(F::Status.is_in(["open", "flapping"]))
            .filter(
                Condition::any()
                    .add(F::LastSeenRunId.ne(run_id))
                    .add(F::LastSeenRunId.is_null()),
            )
            .all(self.db())
            .await
            .map_err(db_err)?;
        for f in &unseen {
            seen::resolve(self.db(), f, run_id, now).await?;
        }
        Ok(unseen.len() as u64)
    }

    async fn alert_candidates(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<Vec<Finding>> {
        use findings::Column as F;
        findings::Entity::find()
            .filter(F::OrganisationId.eq(organisation_id))
            .filter(F::ConnectionId.eq(connection_id))
            .filter(F::Severity.eq(enum_str(Severity::Critical)))
            .filter(F::Status.eq("open"))
            .filter(F::AlertedAt.is_null())
            .order_by_asc(F::CreatedAt)
            .order_by_asc(F::Id)
            .all(self.db())
            .await
            .map_err(db_err)?
            .into_iter()
            .map(finding)
            .collect()
    }

    async fn mark_alerted(
        &self,
        organisation_id: Uuid,
        ids: &[Uuid],
        at: DateTime<Utc>,
    ) -> RepoResult<()> {
        use findings::Column as F;
        findings::Entity::update_many()
            .col_expr(F::AlertedAt, Expr::value(at))
            .filter(F::OrganisationId.eq(organisation_id))
            .filter(F::Id.is_in(ids.iter().copied()))
            // A finding resolved since it was read must keep `alerted_at` cleared (it re-alerts on reopen).
            .filter(F::Status.ne("resolved"))
            .exec(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn set_evidence_hash(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        hash: &str,
    ) -> RepoResult<()> {
        exec(
            self.db(),
            "UPDATE findings SET evidence_hash = $3 WHERE id = $1 AND organisation_id = $2",
            vec![id.into(), organisation_id.into(), hash.into()],
        )
        .await
    }

    async fn posture_rows(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<Vec<PostureRow>> {
        let rows = self
            .db()
            .query_all_raw(stmt(
                "SELECT check_id, severity, count(*) AS n FROM findings WHERE organisation_id = $2 \
                 AND connection_id = $1 AND status = 'open' GROUP BY check_id, severity ORDER BY check_id, severity",
                vec![connection_id.into(), organisation_id.into()],
            ))
            .await
            .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                let s: String = r.try_get("", "severity").map_err(db_err)?;
                let n: i64 = r.try_get("", "n").map_err(db_err)?;
                Ok(PostureRow {
                    check_id: r.try_get("", "check_id").map_err(db_err)?,
                    severity: severity(&s)?,
                    open: n as u64,
                })
            })
            .collect()
    }
}
