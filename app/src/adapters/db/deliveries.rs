use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    connection::ConnectionStatus,
    finding::{FindingKey, Severity},
    repo::{PageOf, PageRequest, RepoError, RepoResult},
};
use opsagent_deliver::{
    model::{ConnectionSnapshot, EventKind, FindingSnapshot, FindingStatus, SeverityCounts},
    repo::{DeliveriesRepo, DeliveryFilter, DeliveryRow, NewDelivery},
};
use sea_orm::{
    prelude::DateTimeWithTimeZone, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryResult, QueryTrait, Value,
};
use uuid::Uuid;

use super::{db_err, ledger_storage::stmt, page, utc, Conn, Pg};
use crate::models::{
    _entities::{
        connections,
        deliveries::{self, Column as Col},
    },
    enum_of,
};

fn row(m: deliveries::Model) -> DeliveryRow {
    DeliveryRow {
        id: m.id,
        organisation_id: m.organisation_id,
        connection_id: m.connection_id,
        kind: m.kind,
        channel: m.channel,
        target: m.target,
        status: m.status,
        attempts: m.attempts,
        sent_at: m.sent_at.map(utc),
        created_at: utc(m.created_at),
    }
}

fn ts(r: &QueryResult, col: &str) -> RepoResult<Option<DateTime<Utc>>> {
    let t: Option<DateTimeWithTimeZone> = r.try_get("", col).map_err(db_err)?;
    Ok(t.map(utc))
}

fn get<T: sea_orm::TryGetable>(r: &QueryResult, col: &str) -> RepoResult<T> {
    r.try_get("", col).map_err(db_err)
}

impl<C: Conn> Pg<C> {
    /// Open-finding counts by severity (open and flapping) and the posture score (checks.md:
    /// `max(0, 100 - sum of weight(open))`, flapping excluded).
    async fn counts_and_score(&self, org: Uuid, id: Uuid) -> RepoResult<(SeverityCounts, f64)> {
        let rows = self
            .db()
            .query_all_raw(stmt(
                "SELECT severity, count(*) AS n, count(*) FILTER (WHERE status = 'open') AS open \
                 FROM findings WHERE organisation_id = $1 AND connection_id = $2 \
                 AND status IN ('open','flapping') GROUP BY severity",
                vec![org.into(), id.into()],
            ))
            .await
            .map_err(db_err)?;
        let (mut counts, mut sum) = (SeverityCounts::default(), 0f32);
        for r in rows {
            let n = u32::try_from(get::<i64>(&r, "n")?).unwrap_or(u32::MAX);
            let severity = enum_of::<Severity>(&get::<String>(&r, "severity")?);
            sum += severity.map_or(0.0, Severity::weight) * get::<i64>(&r, "open")? as f32;
            match severity {
                Some(Severity::Critical) => counts.critical = n,
                Some(Severity::High) => counts.high = n,
                Some(Severity::Medium) => counts.medium = n,
                Some(Severity::Low) => counts.low = n,
                Some(Severity::Info) => counts.info = n,
                None => {}
            }
        }
        Ok((counts, f64::from((100.0 - sum).max(0.0))))
    }
}

#[async_trait]
impl<C: Conn> DeliveriesRepo for Pg<C> {
    async fn list(
        &self,
        organisation_id: Uuid,
        filter: DeliveryFilter,
        req: PageRequest,
    ) -> RepoResult<PageOf<DeliveryRow>> {
        let q = deliveries::Entity::find()
            .filter(Col::OrganisationId.eq(organisation_id))
            .apply_if(filter.connection_id, |q, v| {
                q.filter(Col::ConnectionId.eq(v))
            })
            .apply_if(filter.kind, |q, v| q.filter(Col::Kind.eq(v)));
        let got = page(
            self.db(),
            q,
            (Col::CreatedAt, Col::Id),
            |m| (m.created_at, m.id),
            req,
        )
        .await?;
        Ok(PageOf {
            items: got.items.into_iter().map(row).collect(),
            next: got.next,
        })
    }

    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<DeliveryRow>> {
        let m = deliveries::Entity::find_by_id(id)
            .filter(Col::OrganisationId.eq(organisation_id))
            .one(self.db())
            .await
            .map_err(db_err)?;
        Ok(m.map(row))
    }

    async fn record(&self, organisation_id: Uuid, d: NewDelivery<'_>) -> RepoResult<()> {
        let id = Uuid::new_v5(&d.run_id, d.key.as_bytes());
        self.db()
            .execute_raw(stmt(
                "INSERT INTO deliveries (id, organisation_id, connection_id, kind, channel, target, \
                 status, external_ref, attempts, sent_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, \
                 CASE WHEN $7 IN ('sent','fallback_email') THEN now() END) \
                 ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, \
                 external_ref = coalesce(EXCLUDED.external_ref, deliveries.external_ref), \
                 attempts = deliveries.attempts + 1, \
                 sent_at = coalesce(deliveries.sent_at, EXCLUDED.sent_at), updated_at = now() \
                 WHERE deliveries.organisation_id = EXCLUDED.organisation_id",
                vec![
                    id.into(),
                    organisation_id.into(),
                    d.connection_id.into(),
                    d.kind.into(),
                    d.channel.into(),
                    d.target.into(),
                    d.status.into(),
                    d.external_ref.into(),
                ],
            ))
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn last_success_at(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        kind: &str,
        before: DateTime<Utc>,
    ) -> RepoResult<Option<DateTime<Utc>>> {
        let r = self
            .db()
            .query_one_raw(stmt(
                "SELECT max(sent_at) AS t FROM deliveries WHERE organisation_id = $1 \
                 AND connection_id = $2 AND kind = $3 AND status IN ('sent','fallback_email') \
                 AND sent_at < $4",
                vec![
                    organisation_id.into(),
                    connection_id.into(),
                    kind.into(),
                    before.into(),
                ],
            ))
            .await
            .map_err(db_err)?;
        Ok(r.map(|r| ts(&r, "t")).transpose()?.flatten())
    }

    async fn revoke_notice_due(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        before: DateTime<Utc>,
    ) -> RepoResult<bool> {
        // The revocation time is `integrations.updated_at` (set by `mark_revoked`).
        let r = self
            .db()
            .query_one_raw(stmt(
                "SELECT EXISTS (SELECT 1 FROM integrations i WHERE i.organisation_id = $1 \
                 AND i.kind = 'slack' AND i.status = 'revoked' AND NOT EXISTS (SELECT 1 FROM \
                 deliveries d WHERE d.organisation_id = $1 AND d.connection_id = $2 \
                 AND d.kind = 'briefing' AND d.status = 'fallback_email' \
                 AND d.sent_at >= i.updated_at AND d.sent_at < $3)) AS due",
                vec![organisation_id.into(), connection_id.into(), before.into()],
            ))
            .await
            .map_err(db_err)?;
        r.map_or(Ok(false), |r| get(&r, "due"))
    }

    async fn connection_snapshot(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<ConnectionSnapshot> {
        let c = connections::Entity::find_by_id(connection_id)
            .filter(connections::Column::OrganisationId.eq(organisation_id))
            .one(self.db())
            .await
            .map_err(db_err)?
            .ok_or(RepoError::NotFound)?;
        let ids = || vec![Value::from(organisation_id), Value::from(connection_id)];
        let (counts, score) = self
            .counts_and_score(organisation_id, connection_id)
            .await?;
        let scans = self
            .db()
            .query_one_raw(stmt(
                "SELECT min(finished_at) AS first, max(finished_at) AS last, \
                 (array_agg(status ORDER BY finished_at DESC))[1] AS latest FROM runs \
                 WHERE organisation_id = $1 AND connection_id = $2 AND job_type = 'full_scan' \
                 AND status IN ('done','partial') AND finished_at IS NOT NULL",
                ids(),
            ))
            .await
            .map_err(db_err)?;
        let (first, last, latest) = match &scans {
            Some(r) => (
                ts(r, "first")?,
                ts(r, "last")?,
                get::<Option<String>>(r, "latest")?,
            ),
            None => (None, None, None),
        };
        let status = enum_of::<ConnectionStatus>(&c.status)
            .ok_or_else(|| RepoError::Storage(format!("bad connection status: {}", c.status)))?;
        Ok(ConnectionSnapshot {
            id: c.id,
            display_name: c.display_name.unwrap_or(c.provider),
            status,
            status_reason: c.status_reason,
            posture_score: Some(score),
            // shortcut: no score history is stored yet; the weekly delta stays empty until it is.
            prev_posture_score: None,
            counts_by_severity: counts,
            first_scan_at: first,
            last_scan_at: last,
            partial: latest.as_deref() == Some("partial"),
        })
    }

    async fn finding_snapshots(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        since: DateTime<Utc>,
    ) -> RepoResult<Vec<FindingSnapshot>> {
        let rows = self
            .db()
            .query_all_raw(stmt(
                "SELECT f.id, f.check_id, f.resource_identity, f.variant, f.severity, f.status, \
                 f.title, f.cost_monthly_usd::float8 AS cost, f.created_at, f.updated_at, \
                 coalesce(string_agg(e.event_type, ',' ORDER BY e.created_at), '') AS events \
                 FROM findings f LEFT JOIN finding_events e ON e.finding_id = f.id AND e.created_at >= $3 \
                 WHERE f.organisation_id = $1 AND f.connection_id = $2 GROUP BY f.id \
                 HAVING f.status IN ('open','flapping') OR count(e.id) > 0",
                vec![organisation_id.into(), connection_id.into(), since.into()],
            ))
            .await
            .map_err(db_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let (Some(severity), Some(status)) = (
                enum_of::<Severity>(&get::<String>(&r, "severity")?),
                enum_of::<FindingStatus>(&get::<String>(&r, "status")?),
            ) else {
                continue;
            };
            let events: String = get(&r, "events")?;
            out.push(FindingSnapshot {
                id: get(&r, "id")?,
                key: FindingKey {
                    connection_id,
                    check_id: get(&r, "check_id")?,
                    resource_identity: get(&r, "resource_identity")?,
                    variant: get(&r, "variant")?,
                },
                severity,
                status,
                title: get(&r, "title")?,
                cost_monthly_usd: get(&r, "cost")?,
                first_seen_at: ts(&r, "created_at")?.unwrap_or_default(),
                last_seen_at: ts(&r, "updated_at")?.unwrap_or_default(),
                // Kinds the briefing does not use (accepted, snoozed) are dropped.
                events_since: events.split(',').filter_map(enum_of::<EventKind>).collect(),
            });
        }
        Ok(out)
    }
}
