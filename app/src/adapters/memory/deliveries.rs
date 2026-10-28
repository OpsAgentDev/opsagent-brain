use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    connection::Posture,
    finding::{FindingsRepo, Severity},
    repo::{PageOf, PageRequest, RepoError, RepoResult},
    run::RunStatus,
};
use opsagent_deliver::{
    model::{ConnectionSnapshot, FindingSnapshot, FindingStatus, SeverityCounts},
    repo::{
        AlertTally, DeliveriesRepo, DeliveryFilter, DeliveryRow, NewDelivery, BRIEFING,
        FALLBACK_EMAIL, REVOKED, SENT, SLACK,
    },
};
use uuid::Uuid;

use super::{page, MemStore};
use crate::models::enum_of;

fn sent(status: &str) -> bool {
    status == SENT || status == FALLBACK_EMAIL
}

#[async_trait]
impl DeliveriesRepo for MemStore {
    async fn list(
        &self,
        organisation_id: Uuid,
        filter: DeliveryFilter,
        req: PageRequest,
    ) -> RepoResult<PageOf<DeliveryRow>> {
        let rows = self.state().deliveries.clone();
        let mine = rows
            .into_iter()
            .filter(|d| d.organisation_id == organisation_id)
            .filter(|d| {
                filter
                    .connection_id
                    .is_none_or(|c| d.connection_id == Some(c))
            })
            .filter(|d| filter.kind.as_ref().is_none_or(|k| &d.kind == k))
            .collect();
        Ok(page(mine, |d| (d.created_at.fixed_offset(), d.id), req))
    }

    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<DeliveryRow>> {
        let s = self.state();
        let found = s
            .deliveries
            .iter()
            .find(|d| (d.organisation_id, d.id) == (organisation_id, id));
        Ok(found.cloned())
    }

    async fn record(&self, organisation_id: Uuid, n: NewDelivery<'_>) -> RepoResult<()> {
        let id = Uuid::new_v5(&n.run_id, n.key.as_bytes());
        let now = Utc::now();
        let sent_at = sent(n.status).then_some(now);
        let mut s = self.state();
        match s.deliveries.iter_mut().find(|d| d.id == id) {
            Some(d) if d.organisation_id == organisation_id => {
                d.status = n.status.into();
                d.attempts += 1;
                d.sent_at = d.sent_at.or(sent_at);
            }
            Some(_) => {}
            None => s.deliveries.push(DeliveryRow {
                id,
                organisation_id,
                connection_id: n.connection_id,
                kind: n.kind.into(),
                channel: n.channel.into(),
                target: n.target.into(),
                status: n.status.into(),
                attempts: 1,
                sent_at,
                created_at: now,
            }),
        }
        Ok(())
    }

    async fn last_success_at(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        kind: &str,
        before: DateTime<Utc>,
    ) -> RepoResult<Option<DateTime<Utc>>> {
        let s = self.state();
        Ok(s.deliveries
            .iter()
            .filter(|d| {
                (d.organisation_id, d.connection_id, d.kind.as_str())
                    == (organisation_id, Some(connection_id), kind)
                    && sent(&d.status)
            })
            .filter_map(|d| d.sent_at.filter(|t| *t < before))
            .max())
    }

    async fn revoke_notice_due(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        before: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let s = self.state();
        Ok(s.integrations.iter().any(|i| {
            i.organisation_id == organisation_id
                && i.kind == SLACK
                && i.status == REVOKED
                && !s.deliveries.iter().any(|d| {
                    (
                        d.organisation_id,
                        d.connection_id,
                        d.kind.as_str(),
                        d.status.as_str(),
                    ) == (
                        organisation_id,
                        Some(connection_id),
                        BRIEFING,
                        FALLBACK_EMAIL,
                    ) && d.sent_at.is_some_and(|t| t >= i.updated_at && t < before)
                })
        }))
    }

    async fn alert_tally(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        since: DateTime<Utc>,
    ) -> RepoResult<AlertTally> {
        let s = self.state();
        let mine = |run: &Uuid| {
            s.runs.iter().any(|r| {
                let k = &r.row.key;
                r.row.id == *run
                    && (k.organisation_id, k.connection_id, k.job_type.as_str())
                        == (Some(organisation_id), Some(connection_id), "deliver_alert")
            })
        };
        let done: Vec<(Uuid, &str, DateTime<Utc>)> = s
            .effects_done_at
            .iter()
            .filter(|((run, _), _)| mine(run))
            .map(|((run, key), at)| (*run, key.as_str(), *at))
            .collect();
        let one = |k: &str| {
            k.strip_prefix("alert:")
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
        };
        Ok(AlertTally {
            since: done
                .iter()
                .filter(|(_, k, at)| one(k) && *at >= since)
                .count(),
            this_run: done
                .iter()
                .filter(|(r, k, _)| one(k) && *r == run_id)
                .count(),
            last_rollup_at: done
                .iter()
                .filter(|(_, k, at)| k.starts_with("alert:rollup:") && *at >= since)
                .map(|(_, _, at)| *at)
                .max(),
            baselined: done.iter().any(|(_, k, _)| *k == "alert:baseline"),
        })
    }

    async fn connection_snapshot(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<ConnectionSnapshot> {
        let score = Posture::from_rows(
            &FindingsRepo::posture_rows(self, organisation_id, connection_id).await?,
        )
        .score;
        let s = self.state();
        let c = s
            .connections
            .iter()
            .map(|(c, _)| c)
            .find(|c| (c.organisation_id, c.id) == (organisation_id, connection_id))
            .ok_or(RepoError::NotFound)?;
        let mut counts = SeverityCounts::default();
        for f in s.findings.iter().map(|r| &r.finding) {
            if (f.organisation_id, f.connection_id) == (organisation_id, connection_id)
                && matches!(f.status.as_str(), "open" | "flapping")
            {
                *count_of(&mut counts, f.severity) += 1;
            }
        }
        let mut scans: Vec<_> = s
            .runs
            .iter()
            .filter(|r| {
                let k = &r.row.key;
                (k.organisation_id, k.connection_id, k.job_type.as_str())
                    == (Some(organisation_id), Some(connection_id), "full_scan")
                    && matches!(r.row.status, RunStatus::Done | RunStatus::Partial)
            })
            .filter_map(|r| r.finished_at.map(|t| (t, r.row.status)))
            .collect();
        scans.sort_by_key(|(t, _)| *t);
        Ok(ConnectionSnapshot {
            id: c.id,
            display_name: c.display_name.clone().unwrap_or_else(|| c.provider.clone()),
            status: c.status,
            status_reason: c.status_reason.clone(),
            posture_score: Some(score),
            prev_posture_score: None,
            counts_by_severity: counts,
            first_scan_at: scans.first().map(|(t, _)| *t),
            last_scan_at: scans.last().map(|(t, _)| *t),
            partial: scans
                .last()
                .is_some_and(|(_, st)| *st == RunStatus::Partial),
            timezone: s
                .orgs
                .iter()
                .find(|o| o.id == organisation_id)
                .map_or_else(|| "UTC".into(), |o| o.timezone.clone()),
        })
    }

    async fn finding_snapshots(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        since: DateTime<Utc>,
    ) -> RepoResult<Vec<FindingSnapshot>> {
        let s = self.state();
        let snaps = s.findings.iter().filter_map(|r| {
            let f = &r.finding;
            if (f.organisation_id, f.connection_id) != (organisation_id, connection_id) {
                return None;
            }
            let status = enum_of::<FindingStatus>(&f.status)?;
            let recent: Vec<_> = r.events.iter().filter(|e| e.at >= since).collect();
            let live = matches!(status, FindingStatus::Open | FindingStatus::Flapping);
            (live || !recent.is_empty()).then(|| FindingSnapshot {
                id: f.id,
                key: f.key.clone(),
                severity: f.severity,
                status,
                title: f.title.clone(),
                cost_monthly_usd: f.cost_monthly_usd.and_then(|d| f64::try_from(d).ok()),
                first_seen_at: f.created_at,
                last_seen_at: f.updated_at,
                events_since: recent.iter().filter_map(|e| enum_of(&e.kind)).collect(),
                alerted_at: f.alerted_at,
            })
        });
        Ok(snaps.collect())
    }
}

fn count_of(c: &mut SeverityCounts, s: Severity) -> &mut u32 {
    match s {
        Severity::Critical => &mut c.critical,
        Severity::High => &mut c.high,
        Severity::Medium => &mut c.medium,
        Severity::Low => &mut c.low,
        Severity::Info => &mut c.info,
    }
}
