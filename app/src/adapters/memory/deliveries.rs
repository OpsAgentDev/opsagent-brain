use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::repo::{PageOf, PageRequest, RepoError, RepoResult};
use opsagent_deliver::{
    model::{ConnectionSnapshot, FindingSnapshot},
    repo::{
        DeliveriesRepo, DeliveryFilter, DeliveryRow, NewDelivery, BRIEFING, FALLBACK_EMAIL,
        REVOKED, SENT, SLACK,
    },
};
use uuid::Uuid;

use super::{page, MemStore};

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

    // shortcut: snapshots join connections, findings and runs, which MemStore does not hold
    // yet; implement once those repositories' rows live in MemState.
    async fn connection_snapshot(
        &self,
        _organisation_id: Uuid,
        _connection_id: Uuid,
    ) -> RepoResult<ConnectionSnapshot> {
        Err(RepoError::NotFound)
    }

    async fn finding_snapshots(
        &self,
        _organisation_id: Uuid,
        _connection_id: Uuid,
        _since: DateTime<Utc>,
    ) -> RepoResult<Vec<FindingSnapshot>> {
        Ok(Vec::new())
    }
}
