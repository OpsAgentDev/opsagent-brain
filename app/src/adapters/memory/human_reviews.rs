use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    human_review::{HumanReviewsRepo, NewReviewRequest, Payment, ReviewRequest},
    repo::RepoResult,
};
use uuid::Uuid;

use super::MemStore;

#[async_trait]
impl HumanReviewsRepo for MemStore {
    async fn insert(&self, r: &NewReviewRequest) -> RepoResult<Uuid> {
        let id = Uuid::new_v4();
        let row = ReviewRequest {
            id,
            kind: r.kind,
            finding_id: r.finding_id,
            connection_id: r.connection_id,
            target_label: r.target_label.clone(),
            note: r.note.clone(),
            price_cents: r.price_cents,
            requested_by: r.requested_by,
            requester_email: r.requester_email.clone(),
            payment: r.payment,
            paid_at: None,
            created_at: r.created_at,
        };
        self.state().human_reviews.push((r.organisation_id, row));
        Ok(id)
    }

    async fn count_since(&self, org: Uuid, since: DateTime<Utc>) -> RepoResult<u64> {
        let s = self.state();
        let n = s
            .human_reviews
            .iter()
            .filter(|(o, r)| *o == org && r.created_at > since)
            .count();
        Ok(n as u64)
    }

    async fn list(&self, org: Uuid, limit: u64) -> RepoResult<Vec<ReviewRequest>> {
        let mut rows: Vec<_> = self
            .state()
            .human_reviews
            .iter()
            .filter(|(o, _)| *o == org)
            .map(|(_, r)| r.clone())
            .collect();
        rows.sort_by_key(|a| std::cmp::Reverse((a.created_at, a.id)));
        rows.truncate(limit as usize);
        Ok(rows)
    }

    async fn mark_paid(
        &self,
        org: Uuid,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<ReviewRequest>> {
        let mut s = self.state();
        let row = s
            .human_reviews
            .iter_mut()
            .find(|(o, r)| *o == org && r.id == id && r.payment == Payment::Pending);
        Ok(row.map(|(_, r)| {
            (r.payment, r.paid_at) = (Payment::Paid, Some(now));
            r.clone()
        }))
    }

    async fn paid_at(&self, org: Uuid, at: DateTime<Utc>) -> RepoResult<Option<ReviewRequest>> {
        let s = self.state();
        let mut rows = s.human_reviews.iter();
        let found = rows.find(|(o, r)| *o == org && r.paid_at == Some(at));
        Ok(found.map(|(_, r)| r.clone()))
    }
}
