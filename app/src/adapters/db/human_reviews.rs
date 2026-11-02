//! `HumanReviewsRepo` on Postgres.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    human_review::{HumanReviewsRepo, NewReviewRequest, ReviewKind, ReviewRequest},
    repo::{RepoError, RepoResult},
};
use sea_orm::{
    ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set,
};
use uuid::Uuid;

use super::{db_err, utc, Conn, Pg};
use crate::models::_entities::human_review_requests::{self as hr, Column as Col};

fn row(m: hr::Model) -> RepoResult<ReviewRequest> {
    Ok(ReviewRequest {
        id: m.id,
        kind: ReviewKind::parse(&m.kind)
            .ok_or_else(|| RepoError::Storage(format!("unknown review kind {:?}", m.kind)))?,
        finding_id: m.finding_id,
        connection_id: m.connection_id,
        target_label: m.target_label,
        note: m.note,
        price_cents: m.price_cents,
        requested_by: m.requested_by,
        requester_email: m.requester_email,
        created_at: utc(m.created_at),
    })
}

#[async_trait]
impl<C: Conn> HumanReviewsRepo for Pg<C> {
    async fn insert(&self, r: &NewReviewRequest) -> RepoResult<Uuid> {
        let id = Uuid::new_v4();
        let m = hr::ActiveModel {
            id: Set(id),
            organisation_id: Set(r.organisation_id),
            kind: Set(r.kind.as_str().into()),
            finding_id: Set(r.finding_id),
            connection_id: Set(r.connection_id),
            target_label: Set(r.target_label.clone()),
            note: Set(r.note.clone()),
            price_cents: Set(r.price_cents),
            requested_by: Set(r.requested_by),
            requester_email: Set(r.requester_email.clone()),
            created_at: Set(r.created_at.into()),
        };
        hr::Entity::insert(m)
            .exec_without_returning(self.db())
            .await
            .map_err(db_err)?;
        Ok(id)
    }

    async fn count_since(&self, org: Uuid, since: DateTime<Utc>) -> RepoResult<u64> {
        hr::Entity::find()
            .filter(Col::OrganisationId.eq(org))
            .filter(Col::CreatedAt.gt(since))
            .count(self.db())
            .await
            .map_err(db_err)
    }

    async fn list(&self, org: Uuid, limit: u64) -> RepoResult<Vec<ReviewRequest>> {
        hr::Entity::find()
            .filter(Col::OrganisationId.eq(org))
            .order_by_desc(Col::CreatedAt)
            .order_by_desc(Col::Id)
            .limit(limit)
            .all(self.db())
            .await
            .map_err(db_err)?
            .into_iter()
            .map(row)
            .collect()
    }
}
