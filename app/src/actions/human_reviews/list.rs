use std::sync::Arc;

use opsagent_core::human_review::ReviewRequest;
use uuid::Uuid;

use crate::{actions::uow::UnitOfWork, error::AppResult};

const LIMIT: u64 = 50;

/// The organisation's latest requests, newest first.
pub struct ListReviews {
    uow: Arc<dyn UnitOfWork>,
}

impl ListReviews {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, organisation_id: Uuid) -> AppResult<Vec<ReviewRequest>> {
        Ok(self
            .uow
            .human_reviews()
            .list(organisation_id, LIMIT)
            .await?)
    }
}
