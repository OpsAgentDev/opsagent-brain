use std::sync::Arc;

use uuid::Uuid;

use super::{with_recipients, DeliveryItem};
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// One delivery of the organisation; `NotFound` outside it.
pub struct GetDelivery {
    uow: Arc<dyn UnitOfWork>,
}

impl GetDelivery {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, organisation_id: Uuid, id: Uuid) -> AppResult<DeliveryItem> {
        let d = self
            .uow
            .deliveries()
            .get(organisation_id, id)
            .await?
            .ok_or(AppError::NotFound)?;
        let mut one = with_recipients(&*self.uow, organisation_id, vec![d]).await?;
        one.pop().ok_or(AppError::NotFound)
    }
}
