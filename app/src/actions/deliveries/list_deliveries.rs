use std::sync::Arc;

use opsagent_core::repo::{PageOf, PageRequest};
use opsagent_deliver::repo::DeliveryFilter;
use uuid::Uuid;

use super::{with_recipients, DeliveryItem};
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// The organisation's delivery history, newest first.
pub struct ListDeliveries {
    uow: Arc<dyn UnitOfWork>,
}

impl ListDeliveries {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        filter: DeliveryFilter,
        page: PageRequest,
    ) -> AppResult<PageOf<DeliveryItem>> {
        let got = self
            .uow
            .deliveries()
            .list(organisation_id, filter, page)
            .await?;
        let items = with_recipients(&*self.uow, organisation_id, got.items).await?;
        Ok(PageOf {
            items,
            next: got.next,
        })
    }
}
