use std::sync::Arc;

use opsagent_core::repo::Clock;
use opsagent_deliver::{model::Briefing, render_text};
use uuid::Uuid;

use super::snapshots::{briefing, deliverable};
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// What `DeliverBriefing` would send now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    /// Empty for `none`.
    pub text: String,
    /// `first_scan`, `daily`, or `none` when there is nothing to say.
    pub kind: &'static str,
}

/// The briefing as it would go out now; writes nothing.
pub struct PreviewBriefing {
    uow: Arc<dyn UnitOfWork>,
    web_base_url: String,
    clock: Arc<dyn Clock>,
}

impl PreviewBriefing {
    pub fn new(uow: Arc<dyn UnitOfWork>, web_base_url: String, clock: Arc<dyn Clock>) -> Self {
        Self {
            uow,
            web_base_url,
            clock,
        }
    }

    pub async fn run(&self, organisation_id: Uuid, connection_id: Uuid) -> AppResult<Preview> {
        let r = &*self.uow;
        let c = r
            .connections()
            .get(organisation_id, connection_id)
            .await?
            .ok_or(AppError::NotFound)?;
        let now = self.clock.now();
        let b = if deliverable(&c) {
            briefing(r, &c, now, now, &self.web_base_url).await?
        } else {
            None
        };
        let kind = match &b {
            Some(Briefing::FirstScan { .. }) => "first_scan",
            Some(Briefing::Daily { .. }) => "daily",
            None => "none",
        };
        Ok(Preview {
            text: b.as_ref().map(render_text).unwrap_or_default(),
            kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use opsagent_core::{
        repo::{PageRequest, SystemClock},
        run::{RunKey, RunStatus},
    };
    use opsagent_deliver::repo::DeliveryFilter;
    use opsagent_ledger::Storage;
    use uuid::Uuid;

    use super::PreviewBriefing;
    use crate::{
        actions::{runs::test_support::connected, uow::Repos},
        adapters::memory::MemStore,
    };

    #[tokio::test]
    async fn preview_writes_no_delivery_row() {
        let store = MemStore::default();
        let org = Uuid::new_v4();
        let c = connected(&store, org).await;
        let key = RunKey {
            organisation_id: Some(org),
            connection_id: Some(c.id),
            job_type: "full_scan".into(),
            scheduled_at: Utc::now(),
        };
        let run = store.create_run(key).await.unwrap().run;
        let fence = store.bump_fence(run.id).await.unwrap();
        store
            .set_status(run.id, fence, RunStatus::Done, None)
            .await
            .unwrap();
        let p = PreviewBriefing::new(
            Arc::new(store.clone()),
            "https://web.test".into(),
            Arc::new(SystemClock),
        );
        let got = p.run(org, c.id).await.unwrap();
        assert_eq!(got.kind, "first_scan", "{got:?}");
        assert!(got.text.contains("https://web.test"), "{}", got.text);
        let page = PageRequest {
            after: None,
            limit: 10,
        };
        let rows = store
            .deliveries()
            .list(org, DeliveryFilter::default(), page)
            .await
            .unwrap();
        assert!(rows.items.is_empty(), "preview wrote a delivery row");
    }
}
