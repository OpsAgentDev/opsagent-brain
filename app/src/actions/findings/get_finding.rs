use std::sync::Arc;

use opsagent_core::ai::Explanation;
use opsagent_core::finding::{Finding, FindingEvent, StoredEvidence};
use uuid::Uuid;

use crate::{
    actions::{ai::current_hash, uow::UnitOfWork},
    error::{AppError, AppResult},
};

/// Events shown with a finding.
pub const EVENTS_SHOWN: usize = 20;

pub struct FindingDetail {
    pub finding: Finding,
    /// Newest first, at most `EVENTS_SHOWN`.
    pub events: Vec<FindingEvent>,
    /// Unexpired, newest first.
    pub evidence: Vec<StoredEvidence>,
    /// The cached explanation for the finding's current evidence, if any.
    pub explanation: Option<Explanation>,
}

/// One finding with its evidence and recent events; another org's id is `NotFound`.
#[derive(Clone)]
pub struct GetFinding {
    uow: Arc<dyn UnitOfWork>,
}

impl GetFinding {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, organisation_id: Uuid, id: Uuid) -> AppResult<FindingDetail> {
        let repo = self.uow.findings();
        let finding = repo
            .get(organisation_id, id)
            .await?
            .ok_or(AppError::NotFound)?;
        let mut events = repo.events(organisation_id, id).await?;
        events.truncate(EVENTS_SHOWN);
        let evidence = repo.evidence(organisation_id, id).await?;
        let hash = current_hash(&finding, &evidence);
        let explanation = self
            .uow
            .ai()
            .explanation(organisation_id, &finding.key.check_id, &hash)
            .await?;
        Ok(FindingDetail {
            finding,
            events,
            evidence,
            explanation,
        })
    }
}
