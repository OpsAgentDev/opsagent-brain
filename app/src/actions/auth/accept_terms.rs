use std::sync::Arc;

use opsagent_core::repo::Clock;
use uuid::Uuid;

use crate::{actions::uow::UnitOfWork, error::AppResult};

/// Records that the signed-in user agreed to the Terms and the Privacy Policy. Idempotent: the
/// first acceptance time is kept. Nothing else enforces it; the gate is in the web app.
pub struct AcceptTerms {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
}

impl AcceptTerms {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, clock }
    }

    pub async fn run(&self, user_id: Uuid) -> AppResult<()> {
        self.uow
            .users()
            .accept_terms(user_id, self.clock.now())
            .await?;
        Ok(())
    }
}
