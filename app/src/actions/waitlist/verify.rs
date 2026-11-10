use std::sync::Arc;

use opsagent_core::repo::Clock;

use super::WaitlistStore;
use crate::{error::AppResult, tokens::hash_token};

/// Confirms a waitlist address from its emailed link; `false` for an unknown, replaced or
/// already used token.
pub struct VerifyWaitlist {
    store: Arc<dyn WaitlistStore>,
    clock: Arc<dyn Clock>,
}

impl VerifyWaitlist {
    pub fn new(store: Arc<dyn WaitlistStore>, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }

    pub async fn run(&self, token: &str) -> AppResult<bool> {
        if token.is_empty() || token.len() > 200 {
            return Ok(false);
        }
        self.store
            .verify(&hash_token(token), self.clock.now())
            .await
    }
}
