use async_trait::async_trait;
use opsagent_core::{
    audit::{AuditEntry, AuditLog},
    repo::RepoResult,
};

use uuid::Uuid;

use super::MemStore;

#[async_trait]
impl AuditLog for MemStore {
    async fn record(&self, e: AuditEntry) -> RepoResult<()> {
        self.state().audit.push(e);
        Ok(())
    }

    async fn recorded_for_run(
        &self,
        organisation_id: Uuid,
        action: &str,
        run_id: Uuid,
    ) -> RepoResult<bool> {
        let run = run_id.to_string();
        Ok(self.state().audit.iter().any(|e| {
            e.organisation_id == Some(organisation_id)
                && e.action == action
                && e.meta["run_id"].as_str() == Some(run.as_str())
        }))
    }
}

impl MemStore {
    /// Every recorded entry, oldest first.
    pub fn audit_entries(&self) -> Vec<AuditEntry> {
        self.state().audit.clone()
    }
}
