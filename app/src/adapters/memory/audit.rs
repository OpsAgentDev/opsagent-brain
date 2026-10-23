use async_trait::async_trait;
use opsagent_core::{
    audit::{AuditEntry, AuditLog},
    repo::RepoResult,
};

use super::MemStore;

#[async_trait]
impl AuditLog for MemStore {
    async fn record(&self, e: AuditEntry) -> RepoResult<()> {
        self.state().audit.push(e);
        Ok(())
    }
}
