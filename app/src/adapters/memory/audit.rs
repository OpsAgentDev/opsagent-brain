use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    audit::{AuditEntry, AuditLog, AuditRecord},
    repo::{PageOf, PageRequest, RepoResult},
};

use uuid::Uuid;

use super::{page, MemState, MemStore};

/// An entry with the id and time the database would give it.
#[derive(Clone)]
pub(super) struct Stamped {
    id: Uuid,
    at: DateTime<Utc>,
    entry: AuditEntry,
}

impl std::ops::Deref for Stamped {
    type Target = AuditEntry;
    fn deref(&self) -> &AuditEntry {
        &self.entry
    }
}

impl MemState {
    /// Appends `e`, strictly later than the entry before it (a list never ties).
    pub(super) fn push_audit(&mut self, e: AuditEntry) {
        let after = self.audit.last().map(|l| l.at + Duration::microseconds(1));
        let at = after.map_or_else(Utc::now, |a| a.max(Utc::now()));
        let (id, entry) = (Uuid::now_v7(), e);
        self.audit.push(Stamped { id, at, entry });
    }
}

#[async_trait]
impl AuditLog for MemStore {
    async fn record(&self, e: AuditEntry) -> RepoResult<()> {
        self.state().push_audit(e);
        Ok(())
    }

    async fn list(
        &self,
        organisation_id: Uuid,
        req: PageRequest,
    ) -> RepoResult<PageOf<AuditRecord>> {
        let mine = self
            .state()
            .audit
            .iter()
            .filter(|e| e.organisation_id == Some(organisation_id))
            .map(|e| AuditRecord {
                id: e.id,
                at: e.at,
                actor: e.actor,
                action: e.action.clone(),
                target: e.target.clone().map(|(k, id)| (k.to_owned(), id)),
                outcome: Some(e.outcome.clone()),
                meta: e.meta.clone(),
            })
            .collect();
        Ok(page(mine, |e| (e.at.fixed_offset(), e.id), req))
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
        let s = self.state();
        s.audit.iter().map(|e| e.entry.clone()).collect()
    }
}
