//! Finding lifecycle per `full_scan` (PRD 7.4): the repository upserts what the run saw and
//! resolves what it did not; this holds the rule of which findings may resolve.
use chrono::{DateTime, Utc};
use opsagent_core::{connection::Connection, finding::FindingDraft, repo::RepoResult};
use uuid::Uuid;

use crate::actions::uow::Repos;

/// Applies one run's drafts. Every unseen finding resolves, except those of checks whose
/// capability was partial: a partial scan resolves nothing for a partial capability. `partial`
/// is run-wide today (no check reports which capability it lacked), so every check counts as
/// partial and a partial run resolves nothing.
pub(super) async fn apply(
    repos: &dyn Repos,
    c: &Connection,
    run_id: Uuid,
    drafts: &[FindingDraft],
    now: DateTime<Utc>,
    partial: bool,
) -> RepoResult<()> {
    let (org, conn, findings) = (c.organisation_id, c.id, repos.findings());
    findings.upsert_seen(org, conn, run_id, drafts, now).await?;
    if partial {
        return Ok(());
    }
    findings.resolve_unseen(org, conn, run_id, &[], now).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use opsagent_core::finding::{FindingKey, Severity};

    use super::*;
    use crate::{
        actions::{findings::test_support::page, runs::test_support::connected},
        adapters::memory::MemStore,
    };

    fn draft(c: &Connection, check_id: &str) -> FindingDraft {
        FindingDraft {
            key: FindingKey {
                connection_id: c.id,
                check_id: check_id.into(),
                resource_identity: "user/a".into(),
                variant: String::new(),
            },
            severity: Severity::High,
            title: "t".into(),
            summary: "s".into(),
            next_step: "n".into(),
            cost_monthly_usd: None,
            evidence: vec![],
        }
    }

    async fn status(store: &MemStore, c: &Connection) -> String {
        let all = store
            .findings()
            .list(c.organisation_id, Default::default(), page());
        all.await.unwrap().items[0].status.clone()
    }

    #[tokio::test]
    async fn partial_capability_resolves_nothing_for_that_check() {
        let store = MemStore::default();
        let c = connected(&store, Uuid::new_v4()).await;
        let now = Utc::now();
        let seen = [draft(&c, "no_mfa")];
        apply(&store, &c, Uuid::new_v4(), &seen, now, false)
            .await
            .unwrap();
        assert_eq!(status(&store, &c).await, "open");
        // The check could not be fed this run: its unseen finding stays open.
        apply(&store, &c, Uuid::new_v4(), &[], now, true)
            .await
            .unwrap();
        assert_eq!(status(&store, &c).await, "open");
        // A complete run that does not see it resolves it.
        apply(&store, &c, Uuid::new_v4(), &[], now, false)
            .await
            .unwrap();
        assert_eq!(status(&store, &c).await, "resolved");
    }
}
