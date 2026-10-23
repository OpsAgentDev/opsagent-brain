use std::sync::Arc;

use opsagent_core::audit::AuditEntry;
use uuid::Uuid;

use super::redact::redact;
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

const NOTE_MAX: usize = 2000;

/// Records a customer report that an explanation is wrong: an audit row with the note,
/// redacted (audit metadata carries no secrets).
pub struct ReportExplanation {
    uow: Arc<dyn UnitOfWork>,
}

impl ReportExplanation {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        actor: Uuid,
        id: Uuid,
        note: &str,
    ) -> AppResult<()> {
        let f = self
            .uow
            .findings()
            .get(organisation_id, id)
            .await?
            .ok_or(AppError::NotFound)?;
        let note = note.trim();
        if note.is_empty() || note.chars().count() > NOTE_MAX {
            return Err(AppError::Invalid(format!(
                "note is required (at most {NOTE_MAX} characters)"
            )));
        }
        let (note, _) = redact(note);
        // One write: no transaction needed.
        self.uow
            .audit()
            .record(
                AuditEntry::member(
                    Some(organisation_id),
                    actor,
                    "finding.report_explanation",
                    Some(("finding", f.id.to_string())),
                )
                .with_meta(serde_json::json!({ "note": note })),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use uuid::Uuid;

    use super::ReportExplanation;
    use crate::{
        actions::findings::test_support::seeded, adapters::memory::MemStore, error::AppError,
    };

    #[tokio::test]
    async fn report_explanation_redacts_before_storing() {
        let store = MemStore::default();
        let (org, actor) = (Uuid::new_v4(), Uuid::new_v4());
        let (id, _) = seeded(&store, org, "x").await;
        let report = ReportExplanation::new(Arc::new(store.clone()));
        let note = " wrong: key AKIAABCDEFGHIJKLMNOP and ops@example.com ";
        report.run(org, actor, id, note).await.unwrap();
        let entries = store.audit_entries();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.action, "finding.report_explanation");
        assert_eq!(e.target, Some(("finding", id.to_string())));
        assert_eq!(
            e.meta["note"],
            "wrong: key [redacted:aws_key_id] and [redacted:email]"
        );
    }

    #[tokio::test]
    async fn report_explanation_refuses_empty_note_and_other_org() {
        let store = MemStore::default();
        let (org, actor) = (Uuid::new_v4(), Uuid::new_v4());
        let (id, _) = seeded(&store, org, "x").await;
        let report = ReportExplanation::new(Arc::new(store.clone()));
        let e = report.run(org, actor, id, "  ").await.unwrap_err();
        assert!(matches!(e, AppError::Invalid(_)), "{e:?}");
        let e = report
            .run(Uuid::new_v4(), actor, id, "n")
            .await
            .unwrap_err();
        assert!(matches!(e, AppError::NotFound), "{e:?}");
        assert!(store.audit_entries().is_empty());
    }
}
