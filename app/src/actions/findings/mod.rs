//! Finding use cases (PRD 7.4): list, detail, the customer's status actions and explanation
//! reports.
mod change_finding_status;
mod get_finding;
mod list_findings;
pub mod redact;
mod report_explanation;

pub use change_finding_status::{
    ChangeFindingStatus, FindingAction, ACCEPT_DEFAULT, ACCEPT_MAX, SNOOZE_MAX,
};
pub use get_finding::{FindingDetail, GetFinding, EVENTS_SHOWN};
pub use list_findings::ListFindings;
pub use report_explanation::ReportExplanation;

pub struct Findings {
    pub list_findings: ListFindings,
    pub get_finding: GetFinding,
    pub change_finding_status: ChangeFindingStatus,
    pub report_explanation: ReportExplanation,
}

#[cfg(test)]
pub(crate) mod test_support {
    use opsagent_core::finding::{Evidence, FindingDraft, FindingKey, Severity};
    use uuid::Uuid;

    use crate::{actions::uow::Repos, adapters::memory::MemStore};

    /// One open finding of `org` seen by a scan, with `excerpt` as its evidence.
    pub async fn seeded(store: &MemStore, org: Uuid, excerpt: &str) -> (Uuid, Uuid) {
        let (conn, run) = (Uuid::new_v4(), Uuid::new_v4());
        let draft = FindingDraft {
            key: FindingKey {
                connection_id: conn,
                check_id: "no_mfa".into(),
                resource_identity: "user/a".into(),
                variant: String::new(),
            },
            severity: Severity::High,
            title: "t".into(),
            summary: "s".into(),
            next_step: "n".into(),
            cost_monthly_usd: None,
            evidence: vec![Evidence {
                source: "iam".into(),
                excerpt: excerpt.into(),
            }],
        };
        let now = chrono::Utc::now();
        let f = store.findings();
        f.upsert_seen(org, conn, run, &[draft], now).await.unwrap();
        let id = f.list(org, Default::default(), page()).await.unwrap().items[0].id;
        (id, conn)
    }

    pub fn page() -> opsagent_core::repo::PageRequest {
        opsagent_core::repo::PageRequest {
            after: None,
            limit: 50,
        }
    }
}
