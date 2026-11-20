use std::sync::Arc;

use opsagent_core::repo::{PageOf, PageRequest};

use super::{
    audit_view::{AuditItem, Describe},
    OrgScope,
};
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// The organisation's audit log, newest first. Owners only.
pub struct ListAudit {
    uow: Arc<dyn UnitOfWork>,
}

impl ListAudit {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, scope: &OrgScope, page: PageRequest) -> AppResult<PageOf<AuditItem>> {
        scope.require_owner()?;
        let org = scope.organisation.id;
        let got = self.uow.audit().list(org, page).await?;
        let mut describe = Describe::new(&*self.uow, org).await?;
        let mut items = Vec::with_capacity(got.items.len());
        for r in got.items {
            items.push(describe.item(r).await?);
        }
        Ok(PageOf {
            items,
            next: got.next,
        })
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::{
        audit::{AuditEntry, AuditLog},
        org::{OrganisationsRepo, Role},
    };
    use uuid::Uuid;

    use super::*;
    use crate::{actions::orgs::test_support::*, adapters::memory::MemStore, error::AppError};

    fn page(limit: u64) -> PageRequest {
        PageRequest { after: None, limit }
    }

    #[tokio::test]
    async fn owners_read_their_own_entries_newest_first_and_members_are_refused() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "o@example.com", "Acme").await;
        let (_, other) = owned_org(&store, "x@example.com", "Other").await;
        let mate = user(&store, "m@example.com").await;
        store
            .add_member(org.id, mate.id, Role::Member)
            .await
            .unwrap();
        let e = AuditEntry::system(
            org.id,
            "connection.scan_started",
            ("connection", "c".into()),
            "success",
        )
        .with_meta(serde_json::json!({ "run_id": "r", "access_token": "t0ps3cret" }));
        store.record(e).await.unwrap();
        let gone = Uuid::new_v4();
        let e = AuditEntry::member(Some(org.id), gone, "member.leave", None);
        store.record(e).await.unwrap();
        let e = AuditEntry::mcp_client(org.id, Uuid::new_v4(), "mcp.tool.call", "success");
        store.record(e).await.unwrap();
        let theirs = AuditEntry::member(Some(other.id), owner.id, "theirs.only", None);
        store.record(theirs).await.unwrap();

        let list = ListAudit::new(std::sync::Arc::new(store.clone()));
        let as_owner = scope(&store, &org, &owner).await;
        let got = list.run(&as_owner, page(50)).await.unwrap();
        let rows: Vec<_> = got
            .items
            .iter()
            .map(|i| (i.action.as_str(), i.actor.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("mcp.tool.call", "agent"),
                ("member.leave", "Former member"),
                ("connection.scan_started", "OpsAgent"),
                ("org.create", "o@example.com"),
            ]
        );
        assert_eq!(got.items[2].metadata, serde_json::json!({ "run_id": "r" }));
        assert_eq!(got.items[3].target_type.as_deref(), Some("organisation"));

        // Two per page, then the rest; nothing twice.
        let first = list.run(&as_owner, page(2)).await.unwrap();
        let rest = PageRequest {
            after: first.next,
            limit: 2,
        };
        let second = list.run(&as_owner, rest).await.unwrap();
        assert!(first.next.is_some() && second.next.is_none());
        let all: Vec<_> = first.items.iter().chain(&second.items).collect();
        assert_eq!(all.len(), 4);
        assert!(all.iter().zip(&got.items).all(|(a, b)| a.id == b.id));

        let as_member = scope(&store, &org, &mate).await;
        let err = list.run(&as_member, page(50)).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden), "{err:?}");
    }
}
