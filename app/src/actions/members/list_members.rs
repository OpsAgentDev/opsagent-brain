use std::sync::Arc;

use opsagent_core::org::Member;

use crate::{actions::orgs::OrgScope, actions::uow::UnitOfWork, error::AppResult};

/// The organisation's members.
pub struct ListMembers {
    uow: Arc<dyn UnitOfWork>,
}

impl ListMembers {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, scope: &OrgScope) -> AppResult<Vec<Member>> {
        Ok(self.uow.orgs().members(scope.organisation.id).await?)
    }
}
