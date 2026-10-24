use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    actions::{orgs::OrgScope, uow::UnitOfWork},
    error::AppResult,
};

/// One connected agent: an unrevoked grant with its client and member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    pub grant_id: Uuid,
    pub client_name: String,
    pub client_kind: &'static str,
    pub member_email: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// The organisation's unrevoked grants: owners see all, members only their own.
pub struct ListAgents {
    uow: Arc<dyn UnitOfWork>,
}

impl ListAgents {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, scope: &OrgScope) -> AppResult<Vec<Agent>> {
        let org = scope.organisation.id;
        let owner = scope.require_owner().is_ok();
        let members = self.uow.orgs().members(org).await?;
        let mut out = Vec::new();
        for g in self.uow.oauth().grants_for_org(org).await? {
            if !owner && g.member_id != scope.member.id {
                continue;
            }
            let Some(member) = members.iter().find(|m| m.id == g.member_id) else {
                continue;
            };
            let client = self.uow.oauth().client(&g.client_id).await?;
            out.push(Agent {
                grant_id: g.id,
                client_name: client
                    .as_ref()
                    .map_or(g.client_id.clone(), |c| c.name.clone()),
                client_kind: client.map_or("dynamic", |c| c.kind.as_str()),
                member_email: member.email.as_str().into(),
                created_at: g.created_at,
                last_used_at: g.last_used_at,
            });
        }
        Ok(out)
    }
}
