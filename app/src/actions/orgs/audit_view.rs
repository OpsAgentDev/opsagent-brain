//! Audit entries as a customer reads them: who, what and on which target, by name.
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use opsagent_core::{
    audit::{Actor, AuditRecord},
    org::Member,
};
use serde::Serialize;
use uuid::Uuid;

use crate::{actions::uow::Repos, adapters::redact::redact_json, error::AppResult};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditItem {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    /// `member`, `agent` or `system`.
    pub actor_type: &'static str,
    /// A member's name and email, `agent <client name>`, or `OpsAgent`.
    pub actor: String,
    pub action: String,
    /// What the action was on (`connection`, `member`, `finding`, ...), when it had a target.
    pub target_type: Option<String>,
    /// The target by name, where it has one and still exists.
    pub target: Option<String>,
    pub outcome: Option<String>,
    /// The entry's metadata, secrets left out (`redact_json`).
    pub metadata: serde_json::Value,
}

/// Names for the actors and targets of one organisation's entries; each id is looked up once.
pub(super) struct Describe<'a> {
    repos: &'a dyn Repos,
    organisation_id: Uuid,
    members: Vec<Member>,
    names: HashMap<(String, String), Option<String>>,
}

impl<'a> Describe<'a> {
    pub(super) async fn new(repos: &'a dyn Repos, organisation_id: Uuid) -> AppResult<Self> {
        Ok(Self {
            repos,
            organisation_id,
            members: repos.orgs().members(organisation_id).await?,
            names: HashMap::new(),
        })
    }

    pub(super) async fn item(&mut self, r: AuditRecord) -> AppResult<AuditItem> {
        let (actor_type, actor) = match r.actor {
            Actor::System => ("system", "OpsAgent".to_owned()),
            Actor::Member(user_id) => ("member", self.member(|m| m.user_id == user_id)),
            Actor::McpClient(grant) => {
                let name = self.name("oauth_grant", &grant.to_string()).await?;
                let label = name.map_or_else(|| "agent".into(), |n| format!("agent {n}"));
                ("agent", label)
            }
        };
        let target = match &r.target {
            Some((kind, id)) => self.name(kind, id).await?,
            None => None,
        };
        Ok(AuditItem {
            id: r.id,
            at: r.at,
            actor_type,
            actor,
            action: r.action,
            target_type: r.target.map(|t| t.0),
            target,
            outcome: r.outcome,
            metadata: redact_json(&r.meta),
        })
    }

    /// `Name (email)` or the email; someone who is no longer a member is not named.
    fn member(&self, is: impl Fn(&Member) -> bool) -> String {
        match self.members.iter().find(|m| is(m)) {
            Some(m) => match m.name.as_deref().filter(|n| !n.is_empty()) {
                Some(n) => format!("{n} ({})", m.email.as_str()),
                None => m.email.as_str().to_owned(),
            },
            None => "Former member".to_owned(),
        }
    }

    async fn name(&mut self, kind: &str, id: &str) -> AppResult<Option<String>> {
        let key = (kind.to_owned(), id.to_owned());
        if let Some(known) = self.names.get(&key) {
            return Ok(known.clone());
        }
        let found = self.lookup(kind, id).await?;
        self.names.insert(key, found.clone());
        Ok(found)
    }

    /// Every lookup is scoped to the organisation: another organisation's id names nothing.
    async fn lookup(&self, kind: &str, id: &str) -> AppResult<Option<String>> {
        let org = self.organisation_id;
        let Ok(id) = id.parse::<Uuid>() else {
            return Ok(None);
        };
        Ok(match kind {
            "connection" => {
                let c = self.repos.connections().get(org, id).await?;
                c.and_then(|c| c.display_name)
            }
            "finding" => self.repos.findings().get(org, id).await?.map(|f| f.title),
            "member" => Some(self.member(|m| m.id == id)),
            "oauth_grant" => match self.repos.oauth().grant(org, id).await? {
                Some(g) => {
                    let client = self.repos.oauth().client(&g.client_id).await?;
                    client.map(|c| c.name)
                }
                None => None,
            },
            _ => None,
        })
    }
}
