//! Audit entries as a customer reads them: who, what and on which target, by name.
use std::collections::{HashMap, HashSet};

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

/// Names for the actors and targets of one organisation's entries. Members and connections are
/// read once; findings and agents are read once per page of entries (`page`), never per entry.
pub(super) struct Describe<'a> {
    repos: &'a dyn Repos,
    organisation_id: Uuid,
    members: Vec<Member>,
    /// Connection, finding and agent names by id (ids are unique across the three).
    names: HashMap<Uuid, String>,
    /// Finding and grant ids already asked for, named or not.
    asked: HashSet<Uuid>,
}

fn uuid_of(target: &Option<(String, String)>, kind: &str) -> Option<Uuid> {
    let (k, id) = target.as_ref()?;
    (k == kind).then(|| id.parse().ok()).flatten()
}

impl<'a> Describe<'a> {
    /// Every lookup is scoped to the organisation: another organisation's id names nothing.
    pub(super) async fn new(repos: &'a dyn Repos, organisation_id: Uuid) -> AppResult<Self> {
        let connections = repos.connections().list(organisation_id).await?;
        let names = connections
            .into_iter()
            .filter_map(|c| Some((c.id, c.display_name?)));
        Ok(Self {
            repos,
            organisation_id,
            members: repos.orgs().members(organisation_id).await?,
            names: names.collect(),
            asked: HashSet::new(),
        })
    }

    /// One page of entries: at most one query for its findings and one for its agents.
    pub(super) async fn page(&mut self, records: Vec<AuditRecord>) -> AppResult<Vec<AuditItem>> {
        let (mut findings, mut grants) = (Vec::new(), Vec::new());
        for r in &records {
            let finding = uuid_of(&r.target, "finding");
            findings.extend(finding.filter(|id| self.asked.insert(*id)));
            let acted = match r.actor {
                Actor::McpClient(grant) => Some(grant),
                _ => None,
            };
            for id in [acted, uuid_of(&r.target, "oauth_grant")] {
                grants.extend(id.filter(|id| self.asked.insert(*id)));
            }
        }
        let org = self.organisation_id;
        if !findings.is_empty() {
            let titles = self.repos.findings().titles(org, &findings).await?;
            self.names.extend(titles);
        }
        if !grants.is_empty() {
            let clients = self.repos.oauth().client_names(org, &grants).await?;
            self.names.extend(clients);
        }
        Ok(records.into_iter().map(|r| self.item(r)).collect())
    }

    fn item(&self, r: AuditRecord) -> AuditItem {
        let (actor_type, actor) = match r.actor {
            Actor::System => ("system", "OpsAgent".to_owned()),
            Actor::Member(user_id) => ("member", self.member(|m| m.user_id == user_id)),
            Actor::McpClient(grant) => {
                let name = self.names.get(&grant);
                let label = name.map_or_else(|| "agent".into(), |n| format!("agent {n}"));
                ("agent", label)
            }
        };
        let target = r.target.as_ref().and_then(|(kind, id)| {
            let id = id.parse::<Uuid>().ok()?;
            match kind.as_str() {
                "connection" | "finding" | "oauth_grant" => self.names.get(&id).cloned(),
                "member" => Some(self.member(|m| m.id == id)),
                _ => None,
            }
        });
        AuditItem {
            id: r.id,
            at: r.at,
            actor_type,
            actor,
            action: r.action,
            target_type: r.target.map(|t| t.0),
            target,
            outcome: r.outcome,
            metadata: redact_json(&r.meta),
        }
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
}
