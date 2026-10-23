use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::{Cursor, PageOf, PageRequest, RepoResult},
    resource::{CallCount, Provider, Resource, ResourceFilter, ResourceRow, ResourcesRepo},
};
use uuid::Uuid;

use super::{page, MemState, MemStore};

#[derive(Clone)]
pub struct ResourceMem {
    organisation_id: Uuid,
    row: ResourceRow,
    attributes: serde_json::Value,
    /// Runs that wrote a history row.
    history: Vec<Uuid>,
}

fn key(r: &ResourceMem) -> Cursor {
    (r.row.first_seen_at.into(), r.row.id)
}

/// Case-insensitive substring of name or identity, wildcards literal (as Pg's escaped ILIKE).
fn matches(r: &ResourceRow, q: &str) -> bool {
    let q = q.to_lowercase();
    let has = |s: &str| s.to_lowercase().contains(&q);
    has(&r.identity) || r.name.as_deref().is_some_and(has)
}

impl MemStore {
    /// Marks a resource missing from a complete inventory (the full-scan worker does it in SQL).
    pub fn mark_resource_gone(&self, organisation_id: Uuid, identity: &str, at: DateTime<Utc>) {
        for r in self.state().resources.iter_mut() {
            if r.organisation_id == organisation_id && r.row.identity == identity {
                r.row.gone_at = Some(at);
            }
        }
    }
}

impl MemState {
    /// Identities of the connection's resources missing from a complete inventory.
    pub(super) fn gone_identities(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> Vec<String> {
        let gone = self.resources.iter().filter(|r| {
            r.organisation_id == organisation_id
                && r.row.connection_id == connection_id
                && r.row.gone_at.is_some()
        });
        gone.map(|r| r.row.identity.clone()).collect()
    }
}

#[async_trait]
impl ResourcesRepo for MemStore {
    async fn list(
        &self,
        organisation_id: Uuid,
        f: ResourceFilter,
        p: PageRequest,
    ) -> RepoResult<PageOf<ResourceRow>> {
        let rows = self
            .state()
            .resources
            .iter()
            .filter(|r| {
                r.organisation_id == organisation_id
                    && f.connection_id.is_none_or(|c| r.row.connection_id == c)
                    && f.kind.is_none_or(|k| r.row.kind == k)
                    && f.q.as_deref().is_none_or(|q| matches(&r.row, q))
            })
            .cloned()
            .collect();
        let rows = page(rows, key, p);
        Ok(PageOf {
            items: rows.items.into_iter().map(|r| r.row).collect(),
            next: rows.next,
        })
    }

    async fn upsert_chunk(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        resources: &[Resource],
        now: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let mut s = self.state();
        let mut changed = false;
        for r in resources {
            let (name, region) = (Some(r.name.clone()), Some(r.region.clone()));
            let found = s.resources.iter_mut().find(|m| {
                m.organisation_id == organisation_id
                    && m.row.connection_id == connection_id
                    && m.row.identity == r.identity
            });
            let m = match found {
                Some(m) => m,
                None => {
                    s.resources.push(ResourceMem {
                        organisation_id,
                        row: ResourceRow {
                            id: Uuid::now_v7(),
                            connection_id,
                            kind: r.kind,
                            identity: r.identity.clone(),
                            name: None,
                            region: None,
                            tags: Default::default(),
                            first_seen_at: now,
                            last_seen_at: now,
                            gone_at: Some(now),
                        },
                        attributes: serde_json::Value::Null,
                        history: vec![],
                    });
                    s.resources.last_mut().expect("just pushed")
                }
            };
            let row = &m.row;
            changed |= row.kind != r.kind
                || row.name != name
                || row.region != region
                || row.tags != r.tags
                || m.attributes != r.attributes
                || row.gone_at.is_some();
            m.row.kind = r.kind;
            (m.row.name, m.row.region, m.row.tags) = (name, region, r.tags.clone());
            (m.row.last_seen_at, m.row.gone_at) = (now, None);
            m.attributes = r.attributes.clone();
            if !m.history.contains(&run_id) {
                m.history.push(run_id);
            }
        }
        Ok(changed)
    }

    async fn mark_unseen_gone(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<u64> {
        let mut n = 0;
        for r in self.state().resources.iter_mut() {
            if r.organisation_id == organisation_id
                && r.row.connection_id == connection_id
                && r.row.gone_at.is_none()
                && !r.history.contains(&run_id)
            {
                r.row.gone_at = Some(now);
                n += 1;
            }
        }
        Ok(n)
    }

    // shortcut: the fake keeps the latest attributes only, so it answers for the latest run;
    // keep history attributes per run if a test reads an older run.
    async fn observed(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        provider: Provider,
        account: &str,
    ) -> RepoResult<Vec<Resource>> {
        let mut out: Vec<Resource> = self
            .state()
            .resources
            .iter()
            .filter(|r| {
                r.organisation_id == organisation_id
                    && r.row.connection_id == connection_id
                    && r.history.contains(&run_id)
            })
            .map(|r| Resource {
                provider,
                account: account.to_owned(),
                region: r.row.region.clone().unwrap_or_default(),
                kind: r.row.kind,
                identity: r.row.identity.clone(),
                name: r.row.name.clone().unwrap_or_default(),
                tags: r.row.tags.clone(),
                attributes: r.attributes.clone(),
                observed_at: r.row.last_seen_at,
            })
            .collect();
        out.sort_by(|a, b| a.identity.cmp(&b.identity));
        Ok(out)
    }

    /// Nothing reads call counts through the trait, so the fake keeps none.
    async fn replace_inventory_calls(
        &self,
        _run_id: Uuid,
        _provider: &str,
        _service: &str,
        _region: &str,
        _calls: &[CallCount],
    ) -> RepoResult<()> {
        Ok(())
    }
}
