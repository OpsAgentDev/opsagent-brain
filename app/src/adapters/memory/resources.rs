use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::{Cursor, PageOf, PageRequest, RepoResult},
    resource::{Resource, ResourceFilter, ResourceRow, ResourcesRepo},
};
use uuid::Uuid;

use super::{page, MemStore};

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
}
