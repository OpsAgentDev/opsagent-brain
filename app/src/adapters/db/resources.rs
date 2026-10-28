//! `ResourcesRepo` on SeaORM: inventory rows and their per-run history.
use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::{PageOf, PageRequest, RepoError, RepoResult},
    resource::{
        CallCount, Provider, Resource, ResourceFilter, ResourceKind, ResourceRow, ResourcesRepo,
    },
};
use sea_orm::{
    sea_query::{extension::postgres::PgExpr, Condition, Expr, LikeExpr},
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryTrait,
};
use serde_json::json;
use uuid::Uuid;

use super::{db_err, page, utc, Conn, Pg};
use crate::{
    adapters::db::ledger_storage::stmt,
    models::{_entities::resources, enum_of},
};

fn row(m: resources::Model) -> RepoResult<ResourceRow> {
    let kind: ResourceKind = enum_of(&m.kind)
        .ok_or_else(|| RepoError::Storage(format!("unknown resource kind {:?}", m.kind)))?;
    let tags: BTreeMap<String, String> = serde_json::from_value(m.tags)
        .map_err(|_| RepoError::Storage("stored tags are not a string map".into()))?;
    Ok(ResourceRow {
        id: m.id,
        connection_id: m.connection_id,
        kind,
        identity: m.identity,
        name: m.name,
        region: m.region,
        tags,
        first_seen_at: utc(m.first_seen_at),
        last_seen_at: utc(m.last_seen_at),
        gone_at: m.gone_at.map(utc),
    })
}

/// `%q%` with LIKE wildcards in `q` taken literally (backslash is Postgres's default escape;
/// an explicit `ESCAPE` renders as invalid SQL in sea-query 1.0).
fn contains(q: &str) -> LikeExpr {
    let escaped = q
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    LikeExpr::new(format!("%{escaped}%"))
}

/// Upserts one resource and its history row for `run_id`; true when it is new, came back, or
/// changed. `prev` reads the row as it was before this statement.
async fn upsert(
    db: &impl ConnectionTrait,
    (organisation_id, connection_id, run_id): (Uuid, Uuid, Uuid),
    r: &Resource,
    now: DateTime<Utc>,
) -> RepoResult<bool> {
    let row = db
        .query_one_raw(stmt(
            "WITH prev AS (SELECT kind, name, region, tags, attributes, gone_at FROM resources \
             WHERE organisation_id = $2 AND connection_id = $3 AND identity = $5) \
             INSERT INTO resources (id, organisation_id, connection_id, kind, identity, name, region, tags, attributes, \
             first_seen_at, last_seen_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10) \
             ON CONFLICT (connection_id, identity) DO UPDATE SET kind = EXCLUDED.kind, name = EXCLUDED.name, \
             region = EXCLUDED.region, tags = EXCLUDED.tags, attributes = EXCLUDED.attributes, \
             last_seen_at = $10, gone_at = NULL, updated_at = $10 \
             RETURNING id, NOT EXISTS (SELECT 1 FROM prev WHERE prev.kind = $4 \
             AND prev.name IS NOT DISTINCT FROM $6 AND prev.region IS NOT DISTINCT FROM $7 \
             AND prev.tags = $8 AND prev.attributes = $9 AND prev.gone_at IS NULL) AS changed",
            vec![
                Uuid::now_v7().into(),
                organisation_id.into(),
                connection_id.into(),
                r.kind.to_string().into(),
                r.identity.clone().into(),
                r.name.clone().into(),
                r.region.clone().into(),
                json!(r.tags).into(),
                r.attributes.clone().into(),
                now.into(),
            ],
        ))
        .await
        .map_err(db_err)?
        .ok_or_else(|| RepoError::Storage("upsert returned no row".into()))?;
    let id: Uuid = row.try_get("", "id").map_err(db_err)?;
    db.execute_raw(stmt(
        "INSERT INTO resource_history (id, resource_id, run_id, attributes, observed_at) \
         SELECT $1, $2, $3, $4, $5 WHERE NOT EXISTS \
         (SELECT 1 FROM resource_history WHERE resource_id = $2 AND run_id = $3)",
        vec![
            Uuid::now_v7().into(),
            id.into(),
            run_id.into(),
            r.attributes.clone().into(),
            r.observed_at.into(),
        ],
    ))
    .await
    .map_err(db_err)?;
    row.try_get("", "changed").map_err(db_err)
}

#[async_trait]
impl<C: Conn> ResourcesRepo for Pg<C> {
    async fn list(
        &self,
        organisation_id: Uuid,
        f: ResourceFilter,
        p: PageRequest,
    ) -> RepoResult<PageOf<ResourceRow>> {
        use resources::Column as R;
        let q = resources::Entity::find()
            .filter(R::OrganisationId.eq(organisation_id))
            .apply_if(f.connection_id, |q, v| q.filter(R::ConnectionId.eq(v)))
            .apply_if(f.kind, |q, v| q.filter(R::Kind.eq(v.to_string())))
            .apply_if(f.identity, |q, v| q.filter(R::Identity.eq(v)))
            .apply_if(f.q, |q, v| {
                q.filter(
                    Condition::any()
                        .add(Expr::col(R::Name).ilike(contains(&v)))
                        .add(Expr::col(R::Identity).ilike(contains(&v))),
                )
            });
        let rows = page(
            self.db(),
            q,
            (R::CreatedAt, R::Id),
            |m| (m.created_at, m.id),
            p,
        )
        .await?;
        let items = rows.items.into_iter().map(row).collect::<RepoResult<_>>()?;
        Ok(PageOf {
            items,
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
        let mut changed = false;
        for r in resources {
            changed |= upsert(self.db(), (organisation_id, connection_id, run_id), r, now).await?;
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
        let r = self
            .db()
            .execute_raw(stmt(
                "UPDATE resources r SET gone_at = $3, updated_at = now() \
                 WHERE r.organisation_id = $4 AND r.connection_id = $1 AND r.gone_at IS NULL AND NOT EXISTS \
                 (SELECT 1 FROM resource_history h WHERE h.resource_id = r.id AND h.run_id = $2)",
                vec![connection_id.into(), run_id.into(), now.into(), organisation_id.into()],
            ))
            .await
            .map_err(db_err)?;
        Ok(r.rows_affected())
    }

    async fn forget_run(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
    ) -> RepoResult<u64> {
        let r = self
            .db()
            .execute_raw(stmt(
                "DELETE FROM resource_history h USING resources r WHERE h.run_id = $1 \
                 AND h.resource_id = r.id AND r.organisation_id = $2 AND r.connection_id = $3",
                vec![run_id.into(), organisation_id.into(), connection_id.into()],
            ))
            .await
            .map_err(db_err)?;
        Ok(r.rows_affected())
    }

    async fn observed(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        provider: Provider,
        account: &str,
    ) -> RepoResult<Vec<Resource>> {
        let rows = self
            .db()
            .query_all_raw(stmt(
                "SELECT r.kind, r.identity, r.name, r.region, r.tags, h.attributes, h.observed_at \
                 FROM resources r JOIN resource_history h ON h.resource_id = r.id AND h.run_id = $2 \
                 WHERE r.organisation_id = $3 AND r.connection_id = $1 ORDER BY r.identity",
                vec![connection_id.into(), run_id.into(), organisation_id.into()],
            ))
            .await
            .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                let get = |c| r.try_get::<Option<String>>("", c).map_err(db_err);
                let kind: String = r.try_get("", "kind").map_err(db_err)?;
                let tags: serde_json::Value = r.try_get("", "tags").map_err(db_err)?;
                Ok(Resource {
                    provider,
                    account: account.to_owned(),
                    region: get("region")?.unwrap_or_default(),
                    kind: enum_of(&kind)
                        .ok_or_else(|| RepoError::Storage(format!("bad resource kind: {kind}")))?,
                    identity: r.try_get("", "identity").map_err(db_err)?,
                    name: get("name")?.unwrap_or_default(),
                    tags: serde_json::from_value(tags).map_err(db_err)?,
                    attributes: r.try_get("", "attributes").map_err(db_err)?,
                    observed_at: r.try_get("", "observed_at").map_err(db_err)?,
                })
            })
            .collect()
    }

    async fn replace_inventory_calls(
        &self,
        run_id: Uuid,
        provider: &str,
        service: &str,
        region: &str,
        calls: &[CallCount],
    ) -> RepoResult<()> {
        let db = self.db();
        db.execute_raw(stmt(
            "DELETE FROM api_call_stats WHERE run_id = $1 AND action = 'inventory' AND service = $2 AND region = $3",
            vec![run_id.into(), service.into(), region.into()],
        ))
        .await
        .map_err(db_err)?;
        for c in calls {
            db.execute_raw(stmt(
                "INSERT INTO api_call_stats (id, run_id, provider, service, action, region, outcome, count) \
                 VALUES ($1, $2, $3, $4, 'inventory', $5, $6, $7)",
                vec![
                    Uuid::now_v7().into(),
                    run_id.into(),
                    provider.into(),
                    c.service.clone().into(),
                    c.region.clone().into(),
                    c.outcome.into(),
                    c.count.into(),
                ],
            ))
            .await
            .map_err(db_err)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{DbBackend, QuerySelect};

    #[test]
    fn q_wildcards_are_escaped() {
        // tenancy: SQL rendering only, never executed.
        let sql = resources::Entity::find()
            .select_only()
            .filter(Expr::col(resources::Column::Name).ilike(contains("a%_\\'")))
            .build(DbBackend::Postgres)
            .to_string();
        assert!(str::contains(&sql, r"ILIKE E'%a\\%\\_\\\\\'%'"), "{sql}");
    }
}
