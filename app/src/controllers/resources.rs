use axum::{extract::State, Json};
use chrono::{DateTime, FixedOffset};
use loco_rs::app::AppContext;
use sea_orm::{
    sea_query::{extension::postgres::PgExpr, Condition, Expr, LikeExpr},
    ColumnTrait, EntityTrait, QueryFilter, QueryTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    api_error::{ApiError, ApiQuery, Problem},
    middleware::org_scope::OrgScope,
    models::_entities::resources,
    services::pagination::{self, Page, PageParams},
};

#[derive(Serialize, ToSchema)]
pub struct ResourceSummary {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub kind: String,
    pub identity: String,
    pub name: Option<String>,
    pub region: Option<String>,
    #[schema(value_type = Object)]
    pub tags: Value,
    pub first_seen_at: DateTime<FixedOffset>,
    pub last_seen_at: DateTime<FixedOffset>,
    /// Set when the resource was missing from a complete inventory.
    pub gone_at: Option<DateTime<FixedOffset>>,
}

fn summary(r: resources::Model) -> ResourceSummary {
    ResourceSummary {
        id: r.id,
        connection_id: r.connection_id,
        kind: r.kind,
        identity: r.identity,
        name: r.name,
        region: r.region,
        tags: r.tags,
        first_seen_at: r.first_seen_at,
        last_seen_at: r.last_seen_at,
        gone_at: r.gone_at,
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ResourceFilter {
    pub connection: Option<Uuid>,
    pub kind: Option<String>,
    /// Case-insensitive substring of name or identity.
    pub q: Option<String>,
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

#[utoipa::path(get, path = "/orgs/{org}/resources", tag = "resources",
    params(super::OrgPath, ResourceFilter, PageParams),
    responses((status = 200, body = Page<ResourceSummary>), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn list(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiQuery(f): ApiQuery<ResourceFilter>,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<ResourceSummary>>, ApiError> {
    use resources::Column as C;
    let q = resources::Entity::find()
        .filter(C::OrganisationId.eq(scope.organisation_id))
        .apply_if(f.connection, |q, v| q.filter(C::ConnectionId.eq(v)))
        .apply_if(f.kind, |q, v| q.filter(C::Kind.eq(v)))
        .apply_if(f.q, |q, v| {
            q.filter(
                Condition::any()
                    .add(Expr::col(C::Name).ilike(contains(&v)))
                    .add(Expr::col(C::Identity).ilike(contains(&v))),
            )
        });
    let page = pagination::fetch(
        &ctx.db,
        q,
        (C::CreatedAt, C::Id),
        |m| (m.created_at, m.id),
        &p,
    )
    .await?;
    Ok(Json(page.map(summary)))
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new().routes(routes!(list))
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
