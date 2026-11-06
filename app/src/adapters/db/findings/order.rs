//! The findings list order: most severe first, then oldest, then id.
use opsagent_core::repo::{FindingCursor, PageOf, PageRequest, RepoResult};
use sea_orm::{
    sea_query::Expr, ConnectionTrait, ExprTrait, Order, QueryFilter, QueryOrder, QuerySelect,
    Select,
};

use super::severity;
use crate::{adapters::db::db_err, models::_entities::findings};

/// `Severity::rank` in SQL; keep the two in step (the contract tests cover it).
const RANK: &str = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 \
                    WHEN 'low' THEN 3 ELSE 4 END";

/// One page of `select` (already tenant-filtered) in severity order; `p.after` is exclusive.
pub async fn page(
    db: &impl ConnectionTrait,
    select: Select<findings::Entity>,
    p: PageRequest<FindingCursor>,
) -> RepoResult<PageOf<findings::Model, FindingCursor>> {
    let mut q = select
        .order_by(Expr::cust(RANK), Order::Asc)
        .order_by_asc(findings::Column::CreatedAt)
        .order_by_asc(findings::Column::Id)
        .limit(p.limit + 1);
    if let Some((rank, ts, id)) = p.after {
        let here = Expr::tuple([
            Expr::cust(RANK),
            Expr::col(findings::Column::CreatedAt),
            Expr::col(findings::Column::Id),
        ]);
        q = q.filter(here.gt(Expr::tuple([
            Expr::value(i32::from(rank)),
            Expr::value(ts),
            Expr::value(id),
        ])));
    }
    let mut items = q.all(db).await.map_err(db_err)?;
    let more = items.len() as u64 > p.limit;
    items.truncate(p.limit as usize);
    let next = match items.last().filter(|_| more) {
        Some(m) => Some((severity(&m.severity)?.rank(), m.created_at, m.id)),
        None => None,
    };
    Ok(PageOf { items, next })
}
