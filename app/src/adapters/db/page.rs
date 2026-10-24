use opsagent_core::repo::{Cursor, PageOf, PageRequest, RepoResult};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    Select,
};

use super::db_err;

/// One page of `select` (already tenant-filtered), newest `sort` first; `key` reads a row's
/// `(sort, id)` for the next cursor.
pub async fn page<E, C>(
    db: &C,
    select: Select<E>,
    (sort, id): (E::Column, E::Column),
    key: fn(&E::Model) -> Cursor,
    p: PageRequest,
) -> RepoResult<PageOf<E::Model>>
where
    E: EntityTrait,
    C: ConnectionTrait,
{
    let n = p.limit;
    let mut q = select.order_by_desc(sort).order_by_desc(id).limit(n + 1);
    if let Some((ts, last)) = p.after {
        q = q.filter(
            Condition::any()
                .add(sort.lt(ts))
                .add(Condition::all().add(sort.eq(ts)).add(id.lt(last))),
        );
    }
    let mut items = q.all(db).await.map_err(db_err)?;
    let more = items.len() as u64 > n;
    items.truncate(n as usize);
    let next = more.then(|| items.last().map(key)).flatten();
    Ok(PageOf { items, next })
}
