//! Keyset pagination shared by every list endpoint: `ORDER BY sort_key DESC, id DESC`, with an
//! opaque cursor holding the last row's `(sort_key, id)`.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use opsagent_core::repo::{Cursor, PageOf, PageRequest};
use sea_orm::{ConnectionTrait, EntityTrait, Select};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{adapters::db::page, api_error::ApiError};

pub const DEFAULT_LIMIT: u64 = 50;
pub const MAX_LIMIT: u64 = 200;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageParams {
    /// `next_cursor` from the previous page.
    pub cursor: Option<String>,
    /// Page size, default 50; values above 200 are clamped to 200.
    pub limit: Option<u64>,
}

#[derive(Serialize, ToSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Pass as `cursor` to get the next page; null on the last page.
    pub next_cursor: Option<String>,
}

pub type Key = Cursor;

pub fn encode(k: &Key) -> String {
    B64.encode(format!("{}|{}", k.0.to_rfc3339(), k.1))
}

pub fn decode(s: &str) -> Result<Key, ApiError> {
    let bad = || ApiError::invalid("cursor is not valid");
    let raw = String::from_utf8(B64.decode(s).map_err(|_| bad())?).map_err(|_| bad())?;
    let (ts, id) = raw.split_once('|').ok_or_else(bad)?;
    Ok((
        chrono::DateTime::parse_from_rfc3339(ts).map_err(|_| bad())?,
        id.parse().map_err(|_| bad())?,
    ))
}

fn limit(p: &PageParams) -> u64 {
    p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// One page of `select` (already tenant-filtered), newest `sort` first; `key` reads a row's
/// `(sort, id)` for the next cursor.
pub async fn fetch<E, C>(
    db: &C,
    select: Select<E>,
    cols: (E::Column, E::Column),
    key: fn(&E::Model) -> Key,
    p: &PageParams,
) -> Result<Page<E::Model>, ApiError>
where
    E: EntityTrait,
    C: ConnectionTrait,
{
    Ok(Page::of(page(db, select, cols, key, request(p)?).await?))
}

/// The repository page `p` asks for.
pub fn request(p: &PageParams) -> Result<PageRequest, ApiError> {
    Ok(PageRequest {
        after: p.cursor.as_deref().map(decode).transpose()?,
        limit: limit(p),
    })
}

impl<T> Page<T> {
    pub fn of(got: PageOf<T>) -> Self {
        Page {
            items: got.items,
            next_cursor: got.next.as_ref().map(encode),
        }
    }

    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(f).collect(),
            next_cursor: self.next_cursor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn cursor_round_trips_with_microseconds() {
        let ts = chrono::DateTime::parse_from_rfc3339("2026-10-22T10:11:12.123456+00:00").unwrap();
        let k = (ts, Uuid::now_v7());
        assert_eq!(decode(&encode(&k)).unwrap(), k);
    }

    #[test]
    fn bad_cursor_is_validation() {
        for c in ["", "!!", &B64.encode("no-separator"), &B64.encode("x|y")] {
            assert!(decode(c).is_err(), "{c}");
        }
    }

    #[test]
    fn limit_defaults_and_clamps() {
        let p = |l| PageParams {
            cursor: None,
            limit: l,
        };
        assert_eq!(limit(&p(None)), 50);
        assert_eq!(limit(&p(Some(500))), 200);
        assert_eq!(limit(&p(Some(0))), 1);
    }
}
