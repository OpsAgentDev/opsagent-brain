//! Keyset pagination on the wire: an opaque cursor holding the last row's position (`sort_key|id`,
//! newest first; findings carry `rank|created_at|id`). Repositories page; this maps query and response.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use opsagent_core::repo::{Cursor, FindingCursor, PageOf, PageRequest};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::api_error::ApiError;

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

/// A repository keyset position as an opaque wire cursor.
pub trait WireCursor: Sized {
    fn encode(&self) -> String;
    fn decode(s: &str) -> Result<Self, ApiError>;
}

fn bad() -> ApiError {
    ApiError::invalid("cursor is not valid")
}

/// The decoded cursor split on `|` into exactly `N` parts.
fn parts<const N: usize>(s: &str) -> Result<[String; N], ApiError> {
    let raw = String::from_utf8(B64.decode(s).map_err(|_| bad())?).map_err(|_| bad())?;
    let v: Vec<String> = raw.split('|').map(str::to_owned).collect();
    v.try_into().map_err(|_| bad())
}

impl WireCursor for Cursor {
    fn encode(&self) -> String {
        B64.encode(format!("{}|{}", self.0.to_rfc3339(), self.1))
    }

    fn decode(s: &str) -> Result<Self, ApiError> {
        let [ts, id] = parts(s)?;
        Ok((
            chrono::DateTime::parse_from_rfc3339(&ts).map_err(|_| bad())?,
            id.parse().map_err(|_| bad())?,
        ))
    }
}

impl WireCursor for FindingCursor {
    fn encode(&self) -> String {
        B64.encode(format!("{}|{}|{}", self.0, self.1.to_rfc3339(), self.2))
    }

    /// A pre-severity-order cursor (`created_at|id`) has two parts and is rejected here.
    fn decode(s: &str) -> Result<Self, ApiError> {
        let [rank, ts, id] = parts(s)?;
        Ok((
            rank.parse().map_err(|_| bad())?,
            chrono::DateTime::parse_from_rfc3339(&ts).map_err(|_| bad())?,
            id.parse().map_err(|_| bad())?,
        ))
    }
}

fn limit(p: &PageParams) -> u64 {
    p.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// The repository page request for `p`; an invalid cursor is a 422.
pub fn page_request<K: WireCursor>(p: &PageParams) -> Result<PageRequest<K>, ApiError> {
    let after = p.cursor.as_deref().map(K::decode).transpose()?;
    Ok(PageRequest {
        after,
        limit: limit(p),
    })
}

impl<T> Page<T> {
    pub fn of<K: WireCursor>(got: PageOf<T, K>) -> Self {
        Page {
            items: got.items,
            next_cursor: got.next.as_ref().map(K::encode),
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
        assert_eq!(Cursor::decode(&k.encode()).unwrap(), k);
        let f = (1, ts, k.1);
        assert_eq!(FindingCursor::decode(&f.encode()).unwrap(), f);
    }

    #[test]
    fn bad_cursor_is_validation() {
        for c in ["", "!!", &B64.encode("no-separator"), &B64.encode("x|y")] {
            assert!(Cursor::decode(c).is_err(), "{c}");
            assert!(FindingCursor::decode(c).is_err(), "{c}");
        }
        // Each list rejects the other's cursor.
        let ts = chrono::DateTime::parse_from_rfc3339("2026-10-22T10:11:12+00:00").unwrap();
        let k = (ts, Uuid::now_v7());
        assert!(FindingCursor::decode(&k.encode()).is_err());
        assert!(Cursor::decode(&(0, ts, k.1).encode()).is_err());
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
