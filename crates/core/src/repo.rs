//! Shared repository vocabulary: errors, keyset pages, the clock.
use chrono::{DateTime, FixedOffset, Utc};
use uuid::Uuid;

pub type RepoResult<T> = Result<T, RepoError>;

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("storage: {0}")]
    Storage(String),
}

/// A keyset position: the last row's `(sort_key, id)`, newest first.
pub type Cursor = (DateTime<FixedOffset>, Uuid);

/// Findings page in severity order: the last row's `(severity rank, created_at, id)`, oldest
/// first within a rank. `rank` is `Severity::rank` (0 is critical).
pub type FindingCursor = (u8, DateTime<FixedOffset>, Uuid);

/// `limit` is already clamped by the caller. `K` is the repository's keyset position.
#[derive(Debug, Clone, Copy)]
pub struct PageRequest<K = Cursor> {
    pub after: Option<K>,
    pub limit: u64,
}

#[derive(Debug, Clone)]
pub struct PageOf<T, K = Cursor> {
    pub items: Vec<T>,
    /// Position of the last item when more rows follow.
    pub next: Option<K>,
}

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Always the same instant (tests, replays).
pub struct FixedClock(pub DateTime<Utc>);

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}
