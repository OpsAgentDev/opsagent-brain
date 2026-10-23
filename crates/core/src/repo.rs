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

/// `limit` is already clamped by the caller.
#[derive(Debug, Clone, Copy)]
pub struct PageRequest {
    pub after: Option<Cursor>,
    pub limit: u64,
}

#[derive(Debug, Clone)]
pub struct PageOf<T> {
    pub items: Vec<T>,
    /// Position of the last item when more rows follow.
    pub next: Option<Cursor>,
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
