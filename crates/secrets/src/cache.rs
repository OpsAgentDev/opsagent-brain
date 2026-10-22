//! In-process DEK cache (security.md: DEKs cached for 10 minutes, kept in `Zeroizing`).
use crate::kek::{Kek, WrappedDek};
use crate::Result;
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The cache key includes the blob, so a re-wrapped DEK is never served from a stale entry.
type Key = (Uuid, u32, Vec<u8>);
type Entries = HashMap<Key, (Instant, Zeroizing<[u8; 32]>)>;

/// A `Kek` that remembers unwrapped DEKs for `ttl`; wrapping passes straight through.
pub struct CachingKek<K> {
    inner: K,
    ttl: Duration,
    deks: Mutex<Entries>,
}

impl<K: Kek> CachingKek<K> {
    pub fn new(inner: K, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            deks: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Kek> Kek for CachingKek<K> {
    fn wrap(&self, organisation_id: Uuid, dek: &[u8; 32]) -> Result<WrappedDek> {
        self.inner.wrap(organisation_id, dek)
    }

    fn unwrap(&self, organisation_id: Uuid, w: &WrappedDek) -> Result<Zeroizing<[u8; 32]>> {
        let key = (organisation_id, w.version, w.blob.clone());
        let mut deks = self.deks.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        deks.retain(|_, (at, _)| now.duration_since(*at) < self.ttl);
        if let Some((_, dek)) = deks.get(&key) {
            return Ok(dek.clone());
        }
        let dek = self.inner.unwrap(organisation_id, w)?;
        deks.insert(key, (now, dek.clone()));
        Ok(dek)
    }

    fn current_version(&self) -> u32 {
        self.inner.current_version()
    }
}
