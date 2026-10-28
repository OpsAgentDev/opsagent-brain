#[cfg(feature = "test-support")]
use crate::harness::KillSwitch;
use crate::retry::{fail_on_storage_error, settle};
use crate::storage::{Checkpoint, LedgerError, Result, Storage};
use opsagent_core::run::RunStatus;
use redis::{aio::MultiplexedConnection, Client, Script};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Lease {
    pub run_id: Uuid,
    pub fence: u64,
    value: String,
    ttl: Duration,
}

fn lease_key(run_id: Uuid) -> String {
    format!("lease:{run_id}")
}

async fn conn(redis: &Client) -> Result<MultiplexedConnection> {
    Ok(redis.get_multiplexed_async_connection().await?)
}

const CAS_SET: &str = r#"if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('SET',KEYS[1],ARGV[2],'PX',ARGV[3]) and 1 end return 0"#;
const CAS_DEL: &str = r#"if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end"#;

// shortcut: ~51 lines, the two-phase Redis claim must stay readable in one place.
/// Claims `lease:{run}` with a `pending:` marker first, so a failed acquire never touches storage
/// (and cannot bump the live holder's fence). Only the winner bumps the fence, then upgrades the
/// marker to `{worker}:{fence}` via compare-and-set.
pub async fn acquire<S: Storage + ?Sized>(
    storage: &S,
    redis: &Client,
    run_id: Uuid,
    worker_id: &str,
    ttl: Duration,
) -> Result<Option<Lease>> {
    let key = lease_key(run_id);
    let pending = format!("pending:{worker_id}");
    let ttl_ms = ttl.as_millis() as u64;
    let mut c = conn(redis).await?;
    let ok: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg(&pending)
        .arg("NX")
        .arg("PX")
        .arg(ttl_ms)
        .query_async(&mut c)
        .await?;
    if ok.is_none() {
        return Ok(None);
    }
    let fence = match storage.bump_fence(run_id).await {
        Ok(f) => f,
        Err(e) => {
            let _: redis::RedisResult<i32> = Script::new(CAS_DEL)
                .key(&key)
                .arg(&pending)
                .invoke_async(&mut c)
                .await;
            return Err(e);
        }
    };
    let value = format!("{worker_id}:{fence}");
    let n: i32 = Script::new(CAS_SET)
        .key(&key)
        .arg(&pending)
        .arg(&value)
        .arg(ttl_ms)
        .invoke_async(&mut c)
        .await?;
    if n != 1 {
        return Err(LedgerError::LeaseHeld); // marker expired and was taken over before upgrade
    }
    Ok(Some(Lease {
        run_id,
        fence,
        value,
        ttl,
    }))
}

/// Extends the TTL only if the lease is still ours.
pub async fn heartbeat(redis: &Client, lease: &Lease) -> Result<bool> {
    let s = Script::new(
        r#"if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('PEXPIRE',KEYS[1],ARGV[2]) else return 0 end"#,
    );
    let n: i32 = s
        .key(lease_key(lease.run_id))
        .arg(&lease.value)
        .arg(lease.ttl.as_millis() as u64)
        .invoke_async(&mut conn(redis).await?)
        .await?;
    Ok(n == 1)
}

/// Deletes the lease only if it is still ours. Best effort.
pub async fn release(redis: &Client, lease: &Lease) {
    let s = Script::new(CAS_DEL);
    let Ok(mut c) = conn(redis).await else { return };
    let r: redis::RedisResult<i32> = s
        .key(lease_key(lease.run_id))
        .arg(&lease.value)
        .invoke_async(&mut c)
        .await;
    if let Err(e) = r {
        tracing::warn!(error = %e, "lease release failed");
    }
}

const CLAIM: &str = r#"local v = redis.call('GET',KEYS[1]) if not v then redis.call('SET',KEYS[1],ARGV[1],'PX',ARGV[2]) return 1 elseif v == ARGV[1] then redis.call('PEXPIRE',KEYS[1],ARGV[2]) return 1 end return 0"#;

/// Claims `key` for `owner` for `ttl`; re-entrant, so the same owner (a resumed run) claims it
/// again and refreshes the TTL. `false`: another owner holds it.
pub async fn claim(redis: &Client, key: &str, owner: &str, ttl: Duration) -> Result<bool> {
    let n: i32 = Script::new(CLAIM)
        .key(key)
        .arg(owner)
        .arg(ttl.as_millis() as u64)
        .invoke_async(&mut conn(redis).await?)
        .await?;
    Ok(n == 1)
}

/// True while anyone holds the `claim` on `key`.
pub async fn is_claimed(redis: &Client, key: &str) -> Result<bool> {
    let n: i32 = redis::cmd("EXISTS")
        .arg(key)
        .query_async(&mut conn(redis).await?)
        .await?;
    Ok(n == 1)
}

/// Releases `key` if `owner` still holds it. Best effort.
pub async fn unclaim(redis: &Client, key: &str, owner: &str) {
    let Ok(mut c) = conn(redis).await else { return };
    let r: redis::RedisResult<i32> = Script::new(CAS_DEL)
        .key(key)
        .arg(owner)
        .invoke_async(&mut c)
        .await;
    if let Err(e) = r {
        tracing::warn!(error = %e, key, "unclaim failed");
    }
}

/// `stats` merge into the checkpoint by key; a `partial_reason` string there ends the run
/// `Partial`, a `skip_reason` string `Skipped`.
/// `cursor` (an object, or null for none) merges into the checkpoint cursor by key: state a
/// resumed run reads back instead of redoing calls.
#[derive(Debug, Default)]
pub struct ChunkOutcome {
    pub stats: serde_json::Value,
    pub cursor: serde_json::Value,
}

pub struct RunChunkedOptions {
    pub worker_id: String,
    pub lease_ttl: Duration,
    pub heartbeat_every: Duration,
    pub time_cap: Duration,
    /// Test hook invoked right after each checkpoint write.
    #[cfg(feature = "test-support")]
    pub after_checkpoint: Option<KillSwitch>,
}

impl Default for RunChunkedOptions {
    fn default() -> Self {
        Self {
            worker_id: format!("worker-{}", Uuid::now_v7()),
            lease_ttl: Duration::from_secs(120),
            heartbeat_every: Duration::from_secs(30),
            time_cap: Duration::from_secs(600),
            #[cfg(feature = "test-support")]
            after_checkpoint: None,
        }
    }
}

/// Aborts the heartbeat task when dropped (cancelled future, panic in `f`).
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn run_chunked<S, F, Fut>(
    storage: &S,
    redis: &Client,
    run_id: Uuid,
    chunks: Vec<String>,
    opts: RunChunkedOptions,
    f: F,
) -> Result<RunStatus>
where
    S: Storage + ?Sized,
    F: Fn(String, Lease) -> Fut,
    Fut: Future<Output = Result<ChunkOutcome>>,
{
    let lease = acquire(storage, redis, run_id, &opts.worker_id, opts.lease_ttl)
        .await?
        .ok_or(LedgerError::LeaseHeld)?;
    let lost = Arc::new(AtomicBool::new(false));
    let _hb = AbortOnDrop({
        let (redis, lease, lost, every) = (
            redis.clone(),
            lease.clone(),
            lost.clone(),
            opts.heartbeat_every,
        );
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                if !matches!(heartbeat(&redis, &lease).await, Ok(true)) {
                    lost.store(true, SeqCst);
                    return;
                }
            }
        })
    });
    let res = drive(storage, run_id, &chunks, &opts, &lease, &lost, &f).await;
    let res = fail_on_storage_error(storage, run_id, lease.fence, res).await;
    release(redis, &lease).await;
    res
}

/// Ends the run `Partial` with `reason`; another holder owning the row decides instead.
async fn partial<S: Storage + ?Sized>(
    storage: &S,
    run_id: Uuid,
    fence: u64,
    reason: &str,
) -> Result<RunStatus> {
    match storage
        .set_status(run_id, fence, RunStatus::Partial, Some(reason.into()))
        .await
    {
        Ok(()) | Err(LedgerError::StaleFence) => Ok(RunStatus::Partial),
        Err(e) => Err(e),
    }
}

/// Why the run must stop before its next chunk, if it must.
fn stop_reason(lost: &AtomicBool, started: Instant, cap: Duration) -> Option<&'static str> {
    if lost.load(SeqCst) {
        Some("lease_lost")
    } else if started.elapsed() >= cap {
        Some("time_cap")
    } else {
        None
    }
}

/// Records `chunk` as done and merges its stats by key.
fn merge(cp: &mut Checkpoint, chunk: &str, out: &ChunkOutcome) {
    cp.chunks_done.insert(chunk.to_owned());
    if let (Some(dst), Some(src)) = (cp.stats.as_object_mut(), out.stats.as_object()) {
        dst.extend(src.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    if let Some(src) = out.cursor.as_object() {
        if !cp.cursor.is_object() {
            cp.cursor = serde_json::json!({});
        }
        if let Some(dst) = cp.cursor.as_object_mut() {
            dst.extend(src.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
    }
}

/// The final status once every chunk is done. A chunk may decide it by writing
/// `stats.partial_reason` or `stats.skip_reason`; that is in the checkpoint, so a resumed run
/// reaches the same verdict.
async fn finish<S: Storage + ?Sized>(
    storage: &S,
    run_id: Uuid,
    fence: u64,
    cp: &Checkpoint,
) -> Result<RunStatus> {
    let reason = |k: &str| cp.stats[k].as_str().map(str::to_owned);
    let (status, reason) = match (reason("skip_reason"), reason("partial_reason")) {
        (Some(r), _) => (RunStatus::Skipped, Some(r)),
        (None, Some(r)) => (RunStatus::Partial, Some(r)),
        (None, None) => (RunStatus::Done, None),
    };
    match storage.set_status(run_id, fence, status, reason).await {
        Ok(()) => Ok(status),
        Err(LedgerError::StaleFence) => Ok(RunStatus::Partial),
        Err(e) => Err(e),
    }
}

// shortcut: ~60 lines, the chunk loop with its early exits; split further only with a second loop policy.
async fn drive<S, F, Fut>(
    storage: &S,
    run_id: Uuid,
    chunks: &[String],
    opts: &RunChunkedOptions,
    lease: &Lease,
    lost: &AtomicBool,
    f: &F,
) -> Result<RunStatus>
where
    S: Storage + ?Sized,
    F: Fn(String, Lease) -> Fut,
    Fut: Future<Output = Result<ChunkOutcome>>,
{
    let (started, fence) = (Instant::now(), lease.fence);
    let run = storage.load_run(run_id).await?;
    let mut cp = run.checkpoint;
    match storage
        .set_status(run_id, fence, RunStatus::Running, None)
        .await
    {
        Ok(()) => {}
        Err(LedgerError::StaleFence) => return partial(storage, run_id, fence, "lease_lost").await,
        Err(e) => return Err(e),
    }
    for chunk in chunks {
        if cp.chunks_done.contains(chunk) {
            continue;
        }
        if let Some(why) = stop_reason(lost, started, opts.time_cap) {
            return partial(storage, run_id, fence, why).await;
        }
        let out = match f(chunk.clone(), lease.clone()).await {
            Ok(out) => out,
            Err(LedgerError::StaleFence) => {
                return partial(storage, run_id, fence, "lease_lost").await
            }
            #[cfg(feature = "test-support")]
            Err(e @ LedgerError::Killed) => return Err(e),
            // The run must still end: retry later, or fail with the error's code.
            Err(e) => return settle(storage, run_id, run.attempts, fence, &e).await,
        };
        if lost.load(SeqCst) {
            return partial(storage, run_id, fence, "lease_lost").await;
        }
        merge(&mut cp, chunk, &out);
        match storage.write_checkpoint(run_id, fence, &cp).await {
            Ok(()) => {}
            Err(LedgerError::StaleFence) => {
                return partial(storage, run_id, fence, "lease_lost").await
            }
            Err(e) => return Err(e),
        }
        #[cfg(feature = "test-support")]
        if let Some(k) = &opts.after_checkpoint {
            k.after_checkpoint()?;
        }
    }
    finish(storage, run_id, fence, &cp).await
}
