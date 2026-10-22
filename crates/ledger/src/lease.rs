use crate::harness::KillSwitch;
use crate::storage::{LedgerError, Result, Storage};
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

pub struct ChunkOutcome {
    pub stats: serde_json::Value,
}

pub struct RunChunkedOptions {
    pub worker_id: String,
    pub lease_ttl: Duration,
    pub heartbeat_every: Duration,
    pub time_cap: Duration,
    /// Test hook invoked right after each checkpoint write.
    pub after_checkpoint: Option<KillSwitch>,
}

impl Default for RunChunkedOptions {
    fn default() -> Self {
        Self {
            worker_id: format!("worker-{}", Uuid::now_v7()),
            lease_ttl: Duration::from_secs(120),
            heartbeat_every: Duration::from_secs(30),
            time_cap: Duration::from_secs(600),
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
    release(redis, &lease).await;
    res
}

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
    let started = Instant::now();
    let mut cp = storage.load_run(run_id).await?.checkpoint;
    storage
        .set_status(run_id, lease.fence, RunStatus::Running, None)
        .await?;
    let partial = |reason: &'static str| async move {
        match storage
            .set_status(run_id, lease.fence, RunStatus::Partial, Some(reason.into()))
            .await
        {
            // Another holder owns the row now; it decides the final status.
            Ok(()) | Err(LedgerError::StaleFence) => Ok(RunStatus::Partial),
            Err(e) => Err(e),
        }
    };
    match storage
        .set_status(run_id, lease.fence, RunStatus::Running, None)
        .await
    {
        Ok(()) => {}
        Err(LedgerError::StaleFence) => return partial("lease_lost").await,
        Err(e) => return Err(e),
    }
    for chunk in chunks {
        if cp.chunks_done.contains(chunk) {
            continue;
        }
        if lost.load(SeqCst) {
            return partial("lease_lost").await;
        }
        if started.elapsed() >= opts.time_cap {
            return partial("time_cap").await;
        }
        let out = f(chunk.clone(), lease.clone()).await?;
        if lost.load(SeqCst) {
            return partial("lease_lost").await;
        }
        cp.chunks_done.insert(chunk.clone());
        if let (Some(dst), Some(src)) = (cp.stats.as_object_mut(), out.stats.as_object()) {
            dst.extend(src.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        match storage.write_checkpoint(run_id, lease.fence, &cp).await {
            Ok(()) => {}
            Err(LedgerError::StaleFence) => return partial("lease_lost").await,
            Err(e) => return Err(e),
        }
        if let Some(k) = &opts.after_checkpoint {
            k.after_checkpoint()?;
        }
    }
    match storage
        .set_status(run_id, lease.fence, RunStatus::Done, None)
        .await
    {
        Ok(()) => Ok(RunStatus::Done),
        Err(LedgerError::StaleFence) => Ok(RunStatus::Partial),
        Err(e) => Err(e),
    }
}
