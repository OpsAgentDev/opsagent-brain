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

/// Bumps the fence first; a lost SET race leaves a harmless gap in fences.
pub async fn acquire<S: Storage + ?Sized>(
    storage: &S,
    redis: &Client,
    run_id: Uuid,
    worker_id: &str,
    ttl: Duration,
) -> Result<Option<Lease>> {
    let fence = storage.bump_fence(run_id).await?;
    let value = format!("{worker_id}:{fence}");
    let ok: Option<String> = redis::cmd("SET")
        .arg(lease_key(run_id))
        .arg(&value)
        .arg("NX")
        .arg("PX")
        .arg(ttl.as_millis() as u64)
        .query_async(&mut conn(redis).await?)
        .await?;
    Ok(ok.map(|_| Lease {
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
    let s = Script::new(
        r#"if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end"#,
    );
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

impl RunChunkedOptions {
    pub fn new(worker_id: impl Into<String>, time_cap: Duration) -> Self {
        Self {
            worker_id: worker_id.into(),
            lease_ttl: Duration::from_secs(90),
            heartbeat_every: Duration::from_secs(30),
            time_cap,
            after_checkpoint: None,
        }
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
    let hb = {
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
    };
    let res = drive(storage, run_id, &chunks, &opts, &lease, &lost, &f).await;
    hb.abort();
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
