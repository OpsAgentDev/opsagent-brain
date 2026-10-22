use crate::storage::{EffectState, Result, Storage};
use std::future::Future;
use uuid::Uuid;

/// Runs `f` at most once per (run, key). On `Started` (crashed mid-effect) it re-runs only if `idempotent`.
pub async fn with_effect<S, F, Fut>(
    storage: &S,
    run_id: Uuid,
    key: &str,
    idempotent: bool,
    f: F,
) -> Result<EffectState>
where
    S: Storage + ?Sized,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<String>>>,
{
    match storage.effect_begin(run_id, key).await? {
        done @ EffectState::Done(_) => return Ok(done),
        EffectState::Started if !idempotent => return Ok(EffectState::Started),
        _ => {}
    }
    let r = f().await?;
    storage.effect_done(run_id, key, r.clone()).await?;
    Ok(EffectState::Done(r))
}
