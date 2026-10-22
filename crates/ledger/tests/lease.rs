mod common;
use opsagent_ledger::lease::{acquire, heartbeat, release};
use opsagent_ledger::testing::MemoryStorage;
use opsagent_ledger::{Checkpoint, LedgerError, Storage};
use std::time::Duration;

#[tokio::test]
async fn acquire_twice_some_then_none() {
    let (r, s) = (common::redis(), MemoryStorage::default());
    let run = s.create_run(common::key()).await.unwrap().run;
    let l = acquire(&s, &r, run.id, "w1", Duration::from_secs(5))
        .await
        .unwrap();
    assert!(l.is_some());
    assert!(acquire(&s, &r, run.id, "w2", Duration::from_secs(5))
        .await
        .unwrap()
        .is_none());
    let l = l.unwrap();
    // failed acquire must not invalidate the holder's fence
    s.write_checkpoint(run.id, l.fence, &Checkpoint::default())
        .await
        .unwrap();
    assert!(heartbeat(&r, &l).await.unwrap());
    release(&r, &l).await;
    assert!(!heartbeat(&r, &l).await.unwrap());
    assert!(acquire(&s, &r, run.id, "w2", Duration::from_secs(5))
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn expiry_gives_higher_fence_and_old_fence_is_stale() {
    let (r, s) = (common::redis(), MemoryStorage::default());
    let run = s.create_run(common::key()).await.unwrap().run;
    let old = acquire(&s, &r, run.id, "w1", Duration::from_millis(150))
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!heartbeat(&r, &old).await.unwrap());
    let new = acquire(&s, &r, run.id, "w2", Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    assert!(new.fence > old.fence);
    let cp = Checkpoint::default();
    assert!(matches!(
        s.write_checkpoint(run.id, old.fence, &cp).await,
        Err(LedgerError::StaleFence)
    ));
    s.write_checkpoint(run.id, new.fence, &cp).await.unwrap();
}

#[test]
fn backoff_schedule() {
    use opsagent_ledger::retry::backoff;
    let m = |n: u64| Some(Duration::from_secs(60 * n));
    assert_eq!(backoff(0), m(1));
    assert_eq!(backoff(1), m(5));
    assert_eq!(backoff(2), m(15));
    assert_eq!(backoff(3), m(60));
    assert_eq!(backoff(4), None);
}

#[tokio::test]
async fn memory_storage_unique_key_and_effects() {
    use opsagent_ledger::EffectState;
    let s = MemoryStorage::default();
    let k = common::key();
    let a = s.create_run(k.clone()).await.unwrap().run;
    assert_eq!(s.create_run(k).await.unwrap().run.id, a.id);
    assert_eq!(s.effect_begin(a.id, "e").await.unwrap(), EffectState::New);
    assert_eq!(
        s.effect_begin(a.id, "e").await.unwrap(),
        EffectState::Started
    );
    s.effect_done(a.id, "e", Some("x".into())).await.unwrap();
    assert_eq!(
        s.effect_begin(a.id, "e").await.unwrap(),
        EffectState::Done(Some("x".into()))
    );
}

#[tokio::test]
async fn with_effect_rules() {
    use opsagent_ledger::{effects::with_effect, EffectState};
    use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
    let s = MemoryStorage::default();
    let a = s.create_run(common::key()).await.unwrap().run;
    let n = AtomicU32::new(0);
    let f = || async {
        n.fetch_add(1, SeqCst);
        Ok(Some("r".to_string()))
    };
    assert_eq!(
        with_effect(&s, a.id, "k", false, f).await.unwrap(),
        EffectState::Done(Some("r".into()))
    );
    assert_eq!(
        with_effect(&s, a.id, "k", false, f).await.unwrap(),
        EffectState::Done(Some("r".into()))
    );
    assert_eq!(n.load(SeqCst), 1);
    // crashed mid-effect: row stays `started`
    s.effect_begin(a.id, "j").await.unwrap();
    assert_eq!(
        with_effect(&s, a.id, "j", false, f).await.unwrap(),
        EffectState::Started
    );
    assert_eq!(n.load(SeqCst), 1);
    with_effect(&s, a.id, "j", true, f).await.unwrap();
    assert_eq!(n.load(SeqCst), 2);
}
