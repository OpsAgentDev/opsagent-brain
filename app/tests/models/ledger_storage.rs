use chrono::{TimeZone, Utc};
use loco_rs::testing::prelude::boot_test;
use opsagent_brain::{app::App, models::ledger_storage::PgStorage};
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_ledger::{
    redis, run_chunked, Checkpoint, ChunkOutcome, EffectState, LedgerError, RunChunkedOptions,
    Storage,
};
use serial_test::serial;

fn key() -> RunKey {
    RunKey {
        organisation_id: None,
        connection_id: None,
        job_type: "retention".into(),
        scheduled_at: Utc.with_ymd_and_hms(2026, 10, 22, 3, 0, 0).unwrap(),
    }
}

#[tokio::test]
#[serial]
async fn pg_storage_dedupes_keys_and_enforces_fence() {
    crate::requests::support::test_env();
    let boot = boot_test::<App>().await.unwrap();
    let s = PgStorage::new(boot.app_context.db.clone());

    // NULL scope columns still dedupe (NULLS NOT DISTINCT).
    let a = s.create_run(key()).await.unwrap().run;
    let b = s.create_run(key()).await.unwrap().run;
    assert_eq!(a.id, b.id);
    assert_eq!(a.status, RunStatus::Queued);
    assert_eq!(a.key, key());
    assert_eq!(a.fence, 0);

    assert_eq!(s.bump_fence(a.id).await.unwrap(), 1);
    let mut cp = Checkpoint::default();
    cp.chunks_done.insert("ec2:us-east-1".into());
    assert!(matches!(
        s.write_checkpoint(a.id, 0, &cp).await,
        Err(LedgerError::StaleFence)
    ));
    s.write_checkpoint(a.id, 1, &cp).await.unwrap();
    assert!(matches!(
        s.set_status(a.id, 0, RunStatus::Done, None).await,
        Err(LedgerError::StaleFence)
    ));
    s.set_status(a.id, 1, RunStatus::Partial, Some("time_cap".into()))
        .await
        .unwrap();
    let row = s.load_run(a.id).await.unwrap();
    assert_eq!(row.checkpoint, cp);
    assert_eq!(row.status, RunStatus::Partial);
    assert_eq!(row.partial_reason.as_deref(), Some("time_cap"));

    assert_eq!(
        s.effect_begin(a.id, "slack").await.unwrap(),
        EffectState::New
    );
    assert_eq!(
        s.effect_begin(a.id, "slack").await.unwrap(),
        EffectState::Started
    );
    s.effect_done(a.id, "slack", Some("ts-1".into()))
        .await
        .unwrap();
    assert_eq!(
        s.effect_begin(a.id, "slack").await.unwrap(),
        EffectState::Done(Some("ts-1".into()))
    );

    s.schedule_retry(a.id, 2, Utc::now()).await.unwrap();
    let row = s.load_run(a.id).await.unwrap();
    assert_eq!(row.attempts, 2);
    assert_eq!(row.status, RunStatus::Queued);

    assert!(matches!(
        s.load_run(uuid::Uuid::new_v4()).await,
        Err(LedgerError::NotFound)
    ));
}

#[tokio::test]
#[serial]
async fn run_chunked_completes_on_pg_storage() {
    crate::requests::support::test_env();
    let boot = boot_test::<App>().await.unwrap();
    let s = PgStorage::new(boot.app_context.db.clone());
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:56379".into());
    let redis = redis::Client::open(url).unwrap();
    let run = s.create_run(key()).await.unwrap().run;
    let status = run_chunked(
        &s,
        &redis,
        run.id,
        vec!["a".into(), "b".into()],
        RunChunkedOptions::default(),
        |c, _| async move {
            Ok(ChunkOutcome {
                stats: serde_json::json!({ c: 1 }),
                ..Default::default()
            })
        },
    )
    .await
    .unwrap();
    assert_eq!(status, RunStatus::Done);
    let row = s.load_run(run.id).await.unwrap();
    assert_eq!(row.checkpoint.chunks_done.len(), 2);
    assert_eq!(row.checkpoint.stats["a"], 1);
}
