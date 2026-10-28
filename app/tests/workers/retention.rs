//! `retention` (retention.md): the global nightly run records its counts.
use chrono::{Duration, Utc};
use opsagent_brain::adapters::db::ledger_storage::PgStorage;
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_ledger::{JobKind, Storage};
use sea_orm::ConnectionTrait;
use serial_test::serial;
use uuid::Uuid;

use super::deliver_briefing::{sql, stats};
use crate::requests::support::*;

async fn session(ctx: &TestApp, expired_days_ago: i64) {
    sql(
        ctx,
        "INSERT INTO sessions (id, data, expiry_date) VALUES ($1, '\\x00', $2)",
        vec![
            Uuid::now_v7().to_string().into(),
            (Utc::now() - Duration::days(expired_days_ago)).into(),
        ],
    )
    .await;
}

#[tokio::test]
#[serial]
async fn retention_run_records_counts_in_stats() {
    let ctx = TestApp::boot().await;
    // Two sessions past the 1-day grace, one inside it, one live.
    for days in [3, 2, 0, -1] {
        session(&ctx, days).await;
    }
    let key = RunKey {
        organisation_id: None,
        connection_id: None,
        job_type: JobKind::Retention.as_str().into(),
        scheduled_at: Utc::now(),
    };
    let storage = PgStorage::new(ctx.db.clone());
    let id = storage.create_run(key).await.unwrap().run.id;
    perform(&ctx, JobKind::Retention, id).await.unwrap();
    assert_eq!(storage.load_run(id).await.unwrap().status, RunStatus::Done);
    let st = stats(&ctx, id).await;
    assert_eq!(st["sessions"], 2);
    assert_eq!(st["magic_links"], 0);
    let left = ctx
        .db
        .query_one_raw(sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "SELECT count(*) AS n FROM sessions",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(left.try_get::<i64>("", "n").unwrap(), 2);
}
