use loco_rs::prelude::*;
use migration::{Migrator, MigratorTrait};
use serial_test::serial;

async fn exec(db: &DatabaseConnection, sql: &str) -> Result<(), DbErr> {
    db.execute_unprepared(sql).await.map(|_| ())
}

fn is_unique_violation(e: &DbErr) -> bool {
    e.to_string().contains("violates unique constraint")
}

#[tokio::test]
#[serial]
async fn migrations_slice_schema_constraints_and_roundtrip() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://loco:loco@localhost:5432/opsagent_brain_test".into());
    let db = migration::sea_orm::Database::connect(&url).await.unwrap();

    Migrator::fresh(&db).await.unwrap();

    // runs: NULL connection_id must still collide (NULLS NOT DISTINCT).
    let run = "INSERT INTO runs (id, job_type, scheduled_at, status) \
               VALUES (gen_random_uuid(), 'retention', '2026-10-22T00:00:00Z', 'queued')";
    exec(&db, run).await.unwrap();
    let err = exec(&db, run).await.unwrap_err();
    assert!(is_unique_violation(&err), "{err}");

    // connections.status CHECK accepts `disconnected`, rejects junk.
    exec(&db, "INSERT INTO organisations (id, name, slug) VALUES ('00000000-0000-0000-0000-000000000001', 'o', 'o')")
        .await
        .unwrap();
    let org = "'00000000-0000-0000-0000-000000000001'";
    let conn = |status: &str, acct: &str| {
        let acct = if acct.is_empty() {
            "NULL".into()
        } else {
            format!("'{acct}'")
        };
        format!(
            "INSERT INTO connections (id, organisation_id, provider, external_account_id, status) \
             VALUES (gen_random_uuid(), {org}, 'aws', {acct}, '{status}')"
        )
    };
    assert!(exec(&db, &conn("bogus", "2")).await.is_err());
    // Claimed accounts are globally unique.
    exec(&db, &conn("connected", "1")).await.unwrap();
    let err = exec(&db, &conn("connected", "1")).await.unwrap_err();
    assert!(is_unique_violation(&err), "{err}");
    // Pending rows with NULL account coexist; pending cannot squat a claimed account.
    exec(&db, &conn("pending", "")).await.unwrap();
    exec(&db, &conn("pending", "")).await.unwrap();
    exec(&db, &conn("pending", "1")).await.unwrap();
    // A refused duplicate is recorded as blocked without squatting the account.
    exec(&db, &conn("blocked", "1")).await.unwrap();
    exec(&db, &conn("verifying", "")).await.unwrap();
    assert!(exec(&db, &conn("revoked", "")).await.is_err());
    // Non-pending states require an account.
    assert!(exec(&db, &conn("connected", "")).await.is_err());
    // A disconnected row releases the account for a new connected row.
    exec(&db, &conn("disconnected", "3")).await.unwrap();
    exec(&db, &conn("connected", "3")).await.unwrap();

    // audit_events is insert-only.
    exec(&db, "INSERT INTO audit_events (id, actor_type, action) VALUES ('00000000-0000-0000-0000-0000000000aa', 'system', 'x')")
        .await
        .unwrap();
    assert!(exec(&db, "UPDATE audit_events SET action = 'y'")
        .await
        .is_err());
    assert!(exec(&db, "DELETE FROM audit_events").await.is_err());

    Migrator::down(&db, None).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
}
