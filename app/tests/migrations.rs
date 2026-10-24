use migration::{Migrator, MigratorTrait};
use sea_orm::entity::prelude::*;
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

    // recipients: one row per (org, email, connection), org-wide (NULL connection) included.
    let rcpt = format!(
        "INSERT INTO recipients (id, organisation_id, email, status) \
         VALUES (gen_random_uuid(), {org}, 'r@example.com', 'pending')"
    );
    exec(&db, &rcpt).await.unwrap();
    let err = exec(&db, &rcpt).await.unwrap_err();
    assert!(is_unique_violation(&err), "{err}");
    // integrations.status CHECK.
    let integ = |status: &str| {
        format!(
            "INSERT INTO integrations (id, organisation_id, kind, ciphertext, nonce, kek_version, status) \
             VALUES (gen_random_uuid(), {org}, 'slack', '\\x00', '\\x00', 1, '{status}')"
        )
    };
    assert!(exec(&db, &integ("bogus")).await.is_err());
    exec(&db, &integ("failing")).await.unwrap();

    // email_suppressions: `ignored` needs an organisation; `confirm_blocked` must be global.
    let supp = |org_id: &str, reason: &str, expires: &str| {
        format!(
            "INSERT INTO email_suppressions (id, organisation_id, email_hash, reason, expires_at) \
             VALUES (gen_random_uuid(), {org_id}, md5(random()::text), '{reason}', {expires})"
        )
    };
    assert!(exec(&db, &supp("NULL", "ignored", "now()")).await.is_err());
    assert!(exec(&db, &supp(org, "confirm_blocked", "now()"))
        .await
        .is_err());
    assert!(exec(&db, &supp("NULL", "confirm_blocked", "NULL"))
        .await
        .is_err());
    exec(&db, &supp(org, "ignored", "now()")).await.unwrap();
    exec(&db, &supp("NULL", "confirm_blocked", "now()"))
        .await
        .unwrap();
    exec(&db, &supp("NULL", "unsubscribed", "NULL"))
        .await
        .unwrap();

    // audit_events is insert-only.
    exec(&db, "INSERT INTO audit_events (id, actor_type, action) VALUES ('00000000-0000-0000-0000-0000000000aa', 'system', 'x')")
        .await
        .unwrap();
    assert!(exec(&db, "UPDATE audit_events SET action = 'y'")
        .await
        .is_err());
    assert!(exec(&db, "DELETE FROM audit_events").await.is_err());

    // Rows in statuses added by 000010 must not block rolling it back.
    for st in ["fallback_email", "suppressed"] {
        exec(
            &db,
            &format!(
                "INSERT INTO deliveries (id, organisation_id, kind, channel, target, status) \
             VALUES (gen_random_uuid(), {org}, 'briefing', 'email', 'x', '{st}')"
            ),
        )
        .await
        .unwrap();
    }

    Migrator::down(&db, None).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
}

#[tokio::test]
#[serial]
async fn jobs_table_has_spec_columns_and_both_partial_indexes() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://loco:loco@localhost:5432/opsagent_brain_test".into());
    let db = migration::sea_orm::Database::connect(&url).await.unwrap();
    Migrator::fresh(&db).await.unwrap();

    let cols = db
        .query_all_raw(migration::sea_orm::Statement::from_string(
            migration::sea_orm::DbBackend::Postgres,
            "SELECT column_name || ' ' || data_type || ' ' || is_nullable AS c \
             FROM information_schema.columns WHERE table_name = 'jobs' ORDER BY ordinal_position",
        ))
        .await
        .unwrap();
    let cols: Vec<String> = cols.iter().map(|r| r.try_get("", "c").unwrap()).collect();
    assert_eq!(
        cols,
        [
            "id uuid NO",
            "kind text NO",
            "args jsonb NO",
            "run_id uuid YES",
            "run_at timestamp with time zone NO",
            "attempts integer NO",
            "max_attempts integer NO",
            "locked_at timestamp with time zone YES",
            "locked_by text YES",
            "last_error text YES",
            "created_at timestamp with time zone NO",
        ]
    );
    let idx = db
        .query_all_raw(migration::sea_orm::Statement::from_string(
            migration::sea_orm::DbBackend::Postgres,
            "SELECT indexdef FROM pg_indexes WHERE tablename = 'jobs' \
             AND indexname IN ('jobs_ready', 'jobs_one_per_run') ORDER BY indexname",
        ))
        .await
        .unwrap();
    let idx: Vec<String> = idx
        .iter()
        .map(|r| r.try_get("", "indexdef").unwrap())
        .collect();
    assert_eq!(idx.len(), 2, "{idx:?}");
    assert!(
        idx[0].contains("UNIQUE INDEX jobs_one_per_run") && idx[0].contains("(run_id IS NOT NULL)")
    );
    assert!(
        idx[1].contains("INDEX jobs_ready")
            && idx[1].contains("(run_at)")
            && idx[1].contains("(locked_at IS NULL)")
    );

    // Defaults fill id, attempts and created_at; a second job for one run collides.
    exec(&db, "INSERT INTO runs (id, job_type, scheduled_at) VALUES ('00000000-0000-0000-0000-0000000000b1', 'verify', now())")
        .await
        .unwrap();
    let job = "INSERT INTO jobs (kind, args, run_id, run_at, max_attempts) \
               VALUES ('verify', '{}', '00000000-0000-0000-0000-0000000000b1', now(), 5)";
    exec(&db, job).await.unwrap();
    let err = exec(&db, job).await.unwrap_err();
    assert!(is_unique_violation(&err), "{err}");
    // Jobs without a run do not collide.
    let free =
        "INSERT INTO jobs (kind, args, run_at, max_attempts) VALUES ('verify', '{}', now(), 5)";
    exec(&db, free).await.unwrap();
    exec(&db, free).await.unwrap();

    // Three steps: jobs is followed by the oauth and magic-link return_to migrations.
    Migrator::down(&db, Some(3)).await.unwrap();
    assert!(exec(&db, "SELECT 1 FROM jobs").await.is_err());
    Migrator::up(&db, None).await.unwrap();
}
