//! Organisation purge (retention.md, goal 5): both adapters; the full table sweep and the
//! audit trigger are Pg only, below.
use chrono::{DateTime, Duration, Utc};
use opsagent_brain::actions::uow::UnitOfWork;
use opsagent_core::{
    audit::AuditEntry, org::Role, passkey::StoredPasskey, retention::PurgeCounts, run::RunStatus,
    user::Email,
};
use uuid::Uuid;

use super::{contract_suite, org_id, Seed};

/// Whole seconds, so instants survive Postgres' microsecond timestamps unchanged.
fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
}

/// An organisation soft-deleted `days` before `t`.
async fn deleted_org(s: &dyn UnitOfWork, slug: &str, t: DateTime<Utc>, days: i64) -> Uuid {
    let o = org_id(s, slug).await;
    s.orgs()
        .soft_delete(o, t - Duration::days(days))
        .await
        .unwrap();
    o
}

/// A user (by `email`) who is a member of every organisation in `orgs`.
async fn member(s: &dyn UnitOfWork, email: &str, orgs: &[Uuid]) -> Uuid {
    let user = s
        .users()
        .find_or_create_by_email(&Email::parse(email).unwrap())
        .await
        .unwrap();
    for o in orgs {
        s.orgs().add_member(*o, user.id, Role::Owner).await.unwrap();
    }
    user.id
}

/// The organisations purgeable at `t` (30 days deleted, no run busy within 24 hours).
async fn purgeable(s: &dyn UnitOfWork, t: DateTime<Utc>) -> Vec<Uuid> {
    let r = s.retention();
    r.purgeable_orgs(t - Duration::days(30), t - Duration::hours(24))
        .await
        .unwrap()
}

/// Purges `org` in a committed transaction, recording at `at`.
async fn purge(s: &dyn UnitOfWork, org: Uuid, at: DateTime<Utc>) -> Option<PurgeCounts> {
    let tx = s.begin().await.unwrap();
    let counts = tx.retention().purge_org(org, at).await.unwrap();
    tx.commit().await.unwrap();
    counts
}

/// A connection with one run and one audit entry in `o`; returns the run.
async fn activity(s: &dyn UnitOfWork, seed: &dyn Seed, o: Uuid, t: DateTime<Utc>) -> Uuid {
    let c = seed.connection(o).await;
    let entry = AuditEntry::member(Some(o), Uuid::now_v7(), "org.update", None);
    s.audit().record(entry).await.unwrap();
    seed.run_at(o, c, "full_scan", RunStatus::Done, t - Duration::days(40))
        .await
}

contract_suite! {
    async fn purge_leaves_other_orgs_and_shared_users(s, seed) {
        let t = now();
        let doomed = deleted_org(s, "doomed", t, 31).await;
        let live = org_id(s, "live").await;
        let shared = member(s, "shared@example.com", &[doomed, live]).await;
        let solo = member(s, "solo@example.com", &[doomed]).await;
        let doomed_run = activity(s, seed, doomed, t).await;
        let live_run = activity(s, seed, live, t).await;

        assert_eq!(purgeable(s, t).await, vec![doomed]);
        let counts = purge(s, doomed, t).await.unwrap();
        assert_eq!((counts["members"], counts["users"], counts["runs"]), (2, 1, 1));
        assert_eq!(counts["audit_events"], 1);
        assert_eq!(counts["organisations"], 1);

        assert!(s.orgs().get(doomed).await.unwrap().is_none());
        assert!(s.ledger().load_run(doomed_run).await.is_err());
        assert!(s.users().get(solo).await.unwrap().is_none());
        // The shared user keeps the live membership; the live organisation keeps its rows.
        assert!(s.users().get(shared).await.unwrap().is_some());
        assert_eq!(s.orgs().list_for_user(shared).await.unwrap().len(), 1);
        assert_eq!(s.orgs().members(live).await.unwrap().len(), 1);
        assert!(s.ledger().load_run(live_run).await.is_ok());
        assert_eq!(seed.audit_count(Some(live)).await, 1);
        assert_eq!(seed.audit_count(Some(doomed)).await, 0);
    }

    async fn purge_deletes_orphaned_users_and_passkeys(s) {
        let t = now();
        let doomed = deleted_org(s, "doomed", t, 31).await;
        let solo = member(s, "solo@example.com", &[doomed]).await;
        // A brand-new user with no organisation yet is never touched.
        let fresh = member(s, "fresh@example.com", &[]).await;
        for (user, cred) in [(solo, 1u8), (fresh, 2)] {
            let p = StoredPasskey {
                id: Uuid::now_v7(),
                user_id: user,
                credential_id: vec![cred],
                credential: serde_json::json!({}),
                name: "key".into(),
                created_at: t,
                last_used_at: None,
            };
            s.passkeys().add(&p).await.unwrap();
        }
        let email = Email::parse("solo@example.com").unwrap();
        s.users()
            .issue_magic_link(solo, &email, "tok", "code", None, t + Duration::hours(1))
            .await
            .unwrap();

        let counts = purge(s, doomed, t).await.unwrap();
        assert_eq!((counts["users"], counts["passkeys"], counts["magic_links"]), (1, 1, 1));
        assert!(s.users().get(solo).await.unwrap().is_none());
        assert!(s.passkeys().for_user(solo).await.unwrap().is_empty());
        assert!(s.users().live_codes(&email, t).await.unwrap().is_empty());
        assert!(s.users().get(fresh).await.unwrap().is_some());
        assert_eq!(s.passkeys().for_user(fresh).await.unwrap().len(), 1);
    }

    async fn purge_skips_org_with_live_run_then_succeeds(s, seed) {
        let t = now();
        let busy = deleted_org(s, "busy", t, 31).await;
        let queued = deleted_org(s, "queued", t, 31).await;
        let recent = deleted_org(s, "recent", t, 29).await;
        let _live = org_id(s, "live").await;
        let c = seed.connection(busy).await;
        seed.run_at(busy, c, "full_scan", RunStatus::Running, t - Duration::hours(1)).await;
        let c = seed.connection(queued).await;
        seed.run_at(queued, c, "full_scan", RunStatus::Queued, t - Duration::days(5)).await;
        assert!(purgeable(s, t).await.is_empty());

        // The next night the running run is over 24 hours old: dead, so purged with the rest.
        let next = t + Duration::days(1);
        assert_eq!(purgeable(s, next).await, vec![busy]);
        let counts = purge(s, busy, next).await.unwrap();
        assert_eq!(counts["runs"], 1);
        // Two nights on, the 29-day one is due; the queued one still waits.
        assert_eq!(purgeable(s, t + Duration::days(2)).await, vec![recent]);
    }

    async fn purge_rerun_is_noop_with_one_record(s, seed) {
        let t = now();
        let doomed = deleted_org(s, "doomed", t, 31).await;
        member(s, "solo@example.com", &[doomed]).await;
        activity(s, seed, doomed, t).await;
        // A crash mid-purge: the transaction never commits, and nothing is gone.
        let tx = s.begin().await.unwrap();
        assert!(tx.retention().purge_org(doomed, t).await.unwrap().is_some());
        drop(tx);
        assert!(s.orgs().get(doomed).await.unwrap().is_some());
        assert_eq!(seed.purge_records().await.len(), 0);

        let counts = purge(s, doomed, t).await.unwrap();
        assert_eq!(purge(s, doomed, t).await, None);
        assert!(purgeable(s, t).await.is_empty());
        let records = seed.purge_records().await;
        assert_eq!(records.len(), 1);
        let want: serde_json::Map<_, _> = counts.iter().map(|(k, v)| (k.to_string(), (*v).into())).collect();
        assert_eq!(records[0], serde_json::json!({"counts": want}));
        // A live organisation is never purged, even when asked for directly.
        let live = org_id(s, "live").await;
        assert_eq!(purge(s, live, t).await, None);
        assert!(s.orgs().get(live).await.unwrap().is_some());
    }

    async fn old_purge_records_deleted_after_a_year(s, seed) {
        let t = now();
        let old = deleted_org(s, "old", t, 500).await;
        let young = deleted_org(s, "young", t, 40).await;
        purge(s, old, t - Duration::days(400)).await.unwrap();
        purge(s, young, t - Duration::days(10)).await.unwrap();
        // An ordinary global audit entry is never a purge record.
        s.audit().record(AuditEntry::member(None, Uuid::now_v7(), "user.signin", None)).await.unwrap();
        let tx = s.begin().await.unwrap();
        assert_eq!(tx.retention().delete_old_purge_records(t - Duration::days(365)).await.unwrap(), 1);
        tx.commit().await.unwrap();
        assert_eq!(seed.purge_records().await.len(), 1);
        assert_eq!(seed.audit_count(None).await, 2);
    }
}

/// Pg only: one row in every table that hangs off organisation `o` (its user `email` too),
/// through OAuth client `client`.
async fn seed_everything(seed: &super::PgSeed, o: Uuid, client: &str, email: &str) {
    use sea_orm::ConnectionTrait;
    let (c, run, res, fin, user, mem, grant) = (
        seed.connection(o).await,
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
    );
    let sql = format!(
        "INSERT INTO connection_credentials (connection_id, kind, kek_version, nonce, ciphertext) VALUES ('{c}', 'role_arn', 1, '\\x00', '\\x00');
         INSERT INTO connection_verifications (id, connection_id, outcome) VALUES (gen_random_uuid(), '{c}', 'ok');
         INSERT INTO runs (id, organisation_id, connection_id, job_type, status, scheduled_at) VALUES ('{run}', '{o}', '{c}', 'full_scan', 'done', now() - interval '40 days');
         INSERT INTO jobs (kind, args, run_id, run_at, max_attempts) VALUES ('full_scan', '{{}}', '{run}', now(), 5);
         INSERT INTO side_effects (id, run_id, effect_key, status) VALUES (gen_random_uuid(), '{run}', 'k', 'done');
         INSERT INTO api_call_stats (id, run_id, provider, service, action, outcome) VALUES (gen_random_uuid(), '{run}', 'fake', 's', 'a', 'ok');
         INSERT INTO api_calls_raw (id, run_id, provider, service, action, outcome) VALUES (gen_random_uuid(), '{run}', 'fake', 's', 'a', 'ok');
         INSERT INTO resources (id, organisation_id, connection_id, kind, identity) VALUES ('{res}', '{o}', '{c}', 'k', '{res}');
         INSERT INTO resource_history (id, resource_id, run_id) VALUES (gen_random_uuid(), '{res}', '{run}');
         INSERT INTO findings (id, organisation_id, connection_id, check_id, resource_identity, severity, title, first_seen_run_id, last_seen_run_id)
           VALUES ('{fin}', '{o}', '{c}', '01', '{res}', 'low', 't', '{run}', '{run}');
         INSERT INTO finding_events (id, finding_id, run_id, event_type) VALUES (gen_random_uuid(), '{fin}', '{run}', 'opened');
         INSERT INTO evidence (id, finding_id, run_id, source, excerpt, expires_at) VALUES (gen_random_uuid(), '{fin}', '{run}', 's', 'e', now() + interval '1 day');
         INSERT INTO users (id, email) VALUES ('{user}', '{email}');
         INSERT INTO members (id, organisation_id, user_id, role) VALUES ('{mem}', '{o}', '{user}', 'owner');
         INSERT INTO passkeys (id, user_id, credential_id, credential, name) VALUES (gen_random_uuid(), '{user}', '\\x{cred}', '{{}}', 'k');
         INSERT INTO magic_links (id, user_id, token_hash, expires_at) VALUES (gen_random_uuid(), '{user}', '{user}', now() + interval '1 hour');
         INSERT INTO sessions (id, data, expiry_date) VALUES ('{user}', convert_to('{{\"user_id\":\"{user}\"}}', 'UTF8'), now() + interval '1 day');
         INSERT INTO recipients (id, organisation_id, connection_id, member_id, email, status) VALUES (gen_random_uuid(), '{o}', '{c}', '{mem}', '{email}', 'active');
         INSERT INTO integrations (id, organisation_id, kind, kek_version, nonce, ciphertext) VALUES (gen_random_uuid(), '{o}', 'slack', 1, '\\x00', '\\x00');
         INSERT INTO schedules (id, organisation_id, connection_id, job_type, cron_local) VALUES (gen_random_uuid(), '{o}', '{c}', 'full_scan', '0 6 * * *');
         INSERT INTO deliveries (id, organisation_id, connection_id, kind, channel, target) VALUES (gen_random_uuid(), '{o}', '{c}', 'briefing', 'email', 't');
         INSERT INTO oauth_grants (id, client_id, member_id, organisation_id) VALUES ('{grant}', '{client}', '{mem}', '{o}');
         INSERT INTO oauth_access_tokens (id, grant_id, organisation_id, token_hash, expires_at) VALUES (gen_random_uuid(), '{grant}', '{o}', 'a{grant}', now());
         INSERT INTO oauth_refresh_tokens (id, grant_id, organisation_id, token_hash, expires_at) VALUES (gen_random_uuid(), '{grant}', '{o}', 'r{grant}', now());
         INSERT INTO oauth_consent_requests (id, client_id, redirect_uri, code_challenge, resource, scope, organisation_id, expires_at)
           VALUES (gen_random_uuid(), '{client}', 'r', 'c', 'r', 's', '{o}', now());
         INSERT INTO oauth_consent_requests (id, client_id, redirect_uri, code_challenge, resource, scope, grant_id, expires_at)
           VALUES (gen_random_uuid(), '{client}', 'r', 'c', 'r', 's', '{grant}', now());
         INSERT INTO invites (id, organisation_id, email, role, token_hash, expires_at) VALUES (gen_random_uuid(), '{o}', '{email}', 'member', 'i{o}', now());
         INSERT INTO email_suppressions (id, organisation_id, email_hash, reason, expires_at) VALUES (gen_random_uuid(), '{o}', 'h', 'ignored', now());
         INSERT INTO audit_events (id, organisation_id, actor_type, action) VALUES (gen_random_uuid(), '{o}', 'system', 'x');",
        cred = user.simple(),
    );
    seed.raw().execute_unprepared(&sql).await.unwrap();
}

/// Pg only: rows per table, every table but the migrations ledger.
async fn table_counts(seed: &super::PgSeed) -> std::collections::BTreeMap<String, i64> {
    use sea_orm::ConnectionTrait;
    let q = "SELECT table_name::text AS t FROM information_schema.tables WHERE table_schema = 'public' \
             AND table_type = 'BASE TABLE' AND table_name <> 'seaql_migrations'";
    let st = sea_orm::Statement::from_string(sea_orm::DbBackend::Postgres, q);
    let mut out = std::collections::BTreeMap::new();
    for r in seed.raw().query_all_raw(st).await.unwrap() {
        let t: String = r.try_get("", "t").unwrap();
        let st = sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            format!("SELECT count(*) AS n FROM {t}"),
        );
        let n = seed.raw().query_one_raw(st).await.unwrap().unwrap();
        out.insert(t, n.try_get::<i64>("", "n").unwrap());
    }
    out
}

/// Pg only: every row of a 31-day-deleted organisation goes, in every table (a sweep of each
/// table with an `organisation_id` column, and of every table's count); the other one stays.
#[tokio::test]
#[serial_test::serial]
async fn purge_removes_every_row_of_old_deleted_org() {
    use sea_orm::ConnectionTrait;
    let store = super::pg().await;
    let s: &dyn UnitOfWork = &store;
    let seed = super::PgSeed::new().await;
    let t = now();
    let client = "c-purge";
    seed.raw()
        .execute_unprepared(&format!("INSERT INTO oauth_clients (client_id, kind, name, redirect_uris) VALUES ('{client}', 'dynamic', 'x', '[]')"))
        .await
        .unwrap();
    let live = org_id(s, "live").await;
    seed_everything(&seed, live, client, "live@example.com").await;
    let before = table_counts(&seed).await;
    let doomed = deleted_org(s, "doomed", t, 31).await;
    seed_everything(&seed, doomed, client, "doomed@example.com").await;

    assert_eq!(purgeable(s, t).await, vec![doomed]);
    let counts = purge(s, doomed, t).await.unwrap();
    assert!(counts.values().all(|n| *n <= 2), "{counts:?}");

    let cols = "SELECT table_name::text AS t FROM information_schema.columns \
                WHERE table_schema = 'public' AND column_name = 'organisation_id'";
    let st = sea_orm::Statement::from_string(sea_orm::DbBackend::Postgres, cols);
    let tables = seed.raw().query_all_raw(st).await.unwrap();
    // A new tenant table fails here: add it to the purge (`PURGE`) and to `seed_everything`.
    assert_eq!(tables.len(), 16);
    for r in tables {
        let t: String = r.try_get("", "t").unwrap();
        let q = format!("SELECT count(*) AS n FROM {t} WHERE organisation_id = '{doomed}'");
        let st = sea_orm::Statement::from_string(sea_orm::DbBackend::Postgres, q);
        let n = seed.raw().query_one_raw(st).await.unwrap().unwrap();
        assert_eq!(n.try_get::<i64>("", "n").unwrap(), 0, "{t}");
    }
    // Every table is back to the live organisation's rows, plus the one purge record.
    let mut want = before;
    *want.get_mut("audit_events").unwrap() += 1;
    assert_eq!(table_counts(&seed).await, want);
    let st = sea_orm::Statement::from_string(
        sea_orm::DbBackend::Postgres,
        "SELECT organisation_id, actor_type, actor_id, target_type, target_id FROM audit_events WHERE action = 'org.purged'",
    );
    let r = seed.raw().query_one_raw(st).await.unwrap().unwrap();
    assert_eq!(
        r.try_get::<Option<Uuid>>("", "organisation_id").unwrap(),
        None
    );
    assert_eq!(r.try_get::<String>("", "actor_type").unwrap(), "system");
    assert_eq!(r.try_get::<Option<String>>("", "actor_id").unwrap(), None);
    assert_eq!(
        r.try_get::<String>("", "target_type").unwrap(),
        "organisation"
    );
    assert_eq!(
        r.try_get::<String>("", "target_id").unwrap(),
        doomed.to_string()
    );
    assert_eq!(counts["sessions"], 1);
}

/// Pg only: outside a transaction the purge refuses before deleting anything.
#[tokio::test]
#[serial_test::serial]
async fn purge_outside_a_transaction_deletes_nothing() {
    let store = super::pg().await;
    let s: &dyn UnitOfWork = &store;
    let t = now();
    let doomed = deleted_org(s, "doomed", t, 31).await;
    let user = member(s, "solo@example.com", &[doomed]).await;
    assert!(s.retention().purge_org(doomed, t).await.is_err());
    assert!(s.retention().delete_old_purge_records(t).await.is_err());
    assert!(s.orgs().get(doomed).await.unwrap().is_some());
    assert!(s.users().get(user).await.unwrap().is_some());
}

/// Pg only: UPDATE is always refused; DELETE only with `opsagent.purge` set locally.
#[tokio::test]
#[serial_test::serial]
async fn trigger_still_blocks_update_and_unflagged_delete() {
    use sea_orm::{ConnectionTrait, TransactionTrait};
    let store = super::pg().await;
    let seed = super::PgSeed::new().await;
    let db = seed.raw();
    db.execute_unprepared("INSERT INTO audit_events (id, actor_type, action) VALUES (gen_random_uuid(), 'system', 'x')")
        .await
        .unwrap();
    let update = "UPDATE audit_events SET action = 'y'";
    let delete = "DELETE FROM audit_events";
    assert!(db.execute_unprepared(update).await.is_err());
    assert!(db.execute_unprepared(delete).await.is_err());
    for flag in ["off", "true", "ON"] {
        let tx = db.begin().await.unwrap();
        tx.execute_unprepared(&format!("SET LOCAL opsagent.purge = '{flag}'"))
            .await
            .unwrap();
        assert!(tx.execute_unprepared(delete).await.is_err(), "{flag}");
    }
    let tx = db.begin().await.unwrap();
    tx.execute_unprepared("SET LOCAL opsagent.purge = 'on'")
        .await
        .unwrap();
    assert!(tx.execute_unprepared(update).await.is_err());
    tx.rollback().await.unwrap();
    let tx = db.begin().await.unwrap();
    tx.execute_unprepared("SET LOCAL opsagent.purge = 'on'")
        .await
        .unwrap();
    assert_eq!(
        tx.execute_unprepared(delete).await.unwrap().rows_affected(),
        1
    );
    tx.commit().await.unwrap();
    // SET LOCAL ends with the transaction.
    db.execute_unprepared("INSERT INTO audit_events (id, actor_type, action) VALUES (gen_random_uuid(), 'system', 'x')")
        .await
        .unwrap();
    assert!(db.execute_unprepared(delete).await.is_err());
    drop(store);
}
