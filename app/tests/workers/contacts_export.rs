//! The weekly contacts export over real `users`, `organisations` and `email_suppressions` rows,
//! with a fake object store.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone, Utc};
use opsagent_brain::{
    actions::runs::{ContactsExport, ObjectStore, OBJECT_KEY},
    adapters::db::{ledger_storage::PgStorage, PgContactRows},
    error::AppResult,
};
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_ledger::{JobKind, RunChunkedOptions, Storage};
use serial_test::serial;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::deliver_briefing::sql;
use crate::requests::support::*;

const HEADER: &str = "email,name,company,product,external_id,kind,plan,status,signed_up_at,source,marketing_ok,opted_out";

#[derive(Default)]
struct FakeStore {
    objects: Mutex<HashMap<String, String>>,
    puts: Mutex<usize>,
}

#[async_trait]
impl ObjectStore for FakeStore {
    async fn put(&self, key: &str, body: Vec<u8>) -> AppResult<()> {
        *self.puts.lock().unwrap() += 1;
        let body = String::from_utf8(body).unwrap();
        self.objects.lock().unwrap().insert(key.into(), body);
        Ok(())
    }
}

impl FakeStore {
    fn file(&self) -> String {
        self.objects.lock().unwrap()[OBJECT_KEY].clone()
    }
}

fn job(ctx: &TestApp, store: &Arc<FakeStore>, enabled: bool) -> ContactsExport {
    ContactsExport::new(
        Arc::new(PgContactRows(ctx.db.clone())),
        store.clone(),
        ctx.state.uow.clone(),
        ctx.redis(),
        enabled,
    )
}

async fn week_run(ctx: &TestApp, at: DateTime<Utc>) -> Uuid {
    let key = RunKey {
        organisation_id: None,
        connection_id: None,
        job_type: JobKind::ContactsExport.as_str().into(),
        scheduled_at: at,
    };
    PgStorage::new(ctx.db.clone())
        .create_run(key)
        .await
        .unwrap()
        .run
        .id
}

fn monday() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 23, 2, 0, 0).unwrap()
}

fn signed_up() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 10, 8, 30, 5).unwrap()
}

/// An organisation `org_name` owned by `email` (user name `name`), created at `signed_up()`.
async fn owner(
    ctx: &TestApp,
    email: &str,
    name: Option<&str>,
    org_name: &str,
    source: Option<&str>,
) -> Uuid {
    let (org, user) = (Uuid::new_v4(), Uuid::new_v4());
    let src = source.map(|s| serde_json::json!({ "utm_source": s }));
    sql(
        ctx,
        "INSERT INTO organisations (id, name, slug, signup_source, created_at) VALUES ($1, $4, $1::text, $2, $3)",
        vec![org.into(), src.into(), signed_up().into(), org_name.into()],
    )
    .await;
    sql(
        ctx,
        "INSERT INTO users (id, email, name) VALUES ($1, $2, $3)",
        vec![user.into(), email.into(), name.into()],
    )
    .await;
    sql(
        ctx,
        "INSERT INTO members (id, organisation_id, user_id, role) VALUES ($1, $2, $3, 'owner')",
        vec![Uuid::new_v4().into(), org.into(), user.into()],
    )
    .await;
    org
}

async fn export(ctx: &TestApp, store: &Arc<FakeStore>, at: DateTime<Utc>) -> RunStatus {
    let run = week_run(ctx, at).await;
    job(ctx, store, true)
        .run(run, RunChunkedOptions::default())
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn exports_owner_rows_in_column_order() {
    serve(|_req, ctx| async move {
        let org = owner(&ctx, "Ann@Example.com", Some("Ann Lee"), "Acme, Inc", Some("HN")).await;
        sql(
            &ctx,
            "UPDATE organisations SET billing_status = 'active', billing_tier = 'team' WHERE id = $1;",
            vec![org.into()],
        )
        .await;
        sql(
            &ctx,
            "UPDATE users SET marketing_ok = true WHERE email = 'Ann@Example.com'",
            vec![],
        )
        .await;
        let bare = owner(&ctx, "bob@example.com", None, "Bob Co", None).await;
        // A member who is not an owner has no row.
        let (member, bob) = (Uuid::new_v4(), Uuid::new_v4());
        sql(&ctx, "INSERT INTO users (id, email) VALUES ($1, 'm@example.com')", vec![member.into()]).await;
        sql(
            &ctx,
            "INSERT INTO members (id, organisation_id, user_id, role) VALUES ($1, $2, $3, 'member')",
            vec![bob.into(), org.into(), member.into()],
        )
        .await;

        let store = Arc::new(FakeStore::default());
        assert_eq!(export(&ctx, &store, monday()).await, RunStatus::Done);
        let mut rows: Vec<String> = store.file().lines().map(String::from).collect();
        assert_eq!(rows.remove(0), HEADER);
        rows.sort();
        let mut want = vec![
            format!("ann@example.com,Ann Lee,\"Acme, Inc\",opsagent,{org},customer,team,active,2026-11-10T08:30:05Z,hn,true,false"),
            format!("bob@example.com,,Bob Co,opsagent,{bare},customer,trial,trial,2026-11-10T08:30:05Z,unknown,false,false"),
        ];
        want.sort();
        assert_eq!(rows, want);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn escapes_formula_cells() {
    serve(|_req, ctx| async move {
        let org = owner(
            &ctx,
            "evil@example.com",
            Some("=HYPERLINK(\"http://x\",\"c\")"),
            "+cmd|' /C calc'!A0\u{7}",
            Some("@x"),
        )
        .await;
        let store = Arc::new(FakeStore::default());
        export(&ctx, &store, monday()).await;
        let file = store.file();
        let row = file.lines().nth(1).unwrap();
        let want = format!(
            "evil@example.com,\"'=HYPERLINK(\"\"http://x\"\",\"\"c\"\")\",'+cmd|' /C calc'!A0,opsagent,{org},customer,trial,trial,2026-11-10T08:30:05Z,x,false,false"
        );
        assert_eq!(row, want);
        // The `@` of a source is not in `[a-z0-9_.-]`, so it is stripped, not defused.
        assert_eq!(file.lines().count(), 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn maps_unsubscribe() {
    serve(|_req, ctx| async move {
        owner(&ctx, "Gone@Example.com", Some("G"), "G Co", None).await;
        owner(&ctx, "stay@example.com", Some("S"), "S Co", None).await;
        // The hash `/unsubscribe` stores: SHA-256 of the lower-cased email, in hex.
        let hash: String = Sha256::digest("gone@example.com")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        sql(
            &ctx,
            "INSERT INTO email_suppressions (id, organisation_id, email_hash, reason) VALUES ($1, NULL, $2, 'unsubscribed')",
            vec![Uuid::new_v4().into(), hash.into()],
        )
        .await;
        let store = Arc::new(FakeStore::default());
        export(&ctx, &store, monday()).await;
        let file = store.file();
        let by = |email: &str| file.lines().find(|l| l.starts_with(email)).unwrap().to_owned();
        assert!(by("gone@example.com").ends_with(",false,true"), "{file}");
        assert!(by("stay@example.com").ends_with(",false,false"), "{file}");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn excludes_internal() {
    serve(|_req, ctx| async move {
        owner(&ctx, "Me@OpsAgent.dev", Some("Me"), "Mine", None).await;
        owner(&ctx, "real@example.com", Some("R"), "Real", None).await;
        let store = Arc::new(FakeStore::default());
        export(&ctx, &store, monday()).await;
        let file = store.file();
        assert_eq!(file.lines().count(), 2, "{file}");
        assert!(!file.to_lowercase().contains("opsagent.dev"), "{file}");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn deleted_org_blanked() {
    serve(|_req, ctx| async move {
        let org = owner(&ctx, "d@example.com", Some("Dee"), "Dee Co", Some("hn")).await;
        sql(&ctx, "UPDATE organisations SET deleted_at = now() WHERE id = $1", vec![org.into()]).await;
        let store = Arc::new(FakeStore::default());
        export(&ctx, &store, monday()).await;
        let row = store.file().lines().nth(1).unwrap().to_owned();
        assert_eq!(
            row,
            format!("d@example.com,,,opsagent,{org},customer,trial,deleted,2026-11-10T08:30:05Z,hn,false,false")
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn disabled_writes_nothing() {
    serve(|_req, ctx| async move {
        owner(&ctx, "a@example.com", Some("A"), "A Co", None).await;
        let store = Arc::new(FakeStore::default());
        let run = week_run(&ctx, monday()).await;
        let status = job(&ctx, &store, false)
            .run(run, RunChunkedOptions::default())
            .await
            .unwrap();
        assert_eq!(status, RunStatus::Done);
        assert_eq!(*store.puts.lock().unwrap(), 0);
        assert!(store.objects.lock().unwrap().is_empty());
        // The booted app is off by default: its queued job writes no object either.
        let run = week_run(&ctx, monday() + Duration::days(7)).await;
        perform(&ctx, JobKind::ContactsExport, run).await.unwrap();
    })
    .await;
}

#[tokio::test]
#[serial]
async fn rerun_same_week_overwrites() {
    serve(|_req, ctx| async move {
        owner(&ctx, "a@example.com", Some("A"), "A Co", None).await;
        let store = Arc::new(FakeStore::default());
        export(&ctx, &store, monday()).await;
        assert_eq!(store.file().lines().count(), 2);
        owner(&ctx, "b@example.com", Some("B"), "B Co", None).await;
        // A second run in the same ISO week (a manual re-run): same key, newest content.
        export(&ctx, &store, monday() + Duration::days(1)).await;
        assert_eq!(store.objects.lock().unwrap().len(), 1);
        assert_eq!(*store.puts.lock().unwrap(), 2);
        assert_eq!(store.file().lines().count(), 3);
        // The same run again is a duplicate delivery: it writes nothing more.
        export(&ctx, &store, monday() + Duration::days(1)).await;
        assert_eq!(*store.puts.lock().unwrap(), 2);
    })
    .await;
}
