//! Repository contracts: every test body runs against `Pg` (the lane database, schema recreated
//! and migrated per boot) and against the in-memory `MemStore`; both must pass.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_brain::{
    actions::uow::Repos,
    adapters::{
        db::Pg,
        memory::{MemStore, RunLink},
    },
};
use opsagent_core::{
    org::NewOrganisation,
    retention::TtlTable,
    run::{RunKey, RunStatus},
};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use uuid::Uuid;

mod connections;
mod deliveries;
mod findings;
mod integrations;
mod oauth;
mod orgs;
mod passkeys;
mod purge;
mod recipients;
mod resources;
mod retention;
mod runs;
mod schedules;
mod users;

/// A fresh, migrated lane database (`TestApp` recreates the schema).
pub async fn pg() -> Pg {
    Pg::new(crate::support::TestApp::boot().await.db)
}

/// A new organisation in zone `UTC`.
pub async fn org_id(s: &dyn Repos, slug: &str) -> Uuid {
    let new = NewOrganisation {
        id: Uuid::new_v4(),
        slug: slug.into(),
        name: format!("Org {slug}"),
        timezone: "UTC".into(),
        kek_version: 1,
        wrapped_dek: vec![1, 2, 3],
    };
    s.orgs().insert(new).await.unwrap().id
}

/// Parent rows a repository under test needs but does not own (foreign keys on Pg).
#[async_trait]
pub trait Seed: Sync {
    async fn connection(&self, organisation_id: Uuid) -> Uuid;
    async fn run(&self, organisation_id: Uuid, connection_id: Uuid) -> Uuid;
    /// Marks the resource gone, as the full-scan worker does after a complete inventory.
    async fn resource_gone(&self, organisation_id: Uuid, identity: &str);
    /// One `table` row expiring (or observed) at `at`, with any parents it needs.
    async fn expiring(&self, organisation_id: Uuid, table: TtlTable, at: DateTime<Utc>);
    async fn expiring_left(&self, table: TtlTable) -> u64;
    /// A `job_type` run in `status`, scheduled at `at`.
    async fn run_at(
        &self,
        o: Uuid,
        c: Uuid,
        job_type: &str,
        status: RunStatus,
        at: DateTime<Utc>,
    ) -> Uuid;
    /// One row of kind `link` pointing at `run`.
    async fn run_link(&self, o: Uuid, c: Uuid, run: Uuid, link: RunLink);
    /// Rows still pointing at `run`.
    async fn run_links_left(&self, run: Uuid) -> u64;
    /// Audit entries of organisation `o` (`None`: global entries).
    async fn audit_count(&self, o: Option<Uuid>) -> u64;
    /// The metadata of every `org.purged` entry, oldest first.
    async fn purge_records(&self) -> Vec<serde_json::Value>;
}

/// Seeds the lane database over its own connection (the app pool has one connection).
pub struct PgSeed(DatabaseConnection);

impl PgSeed {
    pub async fn new() -> Self {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        Self(Database::connect(url).await.expect("seed connection"))
    }

    pub fn raw(&self) -> &DatabaseConnection {
        &self.0
    }

    async fn exec(&self, sql: &str, values: Vec<sea_orm::Value>) {
        let st = sea_orm::Statement::from_sql_and_values(sea_orm::DbBackend::Postgres, sql, values);
        self.raw().execute_raw(st).await.unwrap();
    }

    /// A fresh OAuth client and grant in `organisation_id`; returns `(client_id, grant_id)`.
    async fn grant(&self, organisation_id: Uuid) -> (String, Uuid) {
        let (client, grant) = (format!("c-{}", Uuid::now_v7()), Uuid::now_v7());
        self.exec(
            "INSERT INTO oauth_clients (client_id, kind, name, redirect_uris) VALUES ($1, 'dynamic', 'x', '[]')",
            vec![client.clone().into()],
        )
        .await;
        self.exec(
            "INSERT INTO oauth_grants (id, client_id, member_id, organisation_id) VALUES ($1, $2, $3, $4)",
            vec![grant.into(), client.clone().into(), Uuid::now_v7().into(), organisation_id.into()],
        )
        .await;
        (client, grant)
    }
}

#[async_trait]
impl Seed for PgSeed {
    async fn connection(&self, organisation_id: Uuid) -> Uuid {
        let id = Uuid::now_v7();
        self.raw()
            .execute_unprepared(&format!(
                "INSERT INTO connections (id, organisation_id, provider) VALUES ('{id}', '{organisation_id}', 'fake')"
            ))
            .await
            .unwrap();
        id
    }

    async fn run(&self, organisation_id: Uuid, connection_id: Uuid) -> Uuid {
        let id = Uuid::now_v7();
        self.raw()
            .execute_unprepared(&format!(
                "INSERT INTO runs (id, organisation_id, connection_id, job_type, scheduled_at) \
                 VALUES ('{id}', '{organisation_id}', '{connection_id}', 'full_scan', now())"
            ))
            .await
            .unwrap();
        id
    }

    async fn expiring(&self, o: Uuid, table: TtlTable, at: DateTime<Utc>) {
        let id = Uuid::now_v7();
        let (sql, values): (&str, Vec<sea_orm::Value>) = match table {
            TtlTable::ResourceHistory | TtlTable::Evidence | TtlTable::ApiCallsRaw => {
                let c = self.connection(o).await;
                let run = self.run(o, c).await;
                let parent = Uuid::now_v7();
                match table {
                    TtlTable::ResourceHistory => {
                        self.exec(
                            "INSERT INTO resources (id, organisation_id, connection_id, kind, identity) VALUES ($1, $2, $3, 'k', $4)",
                            vec![parent.into(), o.into(), c.into(), parent.to_string().into()],
                        )
                        .await;
                        ("INSERT INTO resource_history (id, resource_id, run_id, observed_at) VALUES ($1, $2, $3, $4)",
                         vec![id.into(), parent.into(), run.into(), at.into()])
                    }
                    TtlTable::Evidence => {
                        self.exec(
                            "INSERT INTO findings (id, organisation_id, connection_id, check_id, resource_identity, severity, title) \
                             VALUES ($1, $2, $3, '01', $4, 'low', 't')",
                            vec![parent.into(), o.into(), c.into(), parent.to_string().into()],
                        )
                        .await;
                        ("INSERT INTO evidence (id, finding_id, run_id, source, excerpt, expires_at) VALUES ($1, $2, $3, 's', 'e', $4)",
                         vec![id.into(), parent.into(), run.into(), at.into()])
                    }
                    _ => ("INSERT INTO api_calls_raw (id, run_id, provider, service, action, outcome, called_at) \
                           VALUES ($1, $2, 'fake', 's', 'a', 'ok', $3)",
                          vec![id.into(), run.into(), at.into()]),
                }
            }
            TtlTable::Sessions => (
                "INSERT INTO sessions (id, data, expiry_date) VALUES ($1, '\\x00', $2)",
                vec![id.to_string().into(), at.into()],
            ),
            TtlTable::MagicLinks => (
                "INSERT INTO magic_links (id, email, token_hash, expires_at) VALUES ($1, 'a@example.com', $2, $3)",
                vec![id.into(), id.to_string().into(), at.into()],
            ),
            TtlTable::OauthConsentRequests => {
                let (client, _) = self.grant(o).await;
                ("INSERT INTO oauth_consent_requests (id, client_id, redirect_uri, code_challenge, resource, scope, expires_at) \
                  VALUES ($1, $2, 'r', 'c', 'r', 's', $3)",
                 vec![id.into(), client.into(), at.into()])
            }
            TtlTable::OauthAccessTokens | TtlTable::OauthRefreshTokens => {
                let (_, grant) = self.grant(o).await;
                let sql = if table == TtlTable::OauthAccessTokens {
                    "INSERT INTO oauth_access_tokens (id, grant_id, organisation_id, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5)"
                } else {
                    "INSERT INTO oauth_refresh_tokens (id, grant_id, organisation_id, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5)"
                };
                (sql, vec![id.into(), grant.into(), o.into(), id.to_string().into(), at.into()])
            }
            TtlTable::Invites => (
                "INSERT INTO invites (id, organisation_id, email, role, token_hash, expires_at) VALUES ($1, $2, 'a@example.com', 'member', $3, $4)",
                vec![id.into(), o.into(), id.to_string().into(), at.into()],
            ),
            TtlTable::EmailSuppressions => (
                "INSERT INTO email_suppressions (id, email_hash, reason, expires_at) VALUES ($1, $2, 'confirm_blocked', $3)",
                vec![id.into(), id.to_string().into(), at.into()],
            ),
        };
        self.exec(sql, values).await;
    }

    async fn expiring_left(&self, table: TtlTable) -> u64 {
        let sql = format!("SELECT count(*) AS n FROM {}", table.name());
        let st = sea_orm::Statement::from_string(sea_orm::DbBackend::Postgres, sql);
        let row = self.raw().query_one_raw(st).await.unwrap().unwrap();
        row.try_get::<i64>("", "n").unwrap() as u64
    }

    async fn run_at(
        &self,
        o: Uuid,
        c: Uuid,
        job_type: &str,
        status: RunStatus,
        at: DateTime<Utc>,
    ) -> Uuid {
        let id = Uuid::now_v7();
        let status = serde_json::to_value(status)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let checkpoint = serde_json::to_value(opsagent_ledger::Checkpoint::default()).unwrap();
        self.exec(
            "INSERT INTO runs (id, organisation_id, connection_id, job_type, status, scheduled_at, checkpoint) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            vec![id.into(), o.into(), c.into(), job_type.into(), status.into(), at.into(), checkpoint.into()],
        )
        .await;
        id
    }

    async fn run_link(&self, o: Uuid, c: Uuid, run: Uuid, link: RunLink) {
        let (id, parent) = (Uuid::now_v7(), Uuid::now_v7());
        let finding = |first: Option<Uuid>, last: Option<Uuid>| {
            self.exec(
                "INSERT INTO findings (id, organisation_id, connection_id, check_id, resource_identity, severity, title, \
                 first_seen_run_id, last_seen_run_id) VALUES ($1, $2, $3, '01', $4, 'low', 't', $5, $6)",
                vec![parent.into(), o.into(), c.into(), parent.to_string().into(), first.into(), last.into()],
            )
        };
        let (sql, values): (&str, Vec<sea_orm::Value>) = match link {
            RunLink::FirstSeen => return finding(Some(run), None).await,
            RunLink::LastSeen => return finding(None, Some(run)).await,
            RunLink::FindingEvent => {
                finding(None, None).await;
                ("INSERT INTO finding_events (id, finding_id, run_id, event_type) VALUES ($1, $2, $3, 'seen')",
                 vec![id.into(), parent.into(), run.into()])
            }
            RunLink::Evidence => {
                finding(None, None).await;
                ("INSERT INTO evidence (id, finding_id, run_id, source, excerpt, expires_at) VALUES ($1, $2, $3, 's', 'e', now() + interval '1 day')",
                 vec![id.into(), parent.into(), run.into()])
            }
            RunLink::Effect(key) => (
                "INSERT INTO side_effects (id, run_id, effect_key, status) VALUES ($1, $2, $3, 'done')",
                vec![id.into(), run.into(), key.into()],
            ),
            RunLink::ApiCallStats => (
                "INSERT INTO api_call_stats (id, run_id, provider, service, action, outcome) VALUES ($1, $2, 'fake', 's', 'a', 'ok')",
                vec![id.into(), run.into()],
            ),
            RunLink::ApiCallsRaw => (
                "INSERT INTO api_calls_raw (id, run_id, provider, service, action, outcome) VALUES ($1, $2, 'fake', 's', 'a', 'ok')",
                vec![id.into(), run.into()],
            ),
            RunLink::ResourceHistory => {
                self.exec(
                    "INSERT INTO resources (id, organisation_id, connection_id, kind, identity) VALUES ($1, $2, $3, 'k', $4)",
                    vec![parent.into(), o.into(), c.into(), parent.to_string().into()],
                )
                .await;
                ("INSERT INTO resource_history (id, resource_id, run_id) VALUES ($1, $2, $3)",
                 vec![id.into(), parent.into(), run.into()])
            }
        };
        self.exec(sql, values).await;
    }

    async fn run_links_left(&self, run: Uuid) -> u64 {
        let sql = "SELECT (SELECT count(*) FROM side_effects WHERE run_id = $1) \
             + (SELECT count(*) FROM api_call_stats WHERE run_id = $1) \
             + (SELECT count(*) FROM api_calls_raw WHERE run_id = $1) \
             + (SELECT count(*) FROM resource_history WHERE run_id = $1) \
             + (SELECT count(*) FROM finding_events WHERE run_id = $1) \
             + (SELECT count(*) FROM evidence WHERE run_id = $1) \
             + (SELECT count(*) FROM findings WHERE first_seen_run_id = $1 OR last_seen_run_id = $1) AS n";
        let st = sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            sql,
            vec![run.into()],
        );
        let row = self.raw().query_one_raw(st).await.unwrap().unwrap();
        row.try_get::<i64>("", "n").unwrap() as u64
    }

    async fn audit_count(&self, o: Option<Uuid>) -> u64 {
        let st = sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            "SELECT count(*) AS n FROM audit_events WHERE organisation_id IS NOT DISTINCT FROM $1",
            vec![o.into()],
        );
        let row = self.raw().query_one_raw(st).await.unwrap().unwrap();
        row.try_get::<i64>("", "n").unwrap() as u64
    }

    async fn purge_records(&self) -> Vec<serde_json::Value> {
        let st = sea_orm::Statement::from_string(
            sea_orm::DbBackend::Postgres,
            "SELECT metadata FROM audit_events WHERE action = 'org.purged' ORDER BY created_at",
        );
        let rows = self.raw().query_all_raw(st).await.unwrap();
        rows.iter()
            .map(|r| r.try_get("", "metadata").unwrap())
            .collect()
    }

    async fn resource_gone(&self, organisation_id: Uuid, identity: &str) {
        self.raw()
            .execute_unprepared(&format!(
                "UPDATE resources SET gone_at = now() WHERE organisation_id = '{organisation_id}' \
                 AND identity = '{identity}'"
            ))
            .await
            .unwrap();
    }
}

#[async_trait]
impl Seed for MemStore {
    async fn connection(&self, _: Uuid) -> Uuid {
        Uuid::now_v7()
    }

    async fn run(&self, _: Uuid, _: Uuid) -> Uuid {
        Uuid::now_v7()
    }

    async fn expiring(&self, _: Uuid, table: TtlTable, at: DateTime<Utc>) {
        self.seed_expiring(table, at);
    }

    async fn expiring_left(&self, table: TtlTable) -> u64 {
        MemStore::expiring_left(self, table)
    }

    async fn run_at(
        &self,
        o: Uuid,
        c: Uuid,
        job_type: &str,
        status: RunStatus,
        at: DateTime<Utc>,
    ) -> Uuid {
        let key = RunKey {
            organisation_id: Some(o),
            connection_id: Some(c),
            job_type: job_type.into(),
            scheduled_at: at,
        };
        self.seed_run(key, status).await
    }

    async fn run_link(&self, o: Uuid, c: Uuid, run: Uuid, link: RunLink) {
        self.seed_run_link(o, c, run, link);
    }

    async fn run_links_left(&self, run: Uuid) -> u64 {
        MemStore::run_links_left(self, run)
    }

    async fn audit_count(&self, o: Option<Uuid>) -> u64 {
        let all = self.audit_entries();
        all.iter().filter(|e| e.organisation_id == o).count() as u64
    }

    async fn purge_records(&self) -> Vec<serde_json::Value> {
        let all = self.audit_entries();
        let purged = all.into_iter().filter(|e| e.action == "org.purged");
        purged.map(|e| e.meta).collect()
    }

    async fn resource_gone(&self, organisation_id: Uuid, identity: &str) {
        self.mark_resource_gone(organisation_id, identity, chrono::Utc::now());
    }
}

/// `contract_suite! { async fn name(s) { body } ... }`: `s` is a `&dyn UnitOfWork`; each
/// `name` becomes a module with a `pg` and a `mem` test. `async fn name(s, seed)` also binds
/// `seed: &dyn Seed` for parent rows.
macro_rules! contract_suite {
    ($(async fn $name:ident($s:ident $(, $seed:ident)?) $body:block)*) => {$(
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            #[tokio::test]
            #[serial_test::serial]
            async fn pg() {
                let store = crate::contracts::pg().await;
                let $s: &dyn opsagent_brain::actions::uow::UnitOfWork = &store;
                $(let seed = crate::contracts::PgSeed::new().await;
                let $seed: &dyn crate::contracts::Seed = &seed;)?
                $body
            }

            #[tokio::test]
            async fn mem() {
                let store = opsagent_brain::adapters::memory::MemStore::default();
                let $s: &dyn opsagent_brain::actions::uow::UnitOfWork = &store;
                $(let $seed: &dyn crate::contracts::Seed = &store;)?
                $body
            }
        }
    )*};
}
pub(crate) use contract_suite;
mod queue;
