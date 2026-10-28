//! Repository contracts: every test body runs against `Pg` (the lane database, schema recreated
//! and migrated per boot) and against the in-memory `MemStore`; both must pass.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_brain::{
    actions::uow::Repos,
    adapters::{db::Pg, memory::MemStore},
};
use opsagent_core::{org::NewOrganisation, retention::TtlTable};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use uuid::Uuid;

mod connections;
mod deliveries;
mod findings;
mod integrations;
mod oauth;
mod orgs;
mod passkeys;
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
