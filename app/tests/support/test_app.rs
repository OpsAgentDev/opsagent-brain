//! `TestApp`: a fresh, migrated database, a flushed Redis db, test doubles built in up front,
//! and the router served through `axum-test`.
use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use axum::Router;
use axum_test::TestServer;
use migration::{Migrator, MigratorTrait};
use opsagent_brain::{
    adapters::{
        slack::{Channel, Install, SlackClient, SlackError},
        test_doubles::InlineQueue,
    },
    boot,
    config::Config,
    mailers::{CaptureMailer, Mailer},
    state::AppState,
};
use sea_orm::{ConnectionTrait, DatabaseConnection};

#[derive(Clone)]
pub struct TestApp {
    pub state: AppState,
    pub db: DatabaseConnection,
    router: Router,
}

/// The test config: the process environment with `APP_ENV=test`.
fn test_config() -> Config {
    crate::requests::support::test_env();
    Config::from_vars(|k| match k {
        "APP_ENV" => Some("test".into()),
        _ => std::env::var(k).ok(),
    })
    .expect("test config")
}

/// A pool on the config's database with the `public` schema recreated and migrated.
async fn fresh_db(c: &Config) -> DatabaseConnection {
    let db = boot::pool(c).await.expect("test database");
    db.execute_unprepared("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("recreate schema");
    Migrator::up(&db, None).await.expect("migrate");
    db
}

impl TestApp {
    pub async fn boot() -> Self {
        Self::boot_with(|_| {}).await
    }

    /// `boot` with `f` applied to the config first.
    pub async fn boot_with(f: impl FnOnce(&mut Config)) -> Self {
        let mut config = test_config();
        f(&mut config);
        let db = fresh_db(&config).await;
        // Lanes isolate by db index; counters from an earlier run must not leak in. A Redis
        // that is down stays down (boot needs it lazily; `readyz` tests that).
        let redis = opsagent_ledger::redis::Client::open(config.redis_url.as_str()).unwrap();
        if let Ok(mut c) = redis.get_connection() {
            let () = opsagent_ledger::redis::cmd("FLUSHDB")
                .query(&mut c)
                .unwrap();
        }
        let queue = Arc::new(InlineQueue::default());
        let mut deps = boot::deps(config, db.clone(), queue.clone())
            .await
            .expect("deps");
        deps.mailer = Arc::new(CaptureMailer::default());
        deps.slack = Arc::new(NoSlack);
        let state = boot::assemble(deps);
        queue.bind(&state);
        let router = boot::router(state.clone()).expect("router");
        Self { state, db, router }
    }

    /// A client of the app's router that keeps cookies. A method, not a field: `serve` hands
    /// the client and the app to the test separately, and `TestServer` is not `Clone`.
    pub fn server(&self) -> TestServer {
        TestServer::builder()
            .save_cookies()
            .build(self.router.clone())
            .unwrap()
    }

    pub fn set_mailer(&self, m: Arc<dyn Mailer>) {
        self.state.set_mailer(m);
    }

    pub fn set_slack(&self, s: Arc<dyn SlackClient>) {
        self.state.set_slack(s);
    }

    /// The Redis the app's limiter and leases use.
    pub fn redis(&self) -> opsagent_ledger::redis::Client {
        self.state.redis.clone()
    }

    /// shortcut: a no-op, because `InlineQueue` runs each job as it is enqueued; Task 17
    /// drains the Postgres queue here.
    pub async fn drain_jobs(&self) {}
}

/// Boots a `TestApp` and runs `f` with a cookie-saving client of it.
pub async fn serve<F, Fut>(f: F)
where
    F: FnOnce(TestServer, TestApp) -> Fut,
    Fut: Future<Output = ()>,
{
    serve_with(|_| {}, f).await
}

/// `serve` with `config` applied to the config before boot.
pub async fn serve_with<F, Fut>(config: impl FnOnce(&mut Config), f: F)
where
    F: FnOnce(TestServer, TestApp) -> Fut,
    Fut: Future<Output = ()>,
{
    let app = TestApp::boot_with(config).await;
    f(app.server(), app).await;
}

/// The default Slack double: every call fails as unreachable, so nothing leaves the test.
struct NoSlack;

fn unreachable_slack<T>() -> Result<T, SlackError> {
    Err(SlackError::Other("transport".into()))
}

#[async_trait]
impl SlackClient for NoSlack {
    async fn oauth_access(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Install, SlackError> {
        unreachable_slack()
    }

    async fn channels(&self, _: &str) -> Result<Vec<Channel>, SlackError> {
        unreachable_slack()
    }

    async fn revoke(&self, _: &str) -> Result<(), SlackError> {
        unreachable_slack()
    }

    async fn post_message(&self, _: &str, _: &str, _: &str, _: &str) -> Result<String, SlackError> {
        unreachable_slack()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opsagent_brain::adapters::db::ledger_storage::stmt;
    use sea_orm::Database;

    async fn connections(probe: &DatabaseConnection) -> i64 {
        let q = "SELECT count(*) n FROM pg_stat_activity \
                 WHERE datname = current_database() AND pid <> pg_backend_pid()";
        let row = probe.query_one_raw(stmt(q, vec![])).await.unwrap().unwrap();
        row.try_get("", "n").unwrap()
    }

    /// Task 13 review: no state may outlive its test, or its pools exhaust Postgres.
    #[tokio::test]
    #[serial_test::serial]
    async fn connections_return_to_baseline_after_test_apps_drop() {
        let mut opts = sea_orm::ConnectOptions::new(test_config().database_url);
        opts.max_connections(1);
        let probe = Database::connect(opts).await.unwrap();
        let baseline = connections(&probe).await;
        for _ in 0..5 {
            let app = TestApp::boot().await;
            assert_eq!(app.server().get("/readyz").await.status_code(), 200);
            // Opens the lazy scheduler pool too.
            let tick = &app.state.actions.runs.scheduler_tick;
            tick.run(chrono::Utc::now()).await.unwrap();
            assert!(connections(&probe).await > baseline);
        }
        let mut now = connections(&probe).await;
        for _ in 0..50 {
            if now <= baseline {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            now = connections(&probe).await;
        }
        assert!(
            now <= baseline,
            "{now} connections open, baseline {baseline}"
        );
    }
}
