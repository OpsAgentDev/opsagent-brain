//! `TestApp`: a fresh, migrated database, a flushed Redis db, test doubles built in up front,
//! and the router served through `axum-test`.
use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use axum::Router;
use axum_test::TestServer;
use migration::{Migrator, MigratorTrait};
use opsagent_brain::{
    adapters::slack::{Channel, Install, SlackClient, SlackError},
    boot,
    config::{AppEnv, Config},
    jobs::WorkerRunner,
    mailers::{CaptureMailer, Mailer},
    state::AppState,
};
use sea_orm::{ConnectionTrait, DatabaseConnection};

#[derive(Clone)]
pub struct TestApp {
    pub state: AppState,
    pub db: DatabaseConnection,
    router: Router,
    worker: Arc<WorkerRunner>,
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

/// A pool on the config's database with the `public` schema recreated and migrated, sized
/// for the in-process worker.
async fn fresh_db(c: &Config) -> DatabaseConnection {
    let db = boot::pool(c, true).await.expect("test database");
    db.execute_unprepared("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("recreate schema");
    Migrator::up(&db, None).await.expect("migrate");
    db
}

/// True when `url` names its db index (`/N`), the only case where a flush is safe.
fn names_db_index(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|u| {
        let db = u.path().trim_start_matches('/');
        !db.is_empty() && db.bytes().all(|b| b.is_ascii_digit())
    })
}

/// Lanes isolate by db index, so counters from an earlier run must not leak in. Never flushes
/// an implicit db 0 (another app's data may live there). A Redis that is down stays down
/// (boot needs it lazily; `readyz` tests that).
fn flush_lane_redis(url: &str) {
    if !names_db_index(url) {
        tracing::warn!("REDIS_URL names no db index; not flushed. Use redis://host:port/<lane db>");
        return;
    }
    let redis = opsagent_ledger::redis::Client::open(url).unwrap();
    if let Ok(mut c) = redis.get_connection() {
        let () = opsagent_ledger::redis::cmd("FLUSHDB")
            .query(&mut c)
            .unwrap();
    }
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
        flush_lane_redis(&config.redis_url);
        // The doubles replace every env-dependent adapter (the production mailer needs
        // RESEND_API_KEY), so adapters build as `test`; the env applies to the config only.
        let env = std::mem::replace(&mut config.env, AppEnv::Test);
        let mut deps = boot::deps(config, db.clone()).await.expect("deps");
        deps.config.env = env;
        deps.mailer = Arc::new(CaptureMailer::default());
        deps.slack = Arc::new(NoSlack);
        let state = boot::assemble(deps);
        let worker = Arc::new(boot::worker(&state));
        let mut router = boot::router(state.clone()).expect("router");
        if env == AppEnv::Test {
            // Each request is followed by a drain, so a test sees the jobs it caused as done.
            let w = worker.clone();
            router = router.layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let w = w.clone();
                    async move {
                        let res = next.run(req).await;
                        w.drain().await.expect("drain jobs");
                        res
                    }
                },
            ));
        }
        Self {
            state,
            db,
            router,
            worker,
        }
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

    /// Runs every due job (and the jobs they enqueue) on the app's `WorkerRunner`.
    pub async fn drain_jobs(&self) -> usize {
        self.worker.drain().await.expect("drain jobs")
    }

    /// The app's runner, for tests that build their own (`WorkerRunner::new`) next to it.
    pub fn worker(&self) -> &WorkerRunner {
        &self.worker
    }
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

    #[test]
    fn flushes_only_a_named_db_index() {
        for (url, flush) in [
            ("redis://localhost:56379/5", true),
            ("redis://localhost:56379/15", true),
            ("redis://localhost:6379/0", true),
            ("redis://localhost:6379", false),
            ("redis://localhost:6379/", false),
            ("redis://:pw@localhost:6379/x", false),
        ] {
            assert_eq!(names_db_index(url), flush, "{url}");
        }
    }

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
        // Pools of the previous serial test may still be closing: wait for a steady count.
        let mut baseline = connections(&probe).await;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let next = connections(&probe).await;
            if next == baseline {
                break;
            }
            baseline = next;
        }
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
