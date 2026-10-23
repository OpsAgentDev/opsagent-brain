//! The `opsagent-brain` command line: `start`, `scheduler`, `task <name> [k:v…]`, `db`.
use std::{collections::BTreeMap, process::ExitCode, sync::Arc};

use chrono::Utc;
use clap::{Parser, Subcommand};
use migration::{Migrator, MigratorTrait};
use uuid::Uuid;

use crate::{
    adapters::loco_queue::LocoQueue,
    boot,
    config::{self, Config},
    controllers::openapi::document_json,
    error::{AppError, AppResult},
    logging::init_tracing,
    state::AppState,
};

/// The committed OpenAPI document, `openapi:dump`'s default target.
const COMMITTED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../openapi.json");

#[derive(Parser)]
#[command(name = "opsagent-brain", version)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// The API; `--worker` the job workers only; `--server-and-worker` both.
    Start {
        #[arg(long)]
        worker: bool,
        #[arg(long)]
        server_and_worker: bool,
    },
    /// The scheduler (exactly one instance).
    Scheduler,
    /// `openapi:dump [path:<file>]`, `scan:now connection:<id>`,
    /// `deliver:briefing connection:<id>`, `scheduler:tick`.
    Task { name: String, vars: Vec<String> },
    Db {
        #[command(subcommand)]
        op: DbOp,
    },
}

#[derive(Subcommand)]
pub enum DbOp {
    Migrate,
    Status,
}

/// A task's `k:v` arguments.
#[derive(Debug)]
pub struct TaskVars(BTreeMap<String, String>);

impl TaskVars {
    pub fn parse(raw: &[String]) -> Result<Self, AppError> {
        raw.iter()
            .map(|kv| match kv.split_once(':') {
                Some((k, v)) => Ok((k.to_owned(), v.to_owned())),
                None => Err(AppError::Invalid(format!("task var `{kv}` is not k:v"))),
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }

    pub fn get(&self, k: &str) -> Result<&str, AppError> {
        self.0
            .get(k)
            .map(String::as_str)
            .ok_or_else(|| AppError::Invalid(format!("missing task var `{k}:<value>`")))
    }

    pub fn uuid(&self, k: &str) -> Result<Uuid, AppError> {
        self.get(k)?
            .parse()
            .map_err(|_| AppError::Invalid(format!("task var `{k}` is not a uuid")))
    }
}

/// Installs the process subscriber before any command runs. With a config that does not
/// parse, a default subscriber, so the config error itself is still logged.
pub fn install_tracing() {
    match Config::from_env() {
        Ok(c) => init_tracing(&c),
        Err(_) => drop(tracing_subscriber::fmt().try_init()),
    }
    config::warn_if_loco_env();
}

/// Runs `cli`; a failure is logged as one `tracing` error and exits 1.
pub async fn main(cli: Cli) -> ExitCode {
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "command failed");
            ExitCode::FAILURE
        }
    }
}

pub async fn run(cli: Cli) -> Result<(), AppError> {
    match cli.cmd {
        Cmd::Start {
            worker: false,
            server_and_worker: false,
        } => serve().await,
        // shortcut: Loco still runs the workers and the scheduler; Task 18 replaces both.
        Cmd::Start { .. } | Cmd::Scheduler => loco_rs::cli::main::<crate::app::App, Migrator>()
            .await
            .map_err(internal),
        Cmd::Task { name, vars } => task(&name, &TaskVars::parse(&vars)?).await,
        Cmd::Db { op } => db(op).await,
    }
}

fn internal(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(e.to_string())
}

fn config() -> AppResult<Config> {
    Config::from_env().map_err(internal)
}

/// The state over the Loco queue the workers drain (until Task 18).
async fn state() -> AppResult<AppState> {
    let c = config()?;
    let queue = Arc::new(LocoQueue::connect(c.env).await?);
    // shortcut: the worker modes still run under Loco; Task 18 boots them with `worker: true`.
    boot::boot(c, queue, false).await
}

/// The API until SIGTERM or Ctrl-C; in-flight requests finish first.
async fn serve() -> AppResult<()> {
    let state = state().await?;
    let addr = format!("{}:{}", state.config.binding, state.config.port);
    let router = boot::router(state)?;
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(internal)?;
    tracing::info!(%addr, "listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(internal)
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => drop(s.recv().await),
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = term => {} }
    tracing::info!("shutting down");
}

async fn task(name: &str, vars: &TaskVars) -> AppResult<()> {
    let not_found = |e| match e {
        AppError::NotFound => AppError::Invalid("connection not found".into()),
        e => e,
    };
    match name {
        "openapi:dump" => {
            let path = vars.get("path").unwrap_or(COMMITTED);
            std::fs::write(path, document_json()).map_err(internal)
        }
        "scan:now" => {
            let id = vars.uuid("connection")?;
            let a = state().await?.actions.clone();
            a.runs.scan_now.run(id).await.map(drop).map_err(not_found)
        }
        "deliver:briefing" => {
            let id = vars.uuid("connection")?;
            let a = state().await?.actions.clone();
            let now = &a.deliveries.deliver_briefing_now;
            now.run(id).await.map(drop).map_err(not_found)
        }
        "scheduler:tick" => {
            let a = state().await?.actions.clone();
            match a.runs.scheduler_tick.run(Utc::now()).await? {
                Some(r) => tracing::info!(?r, "scheduler tick"),
                None => tracing::info!("scheduler lock held elsewhere, skipping tick"),
            }
            Ok(())
        }
        other => Err(AppError::Invalid(format!("unknown task `{other}`"))),
    }
}

/// `db migrate` applies pending migrations; `db status` lists them. Neither boots the app.
async fn db(op: DbOp) -> AppResult<()> {
    let c = config()?;
    let db = sea_orm::Database::connect(c.database_url.as_str())
        .await
        .map_err(internal)?;
    match op {
        DbOp::Migrate => Migrator::up(&db, None).await,
        DbOp::Status => Migrator::status(&db).await,
    }
    .map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("opsagent-brain").chain(args.iter().copied()))
    }

    fn vars(cli: Cli) -> Result<TaskVars, AppError> {
        let Cmd::Task { vars, .. } = cli.cmd else {
            panic!("not a task")
        };
        TaskVars::parse(&vars)
    }

    #[test]
    fn task_deliver_briefing_connection_var_parses() {
        let id = Uuid::new_v4();
        let cli = parse(&["task", "deliver:briefing", &format!("connection:{id}")]).unwrap();
        let Cmd::Task { ref name, .. } = cli.cmd else {
            panic!("not a task")
        };
        assert_eq!(name, "deliver:briefing");
        assert_eq!(vars(cli).unwrap().uuid("connection").unwrap(), id);
    }

    #[test]
    fn task_var_without_colon_is_error() {
        let cli = parse(&["task", "scan:now", "connection"]).unwrap();
        assert!(matches!(vars(cli), Err(AppError::Invalid(_))));
    }

    #[tokio::test]
    async fn task_missing_connection_var_is_error() {
        let cli = parse(&["task", "scan:now"]).unwrap();
        assert!(matches!(
            vars(cli).unwrap().uuid("connection"),
            Err(AppError::Invalid(_))
        ));
        // Refused before any boot: no database or KEK is needed to see it.
        let cli = parse(&["task", "deliver:briefing", "connection:nope"]).unwrap();
        assert!(matches!(run(cli).await, Err(AppError::Invalid(_))));
    }

    #[test]
    fn start_server_and_worker_flag_parses() {
        let cli = parse(&["start", "--server-and-worker"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Start {
                worker: false,
                server_and_worker: true
            }
        ));
        assert!(matches!(
            parse(&["start"]).unwrap().cmd,
            Cmd::Start {
                worker: false,
                server_and_worker: false
            }
        ));
    }

    #[test]
    fn db_status_parses() {
        let cli = parse(&["db", "status"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Db { op: DbOp::Status }));
        assert!(parse(&["db", "nope"]).is_err());
    }

    #[derive(Clone, Default)]
    struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn unknown_task_name_exits_non_zero() {
        let buf = Buf::default();
        let sub = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer({
                let b = buf.clone();
                move || b.clone()
            })
            .finish();
        let _g = tracing::subscriber::set_default(sub);
        let code = main(parse(&["task", "nope:now"]).unwrap()).await;
        assert_eq!(code, std::process::ExitCode::FAILURE);
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(out.contains("ERROR"), "{out}");
        assert!(out.contains("command failed"), "{out}");
        assert!(out.contains("unknown task `nope:now`"), "{out}");
    }

    #[tokio::test]
    async fn openapi_dump_writes_committed_bytes() {
        let path = std::env::temp_dir().join(format!("openapi-{}.json", Uuid::new_v4()));
        let arg = format!("path:{}", path.display());
        run(parse(&["task", "openapi:dump", &arg]).unwrap())
            .await
            .unwrap();
        let written = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(written, std::fs::read(COMMITTED).unwrap());
    }
}
