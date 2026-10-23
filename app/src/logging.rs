//! The process `tracing` subscriber.
use tracing_subscriber::EnvFilter;

use crate::config::{AppEnv, Config, LogFormat};

/// The pre-switch module list, plus `opsagent`: a target prefix, so every `opsagent_*` crate logs.
const LOG_MODULES: [&str; 4] = ["sea_orm_migration", "tower_http", "sqlx::query", "opsagent"];

/// The filter when `RUST_LOG` is unset: each module at `level`.
fn default_directives(level: &str) -> String {
    let d: Vec<_> = LOG_MODULES.iter().map(|m| format!("{m}={level}")).collect();
    d.join(",")
}

/// Installs the process subscriber: `RUST_LOG` wins, else `default_directives(LOG_LEVEL)`.
/// Off in tests unless `RUST_LOG` is set (the old test logger was disabled). A second call
/// is a no-op.
pub fn init_tracing(c: &Config) {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(f) => f,
        Err(_) if c.env == AppEnv::Test => return,
        Err(_) => EnvFilter::new(default_directives(&c.log_level)),
    };
    let fmt = tracing_subscriber::fmt().with_env_filter(filter);
    let _ = match c.log_format {
        LogFormat::Pretty => fmt.pretty().try_init(),
        LogFormat::Compact => fmt.compact().try_init(),
        LogFormat::Json => fmt.json().try_init(),
    };
}

#[cfg(test)]
mod tests {
    use super::default_directives;

    #[test]
    fn default_filter_covers_every_opsagent_crate() {
        assert_eq!(
            default_directives("info"),
            "sea_orm_migration=info,tower_http=info,sqlx::query=info,opsagent=info"
        );
    }
}
