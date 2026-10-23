//! `Config`: every setting is an environment variable, and its default lives here and only here.
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppEnv {
    Development,
    Test,
    Production,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Compact,
    Json,
}

/// `OPSAGENT_CONNECTORS`: `fake` serves every provider from fixtures (tests, local runs) and is
/// refused in production; `aws` (the default) uses the real connectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorMode {
    Aws,
    Fake,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required variables: {0:?}")]
    Missing(Vec<&'static str>),
    #[error("{name}: {reason}")]
    Invalid { name: &'static str, reason: String },
}

/// No `Debug`: it holds secrets.
#[derive(Clone)]
pub struct Config {
    pub env: AppEnv,
    pub port: u16,
    pub binding: String,
    pub log_level: String,
    pub log_format: LogFormat,
    pub database_url: String,
    pub db_logging: bool,
    pub db_connect_timeout_ms: u64,
    pub db_idle_timeout_ms: u64,
    pub db_min_connections: u32,
    pub db_max_connections: u32,
    pub db_auto_migrate: bool,
    pub redis_url: String,
    pub web_base_url: String,
    pub api_base_url: String,
    pub session_secret: String,
    /// Keys unsubscribe links; empty falls back to `session_secret` (see `unsubscribe_key`).
    pub unsubscribe_secret: String,
    pub cookie_secure: bool,
    /// Empty means host-only cookie (local development).
    pub cookie_domain: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    /// Empty disables Slack (`slack_not_configured`).
    pub slack_client_id: String,
    pub slack_client_secret: String,
    pub slack_api_base_url: String,
    pub connectors: ConnectorMode,
    pub aws_outbound_role_arn: Option<String>,
    /// Where the customer-facing CloudFormation templates are served.
    pub template_base_url: String,
    pub worker_concurrency: usize,
    pub worker_poll_ms: u64,
    pub job_lock_max_age_secs: u64,
    pub worker_shutdown_grace_secs: u64,
}

/// Required in production (no default there); the same list as deployment.md and deploy/README.md.
const PRODUCTION_REQUIRED: [&str; 9] = [
    "DATABASE_URL",
    "REDIS_URL",
    "APP_BASE_URL",
    "WEB_BASE_URL",
    "SESSION_SECRET",
    "OPSAGENT_KEK",
    "OPSAGENT_CONNECTORS",
    "OPSAGENT_AWS_OUTBOUND_ROLE_ARN",
    "OPSAGENT_TEMPLATE_BASE_URL",
];

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    /// The testable core: `get` is the environment. An empty value counts as unset.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |k: &str| get(k).filter(|v| !v.is_empty());
        let env = app_env(&get)?;
        let prod = env == AppEnv::Production;
        let missing: Vec<_> = PRODUCTION_REQUIRED
            .into_iter()
            .filter(|k| prod && get(k).is_none())
            .collect();
        if !missing.is_empty() {
            return Err(ConfigError::Missing(missing));
        }
        // (development, test, production) defaults.
        let pick = |d: &'static str, t: &'static str, p: &'static str| match env {
            AppEnv::Development => d,
            AppEnv::Test => t,
            AppEnv::Production => p,
        };
        let s = |k: &str, default: &str| get(k).unwrap_or_else(|| default.to_owned());
        let db_dev = "postgres://loco:loco@localhost:5432/opsagent_brain_development";
        let db_test = "postgres://loco:loco@localhost:5432/opsagent_brain_test";
        let c = Self {
            env,
            port: p(&get, "PORT", "5150")?,
            binding: s("BINDING", pick("localhost", "localhost", "0.0.0.0")),
            log_level: s("LOG_LEVEL", pick("debug", "debug", "info")),
            log_format: log_format(&s("LOG_FORMAT", pick("pretty", "compact", "json")))?,
            database_url: s("DATABASE_URL", pick(db_dev, db_test, "")),
            db_logging: p(&get, "DB_LOGGING", "false")?,
            db_connect_timeout_ms: p(&get, "DB_CONNECT_TIMEOUT", "500")?,
            db_idle_timeout_ms: p(&get, "DB_IDLE_TIMEOUT", "500")?,
            db_min_connections: p(&get, "DB_MIN_CONNECTIONS", "1")?,
            db_max_connections: p(&get, "DB_MAX_CONNECTIONS", pick("1", "1", "10"))?,
            db_auto_migrate: p(&get, "DB_AUTO_MIGRATE", pick("true", "true", "false"))?,
            redis_url: s("REDIS_URL", "redis://localhost:6379"),
            web_base_url: s("WEB_BASE_URL", "http://localhost:3000"),
            api_base_url: s("APP_BASE_URL", "http://localhost:5150"),
            session_secret: s(
                "SESSION_SECRET",
                pick(
                    "dev-session-secret-change-me",
                    "test-session-secret-not-for-prod",
                    "",
                ),
            ),
            unsubscribe_secret: s("UNSUBSCRIBE_SECRET", ""),
            cookie_secure: p(&get, "COOKIE_SECURE", pick("false", "true", "true"))?,
            cookie_domain: s("COOKIE_DOMAIN", pick("", "", "opsagent.dev")),
            github_client_id: s("GITHUB_CLIENT_ID", ""),
            github_client_secret: s("GITHUB_CLIENT_SECRET", ""),
            slack_client_id: s("SLACK_CLIENT_ID", ""),
            slack_client_secret: s("SLACK_CLIENT_SECRET", ""),
            slack_api_base_url: s("SLACK_API_BASE_URL", "https://slack.com/api"),
            connectors: connectors(&s("OPSAGENT_CONNECTORS", "aws"), prod)?,
            aws_outbound_role_arn: get("OPSAGENT_AWS_OUTBOUND_ROLE_ARN"),
            template_base_url: s(
                "OPSAGENT_TEMPLATE_BASE_URL",
                "https://templates.opsagent.dev",
            ),
            worker_concurrency: p(&get, "WORKER_CONCURRENCY", "4")?,
            worker_poll_ms: p(&get, "WORKER_POLL_MS", "1000")?,
            // 420 min, the old reaper age, above the 6 h scan cap.
            job_lock_max_age_secs: p(&get, "JOB_LOCK_MAX_AGE_SECS", "25200")?,
            worker_shutdown_grace_secs: p(&get, "WORKER_SHUTDOWN_GRACE_SECS", "30")?,
        };
        if c.session_secret.len() < 16 {
            return Err(invalid("SESSION_SECRET", "must be at least 16 bytes"));
        }
        if !c.unsubscribe_secret.is_empty() && c.unsubscribe_secret.len() < 16 {
            return Err(invalid("UNSUBSCRIBE_SECRET", "must be at least 16 bytes"));
        }
        Ok(c)
    }

    /// The unsubscribe HMAC secret: `UNSUBSCRIBE_SECRET`, else `SESSION_SECRET` (links issued
    /// under the fallback keep working once it is set to the same value).
    pub fn unsubscribe_key(&self) -> &str {
        if self.unsubscribe_secret.is_empty() {
            &self.session_secret
        } else {
            &self.unsubscribe_secret
        }
    }
}

fn invalid(name: &'static str, reason: &str) -> ConfigError {
    ConfigError::Invalid {
        name,
        reason: reason.into(),
    }
}

/// `APP_ENV`, else the deprecated `LOCO_ENV`, else development.
fn app_env(get: &impl Fn(&str) -> Option<String>) -> Result<AppEnv, ConfigError> {
    let value = get("APP_ENV").or_else(|| {
        let v = get("LOCO_ENV");
        if v.is_some() {
            tracing::warn!("LOCO_ENV is deprecated, set APP_ENV");
        }
        v
    });
    match value.as_deref().unwrap_or("development") {
        "development" => Ok(AppEnv::Development),
        "test" => Ok(AppEnv::Test),
        "production" => Ok(AppEnv::Production),
        _ => Err(invalid(
            "APP_ENV",
            "must be development, test or production",
        )),
    }
}

fn log_format(v: &str) -> Result<LogFormat, ConfigError> {
    match v {
        "pretty" => Ok(LogFormat::Pretty),
        "compact" => Ok(LogFormat::Compact),
        "json" => Ok(LogFormat::Json),
        _ => Err(invalid("LOG_FORMAT", "must be pretty, compact or json")),
    }
}

fn connectors(v: &str, production: bool) -> Result<ConnectorMode, ConfigError> {
    match v {
        "fake" if production => Err(invalid(
            "OPSAGENT_CONNECTORS",
            "fake is not allowed in production",
        )),
        "fake" => Ok(ConnectorMode::Fake),
        "aws" => Ok(ConnectorMode::Aws),
        _ => Err(invalid("OPSAGENT_CONNECTORS", "must be aws or fake")),
    }
}

/// `name` parsed, else `default`. The value is not echoed: it may be a secret set under the wrong name.
fn p<T: FromStr>(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: &str,
) -> Result<T, ConfigError> {
    get(name)
        .as_deref()
        .unwrap_or(default)
        .parse()
        .map_err(|_| invalid(name, &format!("not a valid {}", std::any::type_name::<T>())))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use uuid::Uuid;

    use super::*;
    use crate::actions::recipients::tokens::unsubscribe_token;

    fn vars(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_vars(|k| m.get(k).cloned())
    }

    fn ok(r: Result<Config, ConfigError>) -> Config {
        r.unwrap_or_else(|e| panic!("{e}"))
    }

    fn cfg(pairs: &[(&str, &str)]) -> Config {
        ok(vars(pairs))
    }

    fn production(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
        let mut v = vec![
            ("APP_ENV", "production"),
            ("DATABASE_URL", "postgres://db/prod"),
            ("REDIS_URL", "redis://redis"),
            ("APP_BASE_URL", "https://brain.opsagent.dev"),
            ("WEB_BASE_URL", "https://opsagent.dev"),
            ("SESSION_SECRET", "a-production-session-secret"),
            ("OPSAGENT_KEK", "k"),
            ("OPSAGENT_CONNECTORS", "aws"),
            ("OPSAGENT_AWS_OUTBOUND_ROLE_ARN", "arn:aws:iam::1:role/o"),
            (
                "OPSAGENT_TEMPLATE_BASE_URL",
                "https://templates.opsagent.dev",
            ),
        ];
        v.extend_from_slice(extra);
        v
    }

    #[test]
    fn production_lists_every_missing_required_var_at_once() {
        match vars(&[("APP_ENV", "production"), ("REDIS_URL", "redis://r")]) {
            Err(ConfigError::Missing(m)) => {
                let want: Vec<_> = PRODUCTION_REQUIRED
                    .into_iter()
                    .filter(|k| *k != "REDIS_URL")
                    .collect();
                assert_eq!(m, want);
            }
            _ => panic!("expected Missing"),
        }
        let c = cfg(&production(&[]));
        assert_eq!(
            (c.binding.as_str(), c.port, c.log_level.as_str()),
            ("0.0.0.0", 5150, "info")
        );
        assert_eq!((c.log_format, c.db_max_connections), (LogFormat::Json, 10));
        assert!(c.cookie_secure && !c.db_auto_migrate);
        assert_eq!(c.cookie_domain, "opsagent.dev");
    }

    #[test]
    fn production_refuses_fake_connectors() {
        let fake = production(&[("OPSAGENT_CONNECTORS", "fake")]);
        assert!(matches!(
            vars(&fake),
            Err(ConfigError::Invalid {
                name: "OPSAGENT_CONNECTORS",
                ..
            })
        ));
        let c = cfg(&[("OPSAGENT_CONNECTORS", "fake")]);
        assert_eq!(c.connectors, ConnectorMode::Fake);
        assert_eq!(cfg(&production(&[])).connectors, ConnectorMode::Aws);
        assert_eq!(cfg(&[]).connectors, ConnectorMode::Aws);
        assert!(vars(&[("OPSAGENT_CONNECTORS", "bogus")]).is_err());
    }

    #[test]
    fn loco_env_is_a_fallback_for_app_env() {
        assert_eq!(cfg(&[]).env, AppEnv::Development);
        assert_eq!(cfg(&[("LOCO_ENV", "test")]).env, AppEnv::Test);
        let both = vars(&[("APP_ENV", "test"), ("LOCO_ENV", "development")]);
        assert_eq!(ok(both).env, AppEnv::Test);
        assert!(vars(&[("APP_ENV", "staging")]).is_err());
    }

    #[test]
    fn short_session_secret_rejected() {
        let short = vars(&[("SESSION_SECRET", "too-short")]);
        assert!(matches!(
            short,
            Err(ConfigError::Invalid {
                name: "SESSION_SECRET",
                ..
            })
        ));
        let unsub = vars(&[("UNSUBSCRIBE_SECRET", "too-short")]);
        assert!(matches!(
            unsub,
            Err(ConfigError::Invalid {
                name: "UNSUBSCRIBE_SECRET",
                ..
            })
        ));
        assert!(matches!(
            vars(&[("PORT", "http")]),
            Err(ConfigError::Invalid { name: "PORT", .. })
        ));
    }

    #[test]
    fn unsubscribe_key_falls_back_to_session_secret() {
        let session = ("SESSION_SECRET", "session-secret-0123456789");
        let id = Uuid::new_v4();
        let before = unsubscribe_token(cfg(&[session]).unsubscribe_key(), id);
        let same = vars(&[session, ("UNSUBSCRIBE_SECRET", "session-secret-0123456789")]);
        assert_eq!(unsubscribe_token(ok(same).unsubscribe_key(), id), before);
        let own = vars(&[
            session,
            ("UNSUBSCRIBE_SECRET", "unsubscribe-secret-0123456789"),
        ]);
        assert_eq!(ok(own).unsubscribe_key(), "unsubscribe-secret-0123456789");
    }
}
