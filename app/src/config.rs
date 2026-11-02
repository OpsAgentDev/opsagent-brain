//! `Config`: every setting is an environment variable, and its default lives here and only here.
use std::{str::FromStr, time::Duration};

use opsagent_core::endpoint::UrlPolicy;

mod ai;
pub use ai::{
    model_price, preferred_models, ModelMode, ModelSettings, OpsAgentConnection, MODEL_CHAT,
    MODEL_ROUTINE, OPENAI_TOOL_PREFIXES,
};

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
    pub google_client_id: String,
    pub google_client_secret: String,
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
    /// A request still running after this answers 504 `timeout`.
    pub request_timeout_secs: u64,
    /// Fixed recipient of contact-form mail; never taken from a request.
    pub contact_to: String,
    /// Empty disables billing (`billing_unavailable`).
    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,
    pub stripe_price_starter: String,
    pub stripe_price_team: String,
    pub stripe_price_scale: String,
    pub stripe_api_base: String,
    /// The pinned API version, sent as `Stripe-Version`.
    pub stripe_api_version: String,
    pub stripe_automatic_tax: bool,
    /// Off: nothing is gated on billing state (the alpha organisations keep working).
    pub billing_enforced: bool,
    /// `None`: no OpsAgent model key (`ai_unavailable`).
    pub opsagent: Option<OpsAgentConnection>,
    pub opsagent_backup: Option<OpsAgentConnection>,
    pub allow_private: bool,
    pub model_provider: ModelMode,
    pub anthropic_api_base: String,
    pub anthropic_version: String,
    pub openai_api_base: String,
    pub ai_limits: crate::adapters::model::ModelLimits,
}

/// Required in production (no default there); the same list as deployment.md and deploy/README.md.
const PRODUCTION_REQUIRED: [&str; 7] = [
    "DATABASE_URL",
    "REDIS_URL",
    "APP_BASE_URL",
    "WEB_BASE_URL",
    "SESSION_SECRET",
    "OPSAGENT_KEK",
    "OPSAGENT_CONNECTORS",
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
        let allow_private: bool = p(&get, "AI_ENDPOINT_ALLOW_PRIVATE", "false")?;
        if allow_private && prod {
            return Err(invalid(
                "AI_ENDPOINT_ALLOW_PRIVATE",
                "is not allowed in production",
            ));
        }
        let policy = if allow_private {
            UrlPolicy::Local
        } else {
            UrlPolicy::Trusted
        };
        let (opsagent, opsagent_backup) = ai::opsagent_connections(get, policy)?;
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
            google_client_id: s("GOOGLE_CLIENT_ID", ""),
            google_client_secret: s("GOOGLE_CLIENT_SECRET", ""),
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
            request_timeout_secs: p(&get, "REQUEST_TIMEOUT_SECS", "30")?,
            contact_to: s("CONTACT_TO", "info@opsagent.dev"),
            stripe_secret_key: s("STRIPE_SECRET_KEY", ""),
            stripe_webhook_secret: s("STRIPE_WEBHOOK_SECRET", ""),
            stripe_price_starter: s("STRIPE_PRICE_STARTER", ""),
            stripe_price_team: s("STRIPE_PRICE_TEAM", ""),
            stripe_price_scale: s("STRIPE_PRICE_SCALE", ""),
            stripe_api_base: s("STRIPE_API_BASE", crate::adapters::stripe::API_BASE),
            stripe_api_version: s("STRIPE_API_VERSION", "2025-09-30.clover"),
            stripe_automatic_tax: p(&get, "STRIPE_AUTOMATIC_TAX", "false")?,
            billing_enforced: p(&get, "BILLING_ENFORCED", "false")?,
            opsagent,
            opsagent_backup,
            allow_private,
            model_provider: ai::model_mode(&s("OPSAGENT_MODEL_PROVIDER", "live"), prod)?,
            anthropic_api_base: s(
                "ANTHROPIC_API_BASE",
                crate::adapters::model::anthropic::API_BASE,
            ),
            anthropic_version: s("ANTHROPIC_VERSION", "2023-06-01"),
            openai_api_base: s("OPENAI_API_BASE", crate::adapters::model::openai::API_BASE),
            ai_limits: ai_limits(&get)?,
        };
        if c.session_secret.len() < 16 {
            return Err(invalid("SESSION_SECRET", "must be at least 16 bytes"));
        }
        // rmcp treats an empty allowed-hosts list as allow-all, so the host must exist.
        let base = reqwest::Url::parse(&c.api_base_url).ok();
        if !base.is_some_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some()) {
            return Err(invalid(
                "APP_BASE_URL",
                "must be an absolute http(s) URL with a host",
            ));
        }
        if !c.unsubscribe_secret.is_empty() && c.unsubscribe_secret.len() < 16 {
            return Err(invalid("UNSUBSCRIBE_SECRET", "must be at least 16 bytes"));
        }
        Ok(c)
    }

    /// Checkout, Portal and Stripe calls can work (`billing_unavailable` otherwise).
    pub fn stripe_configured(&self) -> bool {
        !self.stripe_secret_key.is_empty()
    }

    /// The webhook can verify signatures; it answers 503 otherwise.
    pub fn webhook_configured(&self) -> bool {
        self.stripe_configured() && !self.stripe_webhook_secret.is_empty()
    }

    /// The Stripe adapter's settings.
    pub fn stripe_settings(&self) -> crate::adapters::stripe::StripeSettings {
        crate::adapters::stripe::StripeSettings {
            api_base: self.stripe_api_base.clone(),
            secret_key: self.stripe_secret_key.clone(),
            api_version: self.stripe_api_version.clone(),
            automatic_tax: self.stripe_automatic_tax,
        }
    }

    /// The model adapters' and `AiAccess`'s settings.
    pub fn model_settings(&self) -> ModelSettings {
        ModelSettings {
            mode: self.model_provider,
            opsagent: self.opsagent.clone(),
            opsagent_backup: self.opsagent_backup.clone(),
            allow_private: self.allow_private,
            anthropic_api_base: self.anthropic_api_base.clone(),
            anthropic_version: self.anthropic_version.clone(),
            openai_api_base: self.openai_api_base.clone(),
            limits: self.ai_limits,
        }
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

/// Warns when the environment came from `LOCO_ENV`. Called once tracing is up: config is read
/// before the subscriber exists, so a warning from `from_vars` would go nowhere.
pub fn warn_if_deprecated_env() {
    let set = |k| std::env::var(k).is_ok_and(|v| !v.is_empty());
    if !set("APP_ENV") && set("LOCO_ENV") {
        tracing::warn!("LOCO_ENV is deprecated, set APP_ENV");
    }
}

/// `APP_ENV`, else the deprecated `LOCO_ENV` (see `warn_if_deprecated_env`), else development.
fn app_env(get: &impl Fn(&str) -> Option<String>) -> Result<AppEnv, ConfigError> {
    let value = get("APP_ENV").or_else(|| get("LOCO_ENV"));
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
/// `OPSAGENT_AI_MAX_RESPONSE_BYTES`, `_CALL_TIMEOUT_SECS`, `_STREAM_TIMEOUT_SECS`; each above 0.
fn ai_limits(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<crate::adapters::model::ModelLimits, ConfigError> {
    let d = crate::adapters::model::ModelLimits::default();
    let pos = |name: &'static str, default: u64| -> Result<u64, ConfigError> {
        match p(get, name, &default.to_string())? {
            0 => Err(invalid(name, "must be above 0")),
            n => Ok(n),
        }
    };
    Ok(crate::adapters::model::ModelLimits {
        body_cap: pos("OPSAGENT_AI_MAX_RESPONSE_BYTES", d.body_cap as u64)? as usize,
        call: Duration::from_secs(pos("OPSAGENT_AI_CALL_TIMEOUT_SECS", d.call.as_secs())?),
        stream: Duration::from_secs(pos("OPSAGENT_AI_STREAM_TIMEOUT_SECS", d.stream.as_secs())?),
    })
}

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

    use opsagent_core::model::AiProvider;
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

    #[test]
    fn app_base_url_must_be_an_absolute_http_url() {
        for bad in [
            "brain.opsagent.dev",
            "/v1",
            "ftp://x.dev",
            "http://",
            "mailto:a@b.c",
        ] {
            let r = vars(&[("APP_BASE_URL", bad)]);
            assert!(
                matches!(
                    r,
                    Err(ConfigError::Invalid {
                        name: "APP_BASE_URL",
                        ..
                    })
                ),
                "{bad}"
            );
        }
        assert_eq!(
            cfg(&[("APP_BASE_URL", "https://b.dev:8443")]).api_base_url,
            "https://b.dev:8443"
        );
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
        assert_eq!(c.request_timeout_secs, 30);
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
    fn billing_defaults_off_and_parses_flags() {
        let c = cfg(&[]);
        assert!(c.stripe_secret_key.is_empty() && !c.billing_enforced && !c.stripe_automatic_tax);
        assert_eq!(c.stripe_api_base, "https://api.stripe.com");
        let on = cfg(&[
            ("BILLING_ENFORCED", "true"),
            ("STRIPE_AUTOMATIC_TAX", "true"),
        ]);
        assert!(on.billing_enforced && on.stripe_automatic_tax);
        assert!(vars(&[("BILLING_ENFORCED", "yes")]).is_err());
        assert!(!c.stripe_configured() && !c.webhook_configured());
        let key = cfg(&[("STRIPE_SECRET_KEY", "sk_test_x")]);
        assert!(key.stripe_configured() && !key.webhook_configured());
        let both = cfg(&[
            ("STRIPE_SECRET_KEY", "sk_test_x"),
            ("STRIPE_WEBHOOK_SECRET", "whsec_x"),
        ]);
        assert!(both.webhook_configured());
    }

    #[test]
    fn config_refuses_fake_models_in_production() {
        let fake = production(&[("OPSAGENT_MODEL_PROVIDER", "fake")]);
        assert!(matches!(
            vars(&fake),
            Err(ConfigError::Invalid {
                name: "OPSAGENT_MODEL_PROVIDER",
                ..
            })
        ));
        let dev = cfg(&[("OPSAGENT_MODEL_PROVIDER", "fake")]);
        assert_eq!(dev.model_settings().mode, ModelMode::Fake);
        assert!(vars(&[("OPSAGENT_MODEL_PROVIDER", "bogus")]).is_err());
    }

    #[test]
    fn config_ai_defaults_dark() {
        for c in [cfg(&[]), cfg(&production(&[]))] {
            let m = c.model_settings();
            assert!(m.opsagent.is_none() && m.opsagent_backup.is_none() && !m.allow_private);
            assert_eq!(m.mode, ModelMode::Live);
            assert_eq!(m.anthropic_version, "2023-06-01");
            assert_eq!(m.anthropic_api_base, "https://api.anthropic.com");
            assert_eq!(m.openai_api_base, "https://api.openai.com/v1");
        }
        assert_eq!(
            (MODEL_ROUTINE, MODEL_CHAT),
            ("claude-haiku-5-5", "claude-sonnet-5-5")
        );
        let set = cfg(&[("ANTHROPIC_API_BASE", "http://127.0.0.1:1")]);
        assert_eq!(
            set.model_settings().anthropic_api_base,
            "http://127.0.0.1:1"
        );
    }

    fn ai_conn(pairs: &[(&str, &str)]) -> Option<OpsAgentConnection> {
        cfg(pairs).opsagent
    }

    fn assert_invalid_var(pairs: &[(&str, &str)], var: &str) {
        match vars(pairs) {
            Err(ConfigError::Invalid { name, .. }) => assert_eq!(name, var),
            Err(e) => panic!("{e}"),
            Ok(_) => panic!("{var} accepted"),
        }
    }

    #[test]
    fn opsagent_ai_env_defaults() {
        let c = cfg(&[("OPSAGENT_AI_API_KEY", "k")]);
        let p = c.opsagent.expect("primary");
        assert_eq!(
            (p.style, p.base_url, p.api_key.as_str()),
            (AiProvider::Anthropic, None, "k")
        );
        assert_eq!(
            (p.models.routine.as_str(), p.models.chat.as_str()),
            ("claude-haiku-5-5", "claude-sonnet-5-5")
        );
        assert!(c.opsagent_backup.is_none());
    }

    #[test]
    fn opsagent_ai_alias_used_when_empty() {
        // Railway today sets only this variable.
        let p = ai_conn(&[("OPSAGENT_ANTHROPIC_API_KEY", "k")]).expect("primary");
        assert_eq!(
            (p.style, p.base_url, p.api_key.as_str()),
            (AiProvider::Anthropic, None, "k")
        );
        assert_eq!(
            (p.models.routine.as_str(), p.models.chat.as_str()),
            (MODEL_ROUTINE, MODEL_CHAT)
        );
        let both = ai_conn(&[
            ("OPSAGENT_ANTHROPIC_API_KEY", "old"),
            ("OPSAGENT_AI_API_KEY", "new"),
        ]);
        assert_eq!(both.unwrap().api_key, "new");
        let empty = ai_conn(&[
            ("OPSAGENT_ANTHROPIC_API_KEY", "old"),
            ("OPSAGENT_AI_API_KEY", ""),
        ]);
        assert_eq!(empty.unwrap().api_key, "old");
    }

    #[test]
    fn opsagent_ai_backup_exists_only_with_key() {
        let none = cfg(&[
            ("OPSAGENT_AI_BACKUP_STYLE", "openai"),
            ("OPSAGENT_AI_BACKUP_CHAT_MODEL", "gpt-5"),
        ]);
        assert!(none.opsagent_backup.is_none());
        let c = cfg(&[
            ("OPSAGENT_AI_API_KEY", "p"),
            ("OPSAGENT_AI_BACKUP_API_KEY", "b"),
            ("OPSAGENT_AI_BACKUP_STYLE", "openai"),
        ]);
        let b = c.opsagent_backup.expect("backup");
        assert_eq!((b.style, b.api_key.as_str()), (AiProvider::OpenAi, "b"));
        assert_eq!(
            (b.models.routine.as_str(), b.models.chat.as_str()),
            ("gpt-5-mini", "gpt-5")
        );
        assert!(c.opsagent.is_some());
    }

    #[test]
    fn ai_limits_default_and_override() {
        assert_eq!(
            cfg(&[]).ai_limits,
            crate::adapters::model::ModelLimits::default()
        );
        let c = cfg(&[
            ("OPSAGENT_AI_MAX_RESPONSE_BYTES", "4194304"),
            ("OPSAGENT_AI_CALL_TIMEOUT_SECS", "240"),
            ("OPSAGENT_AI_STREAM_TIMEOUT_SECS", "600"),
        ]);
        let l = c.ai_limits;
        assert_eq!(
            (l.body_cap, l.call.as_secs(), l.stream.as_secs()),
            (4194304, 240, 600)
        );
        assert_invalid_var(
            &[("OPSAGENT_AI_CALL_TIMEOUT_SECS", "0")],
            "OPSAGENT_AI_CALL_TIMEOUT_SECS",
        );
        assert_invalid_var(
            &[("OPSAGENT_AI_STREAM_TIMEOUT_SECS", "x")],
            "OPSAGENT_AI_STREAM_TIMEOUT_SECS",
        );
    }

    #[test]
    fn opsagent_ai_backup_without_primary_becomes_primary() {
        let c = cfg(&[
            ("OPSAGENT_AI_BACKUP_API_KEY", "b"),
            ("OPSAGENT_AI_BACKUP_STYLE", "openai"),
        ]);
        let p = c.opsagent.expect("promoted");
        assert_eq!((p.style, p.api_key.as_str()), (AiProvider::OpenAi, "b"));
        assert!(c.opsagent_backup.is_none());
    }

    #[test]
    fn opsagent_ai_bad_style_fails_boot() {
        assert_invalid_var(
            &[
                ("OPSAGENT_AI_API_KEY", "k"),
                ("OPSAGENT_AI_STYLE", "gemini"),
            ],
            "OPSAGENT_AI_STYLE",
        );
        let b = [
            ("OPSAGENT_AI_BACKUP_API_KEY", "k"),
            ("OPSAGENT_AI_BACKUP_STYLE", "x"),
        ];
        assert_invalid_var(&b, "OPSAGENT_AI_BACKUP_STYLE");
    }

    #[test]
    fn opsagent_ai_unpriced_model_fails_boot() {
        let p = [
            ("OPSAGENT_AI_API_KEY", "k"),
            ("OPSAGENT_AI_CHAT_MODEL", "llama-3"),
        ];
        assert_invalid_var(&p, "OPSAGENT_AI_CHAT_MODEL");
        let b = [
            ("OPSAGENT_AI_BACKUP_API_KEY", "k"),
            ("OPSAGENT_AI_BACKUP_ROUTINE_MODEL", "llama-3"),
        ];
        assert_invalid_var(&b, "OPSAGENT_AI_BACKUP_ROUTINE_MODEL");
    }

    #[test]
    fn opsagent_ai_base_url_needs_https() {
        let http = [
            ("OPSAGENT_AI_API_KEY", "k"),
            ("OPSAGENT_AI_BASE_URL", "http://x.test"),
        ];
        assert_invalid_var(&http, "OPSAGENT_AI_BASE_URL");
        let b = [
            ("OPSAGENT_AI_BACKUP_API_KEY", "k"),
            ("OPSAGENT_AI_BACKUP_BASE_URL", "http://x.test"),
        ];
        assert_invalid_var(&b, "OPSAGENT_AI_BACKUP_BASE_URL");
        let ip = ai_conn(&[
            ("OPSAGENT_AI_API_KEY", "k"),
            ("OPSAGENT_AI_BASE_URL", "https://10.0.0.1/v1/"),
        ]);
        assert_eq!(ip.unwrap().base_url.as_deref(), Some("https://10.0.0.1/v1"));
    }

    #[test]
    fn allow_private_admits_http_and_is_refused_in_production() {
        let local = [
            ("OPSAGENT_AI_API_KEY", "k"),
            ("OPSAGENT_AI_BASE_URL", "http://127.0.0.1:9999"),
            ("AI_ENDPOINT_ALLOW_PRIVATE", "true"),
        ];
        let c = cfg(&local);
        assert!(c.model_settings().allow_private);
        assert_eq!(
            c.opsagent.unwrap().base_url.as_deref(),
            Some("http://127.0.0.1:9999")
        );
        assert_invalid_var(
            &production(&[("AI_ENDPOINT_ALLOW_PRIVATE", "true")]),
            "AI_ENDPOINT_ALLOW_PRIVATE",
        );
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
