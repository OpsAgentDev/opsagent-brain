//! `Config` defaults equal what `config/{test,development}.yaml` render to with an empty
//! environment (values hand-listed from the yaml). Deleted with the yaml files (Task 19).
use opsagent_brain::config::{AppEnv, Config, LogFormat};

fn defaults(env: Option<&str>) -> Config {
    let env = env.map(str::to_owned);
    Config::from_vars(|k| if k == "APP_ENV" { env.clone() } else { None })
        .unwrap_or_else(|e| panic!("{e}"))
}

/// The yaml values: `server`, `logger`, `database`, `queue.uri` and `settings`.
fn assert_yaml(c: &Config, format: LogFormat, db: &str, session: &str, cookie_secure: bool) {
    assert_eq!((c.port, c.binding.as_str()), (5150, "localhost"));
    assert_eq!((c.log_level.as_str(), c.log_format), ("debug", format));
    assert_eq!(c.database_url, db);
    assert!(!c.db_logging);
    assert_eq!((c.db_connect_timeout_ms, c.db_idle_timeout_ms), (500, 500));
    assert_eq!((c.db_min_connections, c.db_max_connections), (1, 1));
    assert!(c.db_auto_migrate);
    assert_eq!(c.redis_url, "redis://localhost:6379");
    assert_eq!(c.web_base_url, "http://localhost:3000");
    assert_eq!(c.api_base_url, "http://localhost:5150");
    assert_eq!(c.session_secret, session);
    assert_eq!(c.unsubscribe_secret, "");
    assert_eq!(c.cookie_secure, cookie_secure);
    assert_eq!(c.cookie_domain, "");
    assert_eq!(
        (c.github_client_id.as_str(), c.github_client_secret.as_str()),
        ("", "")
    );
    assert_eq!(
        (c.slack_client_id.as_str(), c.slack_client_secret.as_str()),
        ("", "")
    );
    assert_eq!(c.slack_api_base_url, "https://slack.com/api");
}

#[test]
fn test_env_defaults_match_test_yaml() {
    let c = defaults(Some("test"));
    assert_eq!(c.env, AppEnv::Test);
    assert_yaml(
        &c,
        LogFormat::Compact,
        "postgres://loco:loco@localhost:5432/opsagent_brain_test",
        "test-session-secret-not-for-prod",
        true,
    );
}

#[test]
fn development_defaults_match_development_yaml() {
    let c = defaults(None);
    assert_eq!(c.env, AppEnv::Development);
    assert_yaml(
        &c,
        LogFormat::Pretty,
        "postgres://loco:loco@localhost:5432/opsagent_brain_development",
        "dev-session-secret-change-me",
        false,
    );
}
