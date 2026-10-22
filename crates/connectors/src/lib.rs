use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use opsagent_core::resource::{Provider, Resource};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub mod aws;
pub mod fake;
pub mod registry;

pub use registry::Registry;

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("unknown connector: {0}")]
    Unknown(String),
    #[error("account not found")]
    NotFound,
    #[error("fixture error: {0}")]
    Fixture(String),
    #[error("invalid credentials: {0}")]
    InvalidCredentials(String),
    #[error("provider error: {0}")]
    Provider(String),
    /// A provider API error, with the provider's error code when it sent one.
    #[error("{message}")]
    Api {
        code: Option<String>,
        message: String,
    },
    /// The customer session itself is unusable (expired, invalid, or denied everywhere).
    #[error("auth error: {0}")]
    Auth(String),
    #[error("template error: {0}")]
    Template(String),
}
pub type Result<T> = std::result::Result<T, ConnectorError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Inventory,
    CostDaily,
    Metrics,
    IamReport,
    PublicAccess,
    Backups,
    Certificates,
    Logging,
    Gpu,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyOutcome {
    pub assume_with_ok: bool,
    pub assume_without_denied: bool,
    pub account_matches: bool,
    pub extra_grants: Vec<String>,
    pub missing_grants: Vec<String>,
}

/// Who a provider call is made for. AWS puts it in the session name and session tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallContext {
    pub organisation_id: Uuid,
    pub run_id: Uuid,
    pub trigger: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerraformState {
    pub bucket: String,
    pub prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credentials {
    AwsRole {
        role_arn: String,
        external_id: String,
        /// `TerraformStateBucket` / `TerraformStatePrefix` the stack was launched with.
        terraform_state: Option<TerraformState>,
        context: CallContext,
    },
    Fake {
        account: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostRow {
    pub date: NaiveDate,
    pub service: String,
    pub amount_usd: f64,
}

/// Empty vectors mean "all".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    pub regions: Vec<String>,
    pub services: Vec<String>,
}

/// A service call that failed during inventory; the rest of the inventory still returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceError {
    pub service: String,
    pub region: String,
    pub code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct InventoryResult {
    pub resources: Vec<Resource>,
    pub partial_errors: Vec<ServiceError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricQuery {
    pub resource_identity: String,
    pub metric: String,
    pub hours: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricPoint {
    pub at: DateTime<Utc>,
    pub value: f64,
}

#[async_trait]
pub trait Connector: Send + Sync {
    fn provider(&self) -> Provider;
    fn capabilities(&self) -> BTreeSet<Capability>;
    async fn verify(&self, creds: &Credentials) -> Result<VerifyOutcome>;
    async fn inventory(&self, creds: &Credentials, scope: &Scope) -> Result<InventoryResult>;
    async fn cost_daily(&self, creds: &Credentials, days: u32) -> Result<Vec<CostRow>>;
    async fn metrics(&self, creds: &Credentials, q: MetricQuery) -> Result<Vec<MetricPoint>>;
}
