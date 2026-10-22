use crate::{
    Capability, Connector, ConnectorError, CostRow, Credentials, InventoryResult, MetricPoint,
    MetricQuery, Result, Scope, VerifyOutcome,
};
use async_trait::async_trait;
use opsagent_core::resource::{Provider, Resource};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Deserialize)]
struct Fixture {
    resources: Vec<Resource>,
    cost_daily: Vec<CostRow>,
    #[serde(default)]
    metrics: BTreeMap<String, BTreeMap<String, Vec<MetricPoint>>>,
    verify: VerifyOutcome,
}

/// Fixture-backed connector. `Default` has no fixture and serves only as the
/// registry entry; it resolves the fixture from the credentials' account.
#[derive(Debug, Default)]
pub struct FakeConnector {
    fixture: Option<Fixture>,
    blocked: bool,
}

fn load(account: &str) -> Result<Fixture> {
    // Reject path separators so an account name cannot escape the fixtures dir.
    if account.is_empty()
        || !account
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ConnectorError::NotFound);
    }
    let path = format!(
        "{}/fixtures/accounts/{account}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(path).map_err(|_| ConnectorError::NotFound)?;
    serde_json::from_str(&raw).map_err(|e| ConnectorError::Fixture(e.to_string()))
}

impl FakeConnector {
    pub fn new(account: &str) -> Result<Self> {
        if account == "blocked" {
            return Ok(Self {
                fixture: None,
                blocked: true,
            });
        }
        Ok(Self {
            fixture: Some(load(account)?),
            blocked: false,
        })
    }

    fn fixture(&self, creds: &Credentials) -> Result<std::borrow::Cow<'_, Fixture>> {
        match (&self.fixture, creds) {
            (Some(f), _) => Ok(std::borrow::Cow::Borrowed(f)),
            (None, Credentials::Fake { account }) => Ok(std::borrow::Cow::Owned(load(account)?)),
            _ => Err(ConnectorError::NotFound),
        }
    }
}

#[async_trait]
impl Connector for FakeConnector {
    fn provider(&self) -> Provider {
        Provider::Fake
    }

    fn capabilities(&self) -> BTreeSet<Capability> {
        use Capability::*;
        [
            Inventory,
            CostDaily,
            Metrics,
            IamReport,
            PublicAccess,
            Backups,
            Certificates,
            Logging,
            Gpu,
        ]
        .into()
    }

    async fn verify(&self, creds: &Credentials) -> Result<VerifyOutcome> {
        let blocked =
            self.blocked || matches!(creds, Credentials::Fake { account } if account == "blocked");
        if blocked {
            return Ok(VerifyOutcome {
                assume_with_ok: true,
                assume_without_denied: true,
                account_matches: true,
                extra_grants: vec!["ec2:TerminateInstances".into()],
                missing_grants: vec![],
            });
        }
        Ok(self.fixture(creds)?.verify.clone())
    }

    async fn inventory(&self, creds: &Credentials, scope: &Scope) -> Result<InventoryResult> {
        let mut out = self.fixture(creds)?.resources.clone();
        out.retain(|r| {
            (scope.regions.is_empty() || scope.regions.contains(&r.region))
                && (scope.services.is_empty()
                    || r.attributes["service"]
                        .as_str()
                        .is_some_and(|s| scope.services.iter().any(|x| x == s)))
        });
        Ok(InventoryResult {
            resources: out,
            partial_errors: vec![],
        })
    }

    async fn cost_daily(&self, creds: &Credentials, days: u32) -> Result<Vec<CostRow>> {
        let rows = &self.fixture(creds)?.cost_daily;
        let skip = rows.len().saturating_sub(days as usize);
        Ok(rows[skip..].to_vec())
    }

    async fn metrics(&self, creds: &Credentials, q: MetricQuery) -> Result<Vec<MetricPoint>> {
        let f = self.fixture(creds)?;
        Ok(f.metrics
            .get(&q.resource_identity)
            .and_then(|m| m.get(&q.metric))
            .cloned()
            .unwrap_or_default())
    }
}
