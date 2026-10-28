use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};
use uuid::Uuid;

use crate::repo::{PageOf, PageRequest, RepoResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Aws,
    Gcp,
    Azure,
    Cloudflare,
    Fake,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Compute,
    Storage,
    Database,
    Identity,
    Network,
    Certificate,
    Log,
    Job,
    Deployment,
}

macro_rules! snake_display {
    ($t:ty { $($v:ident => $s:literal),* $(,)? }) => {
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self { $(Self::$v => $s),* })
            }
        }
    };
}

snake_display!(Provider { Aws => "aws", Gcp => "gcp", Azure => "azure", Cloudflare => "cloudflare", Fake => "fake" });
snake_display!(ResourceKind {
    Compute => "compute", Storage => "storage", Database => "database", Identity => "identity",
    Network => "network", Certificate => "certificate", Log => "log", Job => "job",
    Deployment => "deployment",
});

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub provider: Provider,
    pub account: String,
    pub region: String,
    pub kind: ResourceKind,
    pub identity: String,
    pub name: String,
    pub tags: BTreeMap<String, String>,
    pub attributes: serde_json::Value,
    pub observed_at: DateTime<Utc>,
}

impl Resource {
    /// The provider service the resource belongs to (`attributes.service`), or `""`.
    pub fn service(&self) -> &str {
        self.attributes["service"].as_str().unwrap_or("")
    }
}

/// Stable identity: the provider's own id when it has one, else `kind:region:name`.
pub fn resource_identity(
    provider_id: Option<&str>,
    kind: ResourceKind,
    name: &str,
    region: &str,
) -> String {
    provider_id.map_or_else(|| format!("{kind}:{region}:{name}"), str::to_owned)
}

/// A stored resource (inventory row). Provider, account and attributes are not part of the row.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceRow {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub kind: ResourceKind,
    pub identity: String,
    pub name: Option<String>,
    pub region: Option<String>,
    pub tags: BTreeMap<String, String>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// Set when the resource was missing from a complete inventory.
    pub gone_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceFilter {
    pub connection_id: Option<Uuid>,
    pub kind: Option<ResourceKind>,
    /// Case-insensitive substring of name or identity; LIKE wildcards match literally.
    pub q: Option<String>,
}

#[async_trait]
pub trait ResourcesRepo: Send + Sync {
    async fn list(
        &self,
        organisation_id: Uuid,
        filter: ResourceFilter,
        page: PageRequest,
    ) -> RepoResult<PageOf<ResourceRow>>;
    /// Upsert one inventory chunk and its history rows (one per resource per run); true when
    /// a resource is new, came back, or changed kind, name, region, tags or attributes.
    async fn upsert_chunk(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        resources: &[Resource],
        now: DateTime<Utc>,
    ) -> RepoResult<bool>;
    /// Marks the connection's resources without a history row for `run_id` gone at `now`
    /// (after a complete inventory); returns how many.
    async fn mark_unseen_gone(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<u64>;
    /// The resources observed in `run_id` as the checks see them (attributes as of the run),
    /// ordered by identity. Provider and account are not stored per row; the caller names them.
    async fn observed(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        provider: Provider,
        account: &str,
    ) -> RepoResult<Vec<Resource>>;
    /// Deletes the connection's history rows of `run_id` (a watch scan keeps none); returns how many.
    async fn forget_run(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
    ) -> RepoResult<u64>;
    /// Replaces the run's inventory call counts recorded for the chunk `service@region` with
    /// `calls` (a re-run chunk restates its counts). tenancy: call stats belong to the run.
    async fn replace_inventory_calls(
        &self,
        run_id: Uuid,
        provider: &str,
        service: &str,
        region: &str,
        calls: &[CallCount],
    ) -> RepoResult<()>;
}

/// Inventory calls of one chunk by service, region and outcome (`ok` or `error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallCount {
    pub service: String,
    pub region: String,
    pub outcome: &'static str,
    pub count: i64,
}
