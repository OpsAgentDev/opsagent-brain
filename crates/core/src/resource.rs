use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

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
