//! The one place that maps a `connections.provider` value to its connector, its credentials
//! and its onboarding facts. Adding a provider means adding it here, nowhere else.
use crate::aws::{client::parse_role_arn, AwsConnector, AwsOutbound};
use crate::fake::FakeConnector;
use crate::{CallContext, Connector, ConnectorError, Credentials, Result};
use serde::{Deserialize, Serialize};

/// Plaintext of a connection's sealed credential record. Never serialised into an API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Creds {
    pub external_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,
    /// Fixture account for the `fake` provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fake_account: Option<String>,
}

/// What creating a connection for a provider involves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderSpec {
    /// `connection_credentials.kind`.
    pub credential_kind: &'static str,
    /// The customer deploys the read-role template (quick-create link, template version).
    pub uses_template: bool,
}

/// Connectors keyed by provider, built from the outbound identity. `fake_only` (tests and local
/// runs) serves every provider with the fixture connector and admits the `fake` provider.
#[derive(Debug, Clone)]
pub struct Registry {
    outbound: AwsOutbound,
    fake_only: bool,
}

impl Registry {
    pub fn new(outbound: AwsOutbound, fake_only: bool) -> Self {
        Self {
            outbound,
            fake_only,
        }
    }

    /// Onboarding facts; `Unknown` for providers that do not exist or are not allowed here.
    pub fn spec(&self, provider: &str) -> Result<ProviderSpec> {
        match provider {
            "aws" => Ok(ProviderSpec {
                credential_kind: "aws_role",
                uses_template: true,
            }),
            "fake" if self.fake_only => Ok(ProviderSpec {
                credential_kind: "fake",
                uses_template: false,
            }),
            other => Err(ConnectorError::Unknown(other.to_owned())),
        }
    }

    pub fn connector(&self, provider: &str) -> Result<Box<dyn Connector>> {
        self.spec(provider)?;
        if self.fake_only {
            return Ok(Box::new(FakeConnector::default()));
        }
        match provider {
            "aws" => Ok(Box::new(AwsConnector::new(self.outbound.clone()))),
            other => Err(ConnectorError::Unknown(other.to_owned())),
        }
    }
}

/// Fresh credentials for a new connection: a random ExternalId, and for `fake` the fixture
/// account named by the display name.
pub fn new_creds(provider: &str, external_id: String, display_name: &str) -> Creds {
    Creds {
        external_id,
        role_arn: None,
        fake_account: (provider == "fake").then(|| display_name.to_owned()),
    }
}

/// The role the customer reported after deploying the template: `Ok(None)` for providers
/// without one. Errors name the problem, never echo the input.
pub fn reported_role(provider: &str, raw: &str) -> Result<Option<String>> {
    if provider != "aws" {
        return Ok(None);
    }
    let arn = raw.trim();
    let parsed = parse_role_arn(arn).map_err(|_| {
        ConnectorError::InvalidCredentials("role_arn must be an IAM role ARN".into())
    })?;
    if parsed.partition != "aws" {
        return Err(ConnectorError::InvalidCredentials(format!(
            "the {} partition is not supported",
            parsed.partition
        )));
    }
    Ok(Some(arn.to_owned()))
}

/// Call credentials for a stored record.
pub fn credentials(provider: &str, creds: &Creds, context: CallContext) -> Result<Credentials> {
    match provider {
        "fake" => Ok(Credentials::Fake {
            account: creds.fake_account.clone().unwrap_or_default(),
        }),
        "aws" => Ok(Credentials::AwsRole {
            role_arn: creds
                .role_arn
                .clone()
                .ok_or_else(|| ConnectorError::InvalidCredentials("no role ARN".into()))?,
            external_id: creds.external_id.clone(),
            terraform_state: None,
            context,
        }),
        other => Err(ConnectorError::Unknown(other.to_owned())),
    }
}

impl Credentials {
    /// The cloud account these credentials reach.
    pub fn account(&self) -> Option<String> {
        match self {
            Self::AwsRole { role_arn, .. } => parse_role_arn(role_arn).ok().map(|a| a.account),
            Self::Fake { account } => Some(account.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn ctx() -> CallContext {
        CallContext {
            organisation_id: Uuid::nil(),
            run_id: Uuid::nil(),
            trigger: "t".into(),
        }
    }

    #[test]
    fn fake_is_admitted_only_in_fake_mode() {
        let real = Registry::new(AwsOutbound::default(), false);
        assert!(real.spec("fake").is_err());
        assert!(real.connector("fake").is_err());
        assert!(real.spec("gcp").is_err());
        assert!(real.spec("aws").unwrap().uses_template);
        let fake = Registry::new(AwsOutbound::default(), true);
        assert_eq!(fake.spec("fake").unwrap().credential_kind, "fake");
        assert_eq!(
            fake.connector("aws").unwrap().provider(),
            opsagent_core::resource::Provider::Fake
        );
    }

    #[test]
    fn reported_role_checks_arn_and_partition() {
        let ok = "arn:aws:iam::123456789012:role/R";
        assert_eq!(
            reported_role("aws", &format!(" {ok} ")).unwrap().as_deref(),
            Some(ok)
        );
        let bad = reported_role("aws", "nope").unwrap_err().to_string();
        assert!(!bad.contains("nope"), "{bad}");
        assert!(reported_role("aws", "arn:aws-cn:iam::123456789012:role/R")
            .unwrap_err()
            .to_string()
            .contains("aws-cn"));
        assert_eq!(reported_role("fake", "anything").unwrap(), None);
    }

    #[test]
    fn credentials_and_account() {
        let c = Creds {
            external_id: "e".into(),
            role_arn: Some("arn:aws:iam::123456789012:role/R".into()),
            fake_account: None,
        };
        let aws = credentials("aws", &c, ctx()).unwrap();
        assert_eq!(aws.account().as_deref(), Some("123456789012"));
        let f = credentials("fake", &new_creds("fake", "e".into(), "clean"), ctx()).unwrap();
        assert_eq!(f.account().as_deref(), Some("clean"));
        assert!(credentials("aws", &new_creds("aws", "e".into(), "x"), ctx()).is_err());
    }
}
