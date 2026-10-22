//! Live run against a sandbox account with the v1 stack deployed. Ignored by default:
//! `OPSAGENT_SANDBOX_ROLE_ARN=... OPSAGENT_SANDBOX_EXTERNAL_ID=... \
//!  cargo test -p opsagent-connectors --test aws_sandbox -- --ignored`
//! Outbound credentials come from the default AWS provider chain.

use opsagent_connectors::{
    aws::{AwsConnector, AwsOutbound},
    CallContext, Connector, Credentials, Scope, TerraformState,
};
use uuid::Uuid;

fn creds() -> Option<Credentials> {
    Some(Credentials::AwsRole {
        role_arn: std::env::var("OPSAGENT_SANDBOX_ROLE_ARN").ok()?,
        external_id: std::env::var("OPSAGENT_SANDBOX_EXTERNAL_ID").ok()?,
        terraform_state: std::env::var("OPSAGENT_SANDBOX_TF_BUCKET")
            .ok()
            .zip(std::env::var("OPSAGENT_SANDBOX_TF_PREFIX").ok())
            .map(|(bucket, prefix)| TerraformState { bucket, prefix }),
        context: CallContext {
            organisation_id: Uuid::now_v7(),
            run_id: Uuid::now_v7(),
            trigger: "sandbox-test".into(),
        },
    })
}

#[tokio::test]
#[ignore]
#[allow(clippy::print_stderr)] // test-only skip notice
async fn sandbox_verify_inventory_cost() {
    let Some(creds) = creds() else {
        eprintln!("OPSAGENT_SANDBOX_ROLE_ARN / OPSAGENT_SANDBOX_EXTERNAL_ID not set; skipping");
        return;
    };
    let c = AwsConnector::new(AwsOutbound::default());
    let v = c.verify(&creds).await.unwrap();
    assert!(v.assume_with_ok, "{v:?}");
    assert!(v.assume_without_denied, "{v:?}");
    assert!(v.account_matches, "{v:?}");
    assert!(v.extra_grants.is_empty(), "{v:?}");
    assert!(v.missing_grants.is_empty(), "{v:?}");

    let inv = c
        .inventory(
            &creds,
            &Scope {
                regions: vec!["us-east-1".into()],
                services: vec![],
            },
        )
        .await
        .unwrap();
    assert!(inv.partial_errors.is_empty(), "{:?}", inv.partial_errors);

    c.cost_daily(&creds, 3).await.unwrap();
}
