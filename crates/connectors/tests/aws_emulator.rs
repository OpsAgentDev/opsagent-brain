//! Run against a local AWS Emulator (https://github.com/aws/aws-emulator) with the v1 stack
//! deployed in it. Ignored by default; `scripts/aws-emulator-test.sh` starts the emulator, deploys
//! the template, seeds a bucket and runs these in order. No AWS account is needed.
//!
//! The emulator is not AWS: it enforces the role's trust and policies well enough for these
//! tests, but a pass here does not replace `aws_sandbox` before a template change ships.

use opsagent_connectors::{
    aws::{AwsConnector, AwsOutbound},
    CallContext, Connector, Credentials, Scope,
};
use uuid::Uuid;

fn var(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is not set; run scripts/aws-emulator-test.sh"))
}

fn creds() -> Credentials {
    Credentials::AwsRole {
        role_arn: var("OPSAGENT_EMULATOR_ROLE_ARN"),
        external_id: var("OPSAGENT_EMULATOR_EXTERNAL_ID"),
        terraform_state: None,
        context: CallContext {
            organisation_id: Uuid::now_v7(),
            run_id: Uuid::now_v7(),
            trigger: "emulator-test".into(),
        },
    }
}

/// The deployed template passes verification, and the inventory reads the seeded bucket.
#[tokio::test]
#[ignore]
#[allow(clippy::print_stderr)] // test-only notice of emulator gaps
async fn emulator_verify_and_inventory() {
    let c = AwsConnector::new(AwsOutbound::default());
    let v = c.verify(&creds()).await.unwrap();
    assert!(v.assume_with_ok, "{v:?}");
    assert!(v.assume_without_denied, "{v:?}");
    assert!(v.account_matches, "{v:?}");
    assert!(v.extra_grants.is_empty(), "{v:?}");
    assert!(v.missing_grants.is_empty(), "{v:?}");

    let scope = Scope {
        regions: vec!["us-east-1".into()],
        services: vec![],
    };
    let inv = c.inventory(&creds(), &scope).await.unwrap();
    // Operations the emulator has not built yet answer 501; anything else is ours to fix.
    for e in &inv.partial_errors {
        assert_eq!(e.code.as_deref(), Some("NotImplemented"), "{e:?}");
        eprintln!("emulator gap, not checked: {} in {}", e.service, e.region);
    }
    let bucket = var("OPSAGENT_EMULATOR_BUCKET");
    let seen = inv.resources.iter().find(|r| r.name == bucket);
    let seen = seen.unwrap_or_else(|| panic!("bucket {bucket} not in the inventory"));
    assert_eq!(seen.attributes["service"], "s3");
    assert_eq!(seen.attributes["block_public_access"], false, "{seen:?}");
}

/// With the stack deleted the role is gone: verification reports lost access, not an error.
/// This is the answer that, repeated, revokes a connection (PRD 7.2).
#[tokio::test]
#[ignore]
async fn emulator_deleted_stack_is_lost_access() {
    let c = AwsConnector::new(AwsOutbound::default());
    let v = c.verify(&creds()).await.unwrap();
    assert!(!v.assume_with_ok, "{v:?}");
}
