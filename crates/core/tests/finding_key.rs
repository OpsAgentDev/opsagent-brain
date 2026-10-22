use opsagent_core::resource::{resource_identity, ResourceKind};

#[test]
fn identity_falls_back_to_kind_region_name() {
    assert_eq!(
        resource_identity(None, ResourceKind::Compute, "web-1", "us-east-1"),
        "compute:us-east-1:web-1"
    );
}

#[test]
fn identity_prefers_provider_id() {
    let arn = "arn:aws:ec2:us-east-1:123:instance/i-1";
    assert_eq!(
        resource_identity(Some(arn), ResourceKind::Compute, "web-1", "us-east-1"),
        arn
    );
}
