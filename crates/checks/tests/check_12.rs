mod common;
use common::*;
use opsagent_checks::check_12_hardening::InstanceHardening;
use opsagent_core::finding::Severity::*;
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use serde_json::json;

fn ec2(id: &str, tokens: serde_json::Value, endpoint: &str, ip: bool, state: &str) -> Resource {
    Resource {
        provider: Provider::Aws,
        account: "1".into(),
        region: "r".into(),
        kind: ResourceKind::Compute,
        identity: id.into(),
        name: id.into(),
        tags: Default::default(),
        attributes: json!({"service":"ec2","state":state,"metadata_http_tokens":tokens,
            "metadata_http_endpoint":endpoint,"has_public_ip":ip}),
        observed_at: "2026-10-01T00:00:00Z".parse().unwrap(),
    }
}

#[tokio::test]
async fn insecure_exact_set() {
    let (r, c) = load("insecure").await;
    assert_eq!(
        set(&run(&InstanceHardening, &r, &c)),
        vec![
            t("i-imds-open", "imdsv1_allowed", Medium),
            t("i-imds-public", "imdsv1_allowed", High),
        ]
    );
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, c) = load("clean").await;
    assert!(run(&InstanceHardening, &r, &c).is_empty());
}

#[test]
fn public_ip_raises_to_high_and_evidence_names_the_attributes() {
    let d = run(
        &InstanceHardening,
        &[ec2("a", json!("optional"), "enabled", true, "running")],
        &[],
    );
    assert_eq!(set(&d), vec![t("a", "imdsv1_allowed", High)]);
    assert_eq!(
        d[0].evidence[0].excerpt,
        "http_tokens=optional http_endpoint=enabled has_public_ip=true"
    );
    assert!(d[0].next_step.starts_with("Require IMDSv2"));
}

#[test]
fn required_tokens_or_disabled_endpoint_is_clean() {
    let rs = [
        ec2("a", json!("required"), "enabled", true, "running"),
        ec2("b", json!("optional"), "disabled", true, "running"),
    ];
    assert!(run(&InstanceHardening, &rs, &[]).is_empty());
}

#[test]
fn unknown_metadata_and_terminated_instances_are_skipped() {
    let rs = [
        ec2("a", json!(null), "enabled", true, "running"),
        ec2("b", json!("optional"), "enabled", true, "terminated"),
        ec2("c", json!("optional"), "enabled", true, "shutting-down"),
    ];
    assert!(run(&InstanceHardening, &rs, &[]).is_empty());
}

#[test]
fn stopped_instance_still_counts_and_no_instances_no_findings() {
    let d = run(
        &InstanceHardening,
        &[ec2("a", json!("optional"), "enabled", false, "stopped")],
        &[],
    );
    assert_eq!(set(&d), vec![t("a", "imdsv1_allowed", Medium)]);
    assert!(run(&InstanceHardening, &[], &[]).is_empty());
}
