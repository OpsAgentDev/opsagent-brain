mod common;
use common::*;
use opsagent_checks::check_14_trust_policies::TrustPolicies;
use opsagent_core::finding::Severity::*;
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use serde_json::{json, Value};

fn role(arn: &str, trust: Value) -> Resource {
    Resource {
        provider: Provider::Aws,
        account: "123456789012".into(),
        region: "global".into(),
        kind: ResourceKind::Identity,
        identity: arn.into(),
        name: arn.rsplit('/').next().unwrap().into(),
        tags: Default::default(),
        attributes: json!({"service":"iam_role","path":"/","trust_policy":trust}),
        observed_at: "2026-10-01T00:00:00Z".parse().unwrap(),
    }
}

fn arn(name: &str) -> String {
    format!("arn:aws:iam::123456789012:role/{name}")
}

fn allow(principal: Value) -> Value {
    json!({"Effect":"Allow","Principal":principal,"Action":"sts:AssumeRole"})
}

fn policy(statements: Vec<Value>) -> Value {
    json!({"Version":"2012-10-17","Statement":statements})
}

#[tokio::test]
async fn insecure_exact_set() {
    let (r, c) = load("insecure").await;
    assert_eq!(
        set(&run(&TrustPolicies, &r, &c)),
        vec![
            t(&arn("legacy-open"), "any_principal", Critical),
            t(
                &arn("open-with-condition"),
                "any_principal_conditional",
                Medium
            ),
            t(
                &arn("vendor-monitoring"),
                "foreign_account_no_external_id",
                Medium
            ),
        ]
    );
}

#[tokio::test]
async fn clean_and_noisy_are_empty() {
    for account in ["clean", "noisy"] {
        let (r, c) = load(account).await;
        assert!(run(&TrustPolicies, &r, &c).is_empty(), "{account}");
    }
}

/// Contract with opsagent-web's free trust policy tool (tests/fixtures/trust-policy-cases.json there
/// is the same file): both must give the same severities for the same cases.
#[test]
fn cases_match_the_web_tool_fixture() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/trust-policy-cases.json")).unwrap();
    assert!(cases.len() > 20);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let r = role(
            case["role_arn"].as_str().unwrap(),
            case["trust_policy"].clone(),
        );
        let mut got: Vec<(String, String)> = run(&TrustPolicies, &[r], &[])
            .iter()
            .map(|d| {
                let sev = serde_json::to_value(d.severity).unwrap();
                (d.key.variant.clone(), sev.as_str().unwrap().to_owned())
            })
            .collect();
        let mut want: Vec<(String, String)> = case["expect"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["variant"].as_str().unwrap().to_owned(),
                    e["severity"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        got.sort();
        want.sort();
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn two_statements_of_one_kind_are_one_finding_naming_every_account() {
    let doc = policy(vec![
        allow(json!({"AWS":"444455556666"})),
        allow(json!({"AWS":["arn:aws:iam::777788889999:root","444455556666"]})),
    ]);
    let d = run(&TrustPolicies, &[role(&arn("v"), doc)], &[]);
    assert_eq!(
        set(&d),
        vec![t(&arn("v"), "foreign_account_no_external_id", Medium)]
    );
    assert!(d[0].title.contains("444455556666, 777788889999"));
    assert_eq!(
        d[0].evidence[0].excerpt,
        "principal_accounts=444455556666, 777788889999"
    );
}

#[test]
fn evidence_never_holds_the_trust_policy() {
    let doc = policy(vec![allow(json!({"AWS":"*"}))]);
    let d = run(&TrustPolicies, &[role(&arn("o"), doc)], &[]);
    assert_eq!(d[0].evidence[0].excerpt, "principal=*");
    assert!(!d[0].summary.contains("Statement"));
}

#[test]
fn a_role_without_a_readable_trust_policy_is_not_judged() {
    let mut r = role(&arn("odd"), json!(null));
    assert!(run(&TrustPolicies, &[r.clone()], &[]).is_empty());
    r.attributes = json!({"service":"iam_role"});
    assert!(run(&TrustPolicies, &[r], &[]).is_empty());
}

#[test]
fn other_resources_are_ignored() {
    let mut r = role(&arn("x"), policy(vec![allow(json!({"AWS":"*"}))]));
    r.attributes["service"] = json!("iam");
    assert!(run(&TrustPolicies, &[r], &[]).is_empty());
}

#[test]
fn an_unavailable_roles_read_is_silent() {
    let rs = [role(&arn("o"), policy(vec![allow(json!({"AWS":"*"}))]))];
    assert_eq!(run(&TrustPolicies, &rs, &[]).len(), 1);
    let mut parts = CtxParts::default();
    parts.unavailable.insert("iam_role".into());
    assert!(run_with(&parts, &TrustPolicies, &rs, &[]).is_empty());
}

#[test]
fn a_finding_never_quotes_a_condition_value() {
    let secret = "ext-9f3a7c1e5b2d4a60";
    let cond = json!({"Null": {"sts:ExternalId": secret}});
    let mut st = allow(json!({"AWS":"444455556666"}));
    st["Condition"] = cond;
    let d = run(&TrustPolicies, &[role(&arn("v"), policy(vec![st]))], &[]);
    assert_eq!(d.len(), 1);
    let all = serde_json::to_string(&d).unwrap();
    assert!(!all.contains(secret), "{all}");
}
