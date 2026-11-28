//! Template version 4 read: every role's trust policy, for check 14.

use aws_sdk_iam::operation::list_roles::ListRolesOutput;
use aws_sdk_iam::types::Role;
use aws_smithy_http_client::test_util::infallible_client_fn;
use aws_smithy_mocks::{mock, mock_client, RuleMode};
use opsagent_connectors::aws::inventory::{iam_roles, inventory, Target};
use opsagent_connectors::{ConnectorError, Scope};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const T: Target = Target {
    partition: "aws",
    account: "123456789012",
    region: "global",
};

const OPEN: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}"#;

fn role(name: &str, path: &str, doc: &str) -> Role {
    Role::builder()
        .path(path)
        .role_name(name)
        .role_id("AROA")
        .arn(format!("arn:aws:iam::123456789012:role{path}{name}"))
        .create_date(aws_smithy_types::DateTime::from_secs(0))
        .assume_role_policy_document(urlencoding::encode(doc).into_owned())
        .build()
        .unwrap()
}

fn page(roles: Vec<Role>, marker: Option<&'static str>) -> impl Fn() -> ListRolesOutput {
    move || {
        ListRolesOutput::builder()
            .set_roles(Some(roles.clone()))
            .is_truncated(marker.is_some())
            .set_marker(marker.map(String::from))
            .build()
            .unwrap()
    }
}

/// A document `decode_doc` cannot read: the URL-decoded text is not JSON.
fn broken_role(name: &str) -> Role {
    Role::builder()
        .path("/")
        .role_name(name)
        .role_id("AROA")
        .arn(format!("arn:aws:iam::123456789012:role/{name}"))
        .create_date(aws_smithy_types::DateTime::from_secs(0))
        .assume_role_policy_document("%7Bnot-json")
        .build()
        .unwrap()
}

/// One page, or two when `second` is given (the first points at it with a marker).
fn list(first: Vec<Role>, second: Option<Vec<Role>>) -> aws_sdk_iam::Client {
    let one = mock!(aws_sdk_iam::Client::list_roles)
        .then_output(page(first, second.is_some().then_some("m1")));
    let Some(second) = second else {
        return mock_client!(aws_sdk_iam, RuleMode::Sequential, [&one]);
    };
    let two = mock!(aws_sdk_iam::Client::list_roles)
        .match_requests(|r| r.marker() == Some("m1"))
        .then_output(page(second, None));
    mock_client!(aws_sdk_iam, RuleMode::Sequential, [&one, &two])
}

#[tokio::test]
async fn roles_are_paged_and_decoded_and_none_is_skipped_by_its_name() {
    let iam = list(
        vec![
            role("legacy-open", "/", OPEN),
            role("lookalike", "/aws-service-role/x.amazonaws.com/", OPEN),
        ],
        Some(vec![
            role("OpsAgentReadRole-lookalike", "/", OPEN),
            role("deploy", "/ci/", OPEN),
        ]),
    );
    let r = iam_roles(&iam, &T).await.unwrap();
    let names: Vec<_> = r.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "legacy-open",
            "lookalike",
            "OpsAgentReadRole-lookalike",
            "deploy"
        ]
    );
    assert_eq!(r[3].identity, "arn:aws:iam::123456789012:role/ci/deploy");
    assert_eq!(r[3].attributes["path"], "/ci/");
    assert_eq!(r[0].attributes["service"], "iam_role");
    // Only the parts a check reads are kept: no Version, no Sid.
    assert_eq!(
        r[0].attributes["trust_policy"],
        json!({"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}}]})
    );
}

/// A real-looking ExternalId, as in OpsAgent's own role.
const SECRET: &str = "ext-9f3a7c1e5b2d4a60";

fn trust_with(condition: serde_json::Value) -> String {
    json!({"Version": "2012-10-17", "Statement": [{
        "Sid": "S1", "Effect": "Allow", "Action": "sts:AssumeRole",
        "NotAction": "s3:GetObject",
        "Principal": {"AWS": "arn:aws:iam::999999999999:role/opsagent-outbound"},
        "Resource": "*", "Condition": condition
    }]})
    .to_string()
}

#[tokio::test]
async fn an_external_id_is_never_stored_but_wildcards_and_empties_stay() {
    let secret_doc = trust_with(json!({
        "StringEquals": {"sts:ExternalId": SECRET, "aws:PrincipalOrgID": "o-1"},
        "ForAnyValue:StringLike": {"STS:EXTERNALID": [SECRET, "*", ""]},
        "StringNotEquals": {"sts:ExternalId": SECRET},
        "StringLike": {"sts:ExternalId": "*"},
        "StringEqualsIgnoreCase": {"sts:ExternalId": ["ext-9f3a7c*", "ext-9?3a"]},
        "Null": {"sts:ExternalId": "false"},
    }));
    let iam = list(
        vec![role("OpsAgentReadRole-abcd1234", "/", &secret_doc)],
        None,
    );
    let r = iam_roles(&iam, &T).await.unwrap();
    let stored = serde_json::to_string(&r).unwrap();
    assert!(!stored.contains(SECRET), "{stored}");
    // A wildcard value keeps no literal part either.
    assert!(
        !stored.contains("9f3a7c") && !stored.contains("ext-9"),
        "{stored}"
    );
    let c = &r[0].attributes["trust_policy"]["Statement"][0]["Condition"];
    assert_eq!(c["StringEquals"]["sts:ExternalId"], "[redacted]");
    assert_eq!(c["StringEquals"]["aws:PrincipalOrgID"], "o-1");
    assert_eq!(
        c["ForAnyValue:StringLike"]["STS:EXTERNALID"],
        json!(["[redacted]", "*", ""])
    );
    assert_eq!(c["StringNotEquals"]["sts:ExternalId"], "[redacted]");
    assert_eq!(c["StringLike"]["sts:ExternalId"], "*");
    assert_eq!(
        c["StringEqualsIgnoreCase"]["sts:ExternalId"],
        json!(["*", "*"])
    );
    // Any operator: even one that never counts as an external id is redacted.
    assert_eq!(c["Null"]["sts:ExternalId"], "[redacted]");
    let st = &r[0].attributes["trust_policy"]["Statement"][0];
    assert!(st.get("Sid").is_none() && st.get("Resource").is_none());
    assert_eq!(st["NotAction"], "s3:GetObject");
}

/// One broken document must not fail the whole read: that role is kept with no policy.
#[tokio::test]
async fn an_undecodable_trust_policy_is_stored_as_null_and_the_rest_are_read() {
    let iam = list(
        vec![broken_role("broken"), role("legacy-open", "/", OPEN)],
        None,
    );
    let r = iam_roles(&iam, &T).await.unwrap();
    assert_eq!(r.len(), 2);
    assert!(r[0].attributes["trust_policy"].is_null());
    assert_eq!(r[0].name, "broken");
    assert!(r[1].attributes["trust_policy"]["Statement"].is_array());
}

/// IAM answers `code` (None: an empty success) and counts its requests; EC2 answers an empty
/// snapshot list, the other service in `scope()` that keeps the whole call from being denied.
fn session(calls: &Arc<AtomicUsize>, code: Option<&'static str>) -> aws_config::SdkConfig {
    let calls = calls.clone();
    let http = infallible_client_fn(move |req| {
        let r = http::Response::builder();
        if !req.uri().host().unwrap_or_default().starts_with("iam.") {
            return r.status(200).body("<DescribeSnapshotsResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><requestId>r</requestId><snapshotSet/></DescribeSnapshotsResponse>".to_owned()).unwrap();
        }
        calls.fetch_add(1, Ordering::SeqCst);
        match code {
            Some(c) => r.status(403).body(format!("<ErrorResponse><Error><Type>Sender</Type><Code>{c}</Code><Message>no</Message></Error><RequestId>r</RequestId></ErrorResponse>")),
            None => r.status(200).body("<ListRolesResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><ListRolesResult><IsTruncated>false</IsTruncated><Roles/></ListRolesResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListRolesResponse>".to_owned()),
        }
        .unwrap()
    });
    aws_config::SdkConfig::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::from_static("eu-west-1"))
        .credentials_provider(aws_sdk_sts::config::SharedCredentialsProvider::new(
            aws_sdk_sts::config::Credentials::new("AKID", "secret", None, None, "test"),
        ))
        .retry_config(aws_config::retry::RetryConfig::disabled())
        .http_client(http)
        .build()
}

fn scope() -> Scope {
    Scope {
        regions: vec!["eu-west-1".into()],
        services: vec!["iam_role".into(), "ebs_snapshot".into()],
    }
}

/// A role that cannot list roles (a version 4 stack that was changed): that service is partial
/// with its code, and nothing else fails, so the check stays silent without touching the score.
#[tokio::test]
async fn a_denied_roles_read_is_partial_for_that_service_only() {
    let calls = Arc::new(AtomicUsize::new(0));
    let r = inventory(
        &session(&calls, Some("AccessDenied")),
        "aws",
        "123456789012",
        &scope(),
        false,
        true,
    )
    .await
    .expect("a denied optional read is partial, not a failed connection");
    let got: Vec<_> = r
        .partial_errors
        .iter()
        .map(|e| (e.service.as_str(), e.code.as_deref().unwrap_or_default()))
        .collect();
    assert_eq!(got, [("iam_role", "AccessDenied")]);
    assert!(r.resources.is_empty());
}

/// A connection whose role is not known to hold the read makes no call at all.
#[tokio::test]
async fn roles_off_makes_no_call_and_no_partial_error() {
    let calls = Arc::new(AtomicUsize::new(0));
    let r = inventory(
        &session(&calls, Some("AccessDenied")),
        "aws",
        "123456789012",
        &scope(),
        false,
        false,
    )
    .await
    .unwrap();
    assert!(r.partial_errors.is_empty(), "{:?}", r.partial_errors);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // The scan is told the read was wanted but not made, so findings from an earlier read stay.
    assert_eq!(r.skipped, ["iam_role"]);
    // Not wanted (a watch scan), or made: nothing skipped.
    let ebs_only = Scope {
        regions: vec!["eu-west-1".into()],
        services: vec!["ebs_snapshot".into()],
    };
    let r = inventory(
        &session(&calls, None),
        "aws",
        "123456789012",
        &ebs_only,
        false,
        false,
    )
    .await
    .unwrap();
    assert!(r.skipped.is_empty());
    let r = inventory(
        &session(&calls, None),
        "aws",
        "123456789012",
        &scope(),
        false,
        true,
    )
    .await
    .unwrap();
    assert!(r.skipped.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failed_listing_is_an_error_from_the_read_itself() {
    use aws_sdk_iam::error::ErrorMetadata;
    use aws_sdk_iam::operation::list_roles::ListRolesError;
    let rule = mock!(aws_sdk_iam::Client::list_roles).then_error(|| {
        ListRolesError::generic(ErrorMetadata::builder().code("AccessDenied").build())
    });
    let iam = mock_client!(aws_sdk_iam, RuleMode::Sequential, [&rule]);
    let err = iam_roles(&iam, &T).await.unwrap_err();
    assert!(matches!(err, ConnectorError::Api { code: Some(c), .. } if c == "AccessDenied"));
}
