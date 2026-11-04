//! Checks 11 to 13 end to end on the fake connector, through `all()` as the scan runs them.
mod common;
use common::*;
use opsagent_checks::all;
use opsagent_core::finding::Severity::*;

#[test]
fn all_returns_ids_in_order() {
    let ids: Vec<_> = all().iter().map(|c| c.id()).collect();
    assert_eq!(
        ids,
        ["01", "02", "03", "04", "05", "06", "07", "11", "12", "13"]
    );
}

async fn security_set(
    account: &str,
) -> Vec<(String, String, String, opsagent_core::finding::Severity)> {
    let (r, c) = load(account).await;
    let mut out = vec![];
    for ch in all()
        .iter()
        .filter(|c| ["11", "12", "13"].contains(&c.id()))
    {
        for (i, v, s) in set(&run(ch.as_ref(), &r, &c)) {
            out.push((ch.id().to_owned(), i, v, s));
        }
    }
    out
}

fn row(
    c: &str,
    i: &str,
    v: &str,
    s: opsagent_core::finding::Severity,
) -> (String, String, String, opsagent_core::finding::Severity) {
    (c.into(), i.into(), v.into(), s)
}

#[tokio::test]
async fn security_checks_run_on_the_fake_connector() {
    let mut want = vec![
        row("11", "cluster-plain", "unencrypted_database", High),
        row("11", "db-plain", "unencrypted_database", High),
        row("11", "snap-ebs-plain", "unencrypted_snapshot", Low),
        row("11", "snap-rds-plain", "unencrypted_snapshot", Low),
        row("11", "vol-plain-attached", "unencrypted_volume", Medium),
        row("11", "vol-plain-detached", "unencrypted_volume", Low),
        row("12", "i-imds-open", "imdsv1_allowed", Medium),
        row("12", "i-imds-public", "imdsv1_allowed", High),
        row("13", "user-stale-pw", "stale_password", Low),
        row("13", "user-two-keys", "two_active_keys", Low),
        row("13", "user-unused-key", "key_never_used", Medium),
    ];
    want.sort();
    let mut got = security_set("insecure").await;
    got.sort();
    assert_eq!(got, want);
}

#[tokio::test]
async fn clean_account_has_no_security_findings() {
    assert!(security_set("clean").await.is_empty());
}

#[tokio::test]
async fn noisy_account_gets_no_security_findings_without_the_attributes() {
    assert!(security_set("noisy").await.is_empty());
}
