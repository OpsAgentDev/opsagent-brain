//! IAM users from the credential report.
use super::Target;
use crate::aws::client::provider_err;
use crate::ConnectorError;
use crate::Result;
use chrono::{DateTime, NaiveDate, Utc};
use opsagent_core::resource::{Resource, ResourceKind};
use serde_json::json;
use std::collections::BTreeMap;

fn days_since(ts: &str, now: DateTime<Utc>) -> Option<i64> {
    // Report timestamps are ISO 8601; "N/A" and "no_information" fail the parse.
    let d = NaiveDate::parse_from_str(ts.get(..10)?, "%Y-%m-%d").ok()?;
    Some((now.date_naive() - d).num_days())
}

/// Splits one CSV record; handles quoted fields and doubled quotes.
fn csv_fields(line: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted) = (vec![], String::new(), false);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

// shortcut: ~74 lines, one pass over the CSV columns; split into a row parser when more columns are read.
/// Parses the IAM credential report CSV into identity resources. The `<root_account>` row
/// becomes a `root: true` resource; `admin` for users comes from `admins`.
pub fn credential_report_users(
    csv: &str,
    admins: &dyn Fn(&str) -> bool,
    t: &Target<'_>,
    now: DateTime<Utc>,
) -> Vec<Resource> {
    let mut lines = csv.lines();
    let header = csv_fields(lines.next().unwrap_or_default());
    let col = |row: &[String], name: &str| -> String {
        header
            .iter()
            .position(|h| h == name)
            .and_then(|i| row.get(i))
            .cloned()
            .unwrap_or_default()
    };
    let mut out = vec![];
    for line in lines.filter(|l| !l.is_empty()) {
        let row = csv_fields(line);
        let user = col(&row, "user");
        if user.is_empty() {
            continue;
        }
        let active: Vec<&str> = ["access_key_1", "access_key_2"]
            .into_iter()
            .filter(|k| col(&row, &format!("{k}_active")) == "true")
            .collect();
        let mfa = col(&row, "mfa_active") == "true";
        if user == "<root_account>" {
            let attrs = json!({
                "service": "iam",
                "root": true,
                "mfa": mfa,
                "access_keys_active": active.len() as u8,
                "console_last_used_days": days_since(&col(&row, "password_last_used"), now),
            });
            out.push(t.resource(
                ResourceKind::Identity,
                col(&row, "arn"),
                "root",
                BTreeMap::new(),
                attrs,
            ));
            continue;
        }
        let (mut age, mut used): (Option<i64>, Option<i64>) = (None, None);
        for k in active {
            let rotated = days_since(&col(&row, &format!("{k}_last_rotated")), now);
            // A never-used key counts as unused since it was created.
            let last = days_since(&col(&row, &format!("{k}_last_used_date")), now).or(rotated);
            age = age.max(rotated);
            used = match (used, last) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        let attrs = json!({
            "service": "iam",
            "key_age_days": age,
            "key_last_used_days": used,
            "mfa": mfa,
            "console": col(&row, "password_enabled") == "true",
            "admin": admins(&user),
        });
        out.push(t.resource(
            ResourceKind::Identity,
            col(&row, "arn"),
            &user,
            BTreeMap::new(),
            attrs,
        ));
    }
    out
}

/// Generates and fetches the credential report: retries while it is in progress, regenerates
/// when it has expired, gives up after `max_wait`.
pub async fn credential_report(
    iam: &aws_sdk_iam::Client,
    poll: std::time::Duration,
    max_wait: std::time::Duration,
) -> Result<String> {
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut generate = true;
    loop {
        if generate {
            iam.generate_credential_report()
                .send()
                .await
                .map_err(provider_err)?;
            generate = false;
        }
        match iam.get_credential_report().send().await {
            Ok(r) => {
                return Ok(r
                    .content()
                    .map(|b| String::from_utf8_lossy(b.as_ref()).into_owned())
                    .unwrap_or_default())
            }
            Err(e) => match e.as_service_error() {
                Some(se)
                    if se.is_credential_report_not_ready_exception()
                        || se.is_credential_report_not_present_exception() => {}
                Some(se) if se.is_credential_report_expired_exception() => generate = true,
                _ => return Err(provider_err(e)),
            },
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ConnectorError::Provider(format!(
                "credential report not ready after {}s",
                max_wait.as_secs()
            )));
        }
        tokio::time::sleep(poll).await;
    }
}

pub async fn iam_users(iam: &aws_sdk_iam::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    use std::time::Duration;
    let csv = credential_report(iam, Duration::from_secs(2), Duration::from_secs(120)).await?;
    let users: Vec<String> = credential_report_users(&csv, &|_| false, t, Utc::now())
        .into_iter()
        .filter(|r| r.attributes.get("root").is_none())
        .map(|r| r.name)
        .collect();
    let mut admins = std::collections::HashSet::new();
    for u in &users {
        let mut pages = iam
            .list_attached_user_policies()
            .user_name(u)
            .into_paginator()
            .items()
            .send();
        while let Some(p) = pages.next().await {
            if p.map_err(provider_err)?
                .policy_arn()
                .unwrap_or_default()
                .ends_with(":policy/AdministratorAccess")
            {
                admins.insert(u.clone());
            }
        }
    }
    Ok(credential_report_users(
        &csv,
        &|u| admins.contains(u),
        t,
        Utc::now(),
    ))
}
