//! Connection response bodies.
use chrono::{DateTime, FixedOffset, NaiveTime};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use opsagent_connectors::aws::policy_diff::grant_names;

use crate::models::_entities::{connection_verifications, connections};

fn hhmm(t: Option<NaiveTime>) -> Option<String> {
    t.map(|t| t.format("%H:%M").to_string())
}

/// The API shows the IAM action names of the stored grant labels only.
fn grant_actions(v: &Value) -> Vec<String> {
    let labels = v.as_array().into_iter().flatten().filter_map(Value::as_str);
    grant_names(labels).into_iter().map(str::to_owned).collect()
}

#[derive(Serialize, ToSchema)]
pub struct Verification {
    /// Verification outcome code.
    pub outcome: String,
    pub at: DateTime<FixedOffset>,
    pub assume_with_ok: Option<bool>,
    pub assume_without_denied: Option<bool>,
    pub policy_matches: Option<bool>,
    /// IAM action names granted beyond the template.
    pub extra_grants: Vec<String>,
    /// IAM action names the template grants but the role lacks.
    pub missing_grants: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Connection {
    pub id: Uuid,
    pub provider: String,
    pub display_name: Option<String>,
    /// `pending`, `verifying`, `connected`, `degraded`, `revoked`, `blocked` or `disconnected`.
    pub status: String,
    pub status_reason: Option<String>,
    pub external_account_id: Option<String>,
    pub template_version: Option<String>,
    /// `HH:MM` in the organisation's timezone.
    pub scan_time_local: Option<String>,
    pub briefing_time_local: Option<String>,
    pub api_rate_ceiling: Option<i32>,
    /// Slack channel id for this connection's deliveries; null posts nothing to Slack (there is
    /// no organisation channel), so briefings go to the owners by email.
    pub slack_channel_id: Option<String>,
    pub first_connected_at: Option<DateTime<FixedOffset>>,
    pub billable_from: Option<DateTime<FixedOffset>>,
    pub created_at: DateTime<FixedOffset>,
    pub last_verification: Option<Verification>,
}

pub fn view(c: &connections::Model, last: Option<&connection_verifications::Model>) -> Connection {
    Connection {
        id: c.id,
        provider: c.provider.clone(),
        display_name: c.display_name.clone(),
        status: c.status.clone(),
        status_reason: c.status_reason.clone(),
        external_account_id: c.external_account_id.clone(),
        template_version: c.template_version.clone(),
        scan_time_local: hhmm(c.scan_time_local),
        briefing_time_local: hhmm(c.briefing_time_local),
        api_rate_ceiling: c.api_rate_ceiling,
        slack_channel_id: c.slack_channel_id.clone(),
        first_connected_at: c.first_connected_at,
        billable_from: c.billable_from,
        created_at: c.created_at,
        last_verification: last.map(|v| Verification {
            outcome: v.outcome.clone(),
            at: v.created_at,
            assume_with_ok: v.assume_with_ok,
            assume_without_denied: v.assume_without_denied,
            policy_matches: v.policy_matches,
            extra_grants: grant_actions(&v.extra_grants),
            missing_grants: grant_actions(&v.missing_grants),
        }),
    }
}
