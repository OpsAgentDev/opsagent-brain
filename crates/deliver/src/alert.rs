//! Urgent alerts (urgent-alerts spec): which candidates go out on their own and which only in
//! a roll-up, and the message texts. Pure: the action counts what was sent and sends.
use chrono::{DateTime, Duration, Utc};
use opsagent_core::finding::Finding;
use uuid::Uuid;

/// Individual messages per delivery run; the rest go into one roll-up.
pub const ALERTS_PER_RUN: usize = 5;
/// Individual messages per connection in a rolling 24 hours; roll-ups don't count.
pub const ALERTS_PER_DAY: usize = 20;
/// At most one roll-up per connection in this long.
pub const ROLLUP_EVERY: Duration = Duration::hours(1);

/// What one delivery run does with its candidates. Every id in either list gets `alerted_at`,
/// whether or not the roll-up is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertPlan {
    pub individual: Vec<Uuid>,
    pub rollup: Vec<Uuid>,
    /// No roll-up went out in the last `ROLLUP_EVERY`.
    pub rollup_allowed: bool,
}

/// Where an alerted finding lives, as the message names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// The connection's alias, else its account id.
    pub account: String,
    /// The resource's name, else its id.
    pub resource: String,
    pub region: Option<String>,
}

/// `candidates` oldest first; `sent_last_24h` individual alerts of the connection.
pub fn plan_alerts(
    candidates: &[Finding],
    sent_last_24h: usize,
    last_rollup_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> AlertPlan {
    let room = ALERTS_PER_RUN.min(ALERTS_PER_DAY.saturating_sub(sent_last_24h));
    let (individual, rollup) = candidates.split_at(room.min(candidates.len()));
    AlertPlan {
        individual: individual.iter().map(|f| f.id).collect(),
        rollup: rollup.iter().map(|f| f.id).collect(),
        rollup_allowed: last_rollup_at.is_none_or(|t| now - t >= ROLLUP_EVERY),
    }
}

/// Slack mrkdwn for one urgent finding (the email body is its plain form).
pub fn render_alert(f: &Finding, at: &ConnectionInfo, web_base_url: &str) -> String {
    let mut place = vec![esc(&at.resource), esc(&at.account)];
    place.extend(at.region.as_deref().map(esc));
    let mut lines = vec![format!("🔴 Urgent: {}", esc(&f.title)), place.join(" · ")];
    lines.extend(f.next_step.as_deref().map(esc));
    lines.push(format!(
        "View finding: {}/findings/{}",
        base(web_base_url),
        f.id
    ));
    lines.join("\n")
}

pub fn render_rollup(n: usize, web_base_url: &str) -> String {
    format!(
        "🔴 And {n} more urgent findings: {}/findings",
        base(web_base_url)
    )
}

/// The one message of a connection's first full scan, instead of an alert per critical.
pub fn render_baseline(n: usize, web_base_url: &str) -> String {
    format!(
        "First scan: {n} critical findings. See the dashboard: {}/findings",
        base(web_base_url)
    )
}

fn base(url: &str) -> &str {
    url.trim_end_matches('/')
}

fn esc(s: &str) -> String {
    crate::render_text::slack_item(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opsagent_core::finding::{FindingKey, Severity};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_900_000_000, 0).unwrap()
    }

    fn crit(title: &str) -> Finding {
        Finding {
            id: Uuid::now_v7(),
            organisation_id: Uuid::nil(),
            connection_id: Uuid::nil(),
            key: FindingKey {
                connection_id: Uuid::nil(),
                check_id: "03".into(),
                resource_identity: "snap-1".into(),
                variant: "public_snapshot".into(),
            },
            severity: Severity::Critical,
            status: "open".into(),
            title: title.into(),
            summary: None,
            next_step: Some("Make the snapshot private.".into()),
            cost_monthly_usd: None,
            accepted_reason: None,
            accepted_until: None,
            snoozed_until: None,
            first_seen_run_id: None,
            last_seen_run_id: None,
            resolved_at: None,
            resolved_reason: None,
            alerted_at: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn many(n: usize) -> Vec<Finding> {
        (0..n).map(|i| crit(&format!("c{i}"))).collect()
    }

    fn ids(f: &[Finding]) -> Vec<Uuid> {
        f.iter().map(|f| f.id).collect()
    }

    #[test]
    fn seven_candidates_none_sent_give_five_and_a_rollup_of_two() {
        let c = many(7);
        let p = plan_alerts(&c, 0, None, now());
        assert_eq!(p.individual, ids(&c[..5]));
        assert_eq!(p.rollup, ids(&c[5..]));
        assert!(p.rollup_allowed);
    }

    #[test]
    fn nineteen_sent_today_leaves_room_for_one() {
        let c = many(3);
        let p = plan_alerts(&c, 19, None, now());
        assert_eq!(p.individual, ids(&c[..1]));
        assert_eq!(p.rollup, ids(&c[1..]));
        assert_eq!(plan_alerts(&c, 25, None, now()).rollup.len(), 3);
    }

    #[test]
    fn rollup_half_an_hour_ago_holds_the_rollup_but_keeps_its_findings() {
        let c = many(6);
        let p = plan_alerts(&c, 0, Some(now() - Duration::minutes(30)), now());
        assert!(!p.rollup_allowed);
        assert_eq!(p.rollup, ids(&c[5..]), "still marked alerted");
        let later = plan_alerts(&c, 0, Some(now() - Duration::minutes(60)), now());
        assert!(later.rollup_allowed);
    }

    #[test]
    fn alert_text_is_verbatim_and_escaped() {
        let f = crit("Public <snapshot> & co");
        let at = ConnectionInfo {
            account: "Prod".into(),
            resource: "snap-1".into(),
            region: Some("eu-west-1".into()),
        };
        assert_eq!(
            render_alert(&f, &at, "https://opsagent.dev/"),
            format!(
                "🔴 Urgent: Public &lt;snapshot&gt; &amp; co\nsnap-1 · Prod · eu-west-1\n\
                 Make the snapshot private.\nView finding: https://opsagent.dev/findings/{}",
                f.id
            )
        );
        let bare = Finding {
            next_step: None,
            ..f.clone()
        };
        let global = ConnectionInfo { region: None, ..at };
        assert_eq!(
            render_alert(&bare, &global, "https://x.test"),
            format!(
                "🔴 Urgent: Public &lt;snapshot&gt; &amp; co\nsnap-1 · Prod\n\
                 View finding: https://x.test/findings/{}",
                f.id
            )
        );
    }

    #[test]
    fn rollup_and_baseline_texts() {
        assert_eq!(
            render_rollup(2, "https://x.test"),
            "🔴 And 2 more urgent findings: https://x.test/findings"
        );
        assert_eq!(
            render_baseline(3, "https://x.test/"),
            "First scan: 3 critical findings. See the dashboard: https://x.test/findings"
        );
    }
}
