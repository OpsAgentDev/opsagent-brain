//! Slack mrkdwn for the briefing, plain text for the weekly. Titles only, never evidence.
use opsagent_core::connection::ConnectionStatus;

use crate::model::{severity_label, Briefing, DailyCounts, Health, Item, SeverityCounts, Weekly};

/// 10 titles at this length keep a briefing far under Slack's ~4,000-char limit.
const TITLE_MAX: usize = 200;

pub trait RenderText {
    fn render_text(&self) -> String;
}

pub fn render_text<T: RenderText>(doc: &T) -> String {
    doc.render_text()
}

impl RenderText for Briefing {
    fn render_text(&self) -> String {
        match self {
            Briefing::FirstScan { counts, link } => format!(
                "*OpsAgent first scan complete.* Open findings: {}.\n<{link}|See every finding on the dashboard>",
                severity_counts(counts)
            ),
            Briefing::Daily {
                new_critical_high,
                escalated,
                resolved_critical,
                health,
                counts,
                link,
            } => daily(
                [
                    ("New critical and high", new_critical_high, counts.new_critical_high),
                    ("Escalated", escalated, counts.escalated),
                    ("Resolved critical", resolved_critical, counts.resolved_critical),
                ],
                health.as_ref(),
                counts,
                link,
            ),
        }
    }
}

fn daily(
    sections: [(&str, &Vec<Item>, usize); 3],
    health: Option<&Health>,
    counts: &DailyCounts,
    link: &str,
) -> String {
    let mut out = String::from("*OpsAgent morning briefing*\n");
    let mut hidden = 0;
    for (name, items, total) in sections.into_iter().filter(|s| s.2 > 0) {
        out += &format!("*{name}* ({total})\n");
        for i in items {
            out += &format!(
                "• {}: {}\n",
                severity_label(i.severity),
                slack_escape(&i.title)
            );
        }
        hidden += total - items.len();
    }
    if let Some(h) = health {
        out += &format!("*Connection health:* {}\n", health_line(h));
    }
    out += &format!("Open now: {}\n", severity_counts(&counts.open));
    if hidden > 0 {
        out += &format!("{hidden} more on the dashboard. ");
    }
    out + &format!("<{link}|Open the dashboard>")
}

fn health_line(h: &Health) -> String {
    let mut parts = vec![status_label(h.status)];
    if let Some(r) = &h.reason {
        parts.push(slack_escape(r));
    }
    if h.partial {
        parts.push("last scan partial".into());
    }
    if h.stale {
        parts.push("no scan in 48 hours".into());
    }
    parts.join("; ")
}

fn status_label(s: ConnectionStatus) -> String {
    format!("{s:?}").to_lowercase()
}

/// Slack treats `<`, `>` and `&` as control characters; also caps length.
fn slack_escape(s: &str) -> String {
    let s: String = s.chars().take(TITLE_MAX).collect();
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub(crate) fn severity_counts(c: &SeverityCounts) -> String {
    format!(
        "{} critical, {} high, {} medium, {} low, {} info",
        c.critical, c.high, c.medium, c.low, c.info
    )
}

pub(crate) fn usd(x: &f64) -> String {
    format!("${x:.2}")
}

pub(crate) fn signed_usd(x: &f64) -> String {
    let sign = if *x < 0.0 { '-' } else { '+' };
    format!("{sign}${:.2}", x.abs())
}

pub(crate) fn signed(x: &f64) -> String {
    format!("{x:+}")
}

impl RenderText for Weekly {
    fn render_text(&self) -> String {
        let mut out = format!("OpsAgent weekly report: {}\n\n", self.connection_name);
        if self.first_week {
            out += &format!(
                "This is the first week; baselines forming.\nInventory: {}\n",
                severity_counts(&self.inventory)
            );
        } else {
            out += &weekly_sections(self);
        }
        out + &format!(
            "\nDashboard: {}\nNeed a human? {}\n",
            self.link, self.need_a_human_url
        )
    }
}

fn weekly_sections(w: &Weekly) -> String {
    let s = &w.spend;
    let mut out = format!(
        "Spend: {} this week vs {} last week ({})\n",
        usd(&s.this_week_usd),
        usd(&s.last_week_usd),
        signed_usd(&s.delta_usd)
    );
    for (day, amount, baseline) in &s.anomalies {
        out += &format!(
            "  Anomaly {day}: {} vs baseline {}\n",
            usd(amount),
            usd(baseline)
        );
    }
    out += &match &w.recommended_cost_action {
        Some(a) => format!(
            "Recommended cost action: {} (saves {}/month)\n",
            a.title,
            usd(&a.savings_monthly_usd)
        ),
        None => "Recommended cost action: none this week\n".into(),
    };
    out += &match (w.posture.score, w.posture.delta) {
        (Some(score), Some(d)) => format!("Posture score: {score} ({})\n", signed(&d)),
        (Some(score), None) => format!("Posture score: {score}\n"),
        _ => "Posture score: not yet scored\n".into(),
    };
    out += &format!(
        "IAM: {} open ({} new, {} resolved this week)\n",
        w.iam.open, w.iam.opened, w.iam.resolved
    );
    out += &format!(
        "Backups: {} open issues; last successful restore test {}\n",
        w.backups.open_issues,
        w.backups
            .last_restore_test_on
            .map_or("not recorded".into(), |d| d.to_string())
    );
    out += &list("Certificate calendar", &w.certificates);
    out += &match w.untagged_spend_pct {
        Some(p) => format!("Untagged spend: {p:.1}%\n"),
        None => "Untagged spend: unknown\n".into(),
    };
    out += &list("Awaiting your decision", &w.awaiting_decision);
    out += "What the agent would have done:\n";
    for line in &w.would_have_done {
        out += &format!("  - {line}\n");
    }
    out
}

fn list(name: &str, items: &[Item]) -> String {
    let mut out = format!("{name}:\n");
    if items.is_empty() {
        out += "  none\n";
    }
    for i in items {
        out += &format!("  - [{}] {}\n", severity_label(i.severity), i.title);
    }
    out
}
