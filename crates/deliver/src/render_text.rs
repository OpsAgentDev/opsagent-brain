//! Slack mrkdwn for the briefing and the Slack weekly, plain text for the email weekly.
//! Titles only, never evidence.
use opsagent_core::connection::ConnectionStatus;

use crate::model::{severity_label, Briefing, DailyCounts, Health, Item, SeverityCounts, Weekly};

/// Slack's limit is ~4,000; keep headroom. Measured in bytes, which is stricter than chars.
pub const SLACK_MAX: usize = 3_900;
/// Per title or reason, after escaping.
const ITEM_MAX: usize = 200;

pub trait RenderText {
    fn render_text(&self) -> String;
}

pub fn render_text<T: RenderText>(doc: &T) -> String {
    doc.render_text()
}

impl RenderText for Briefing {
    fn render_text(&self) -> String {
        match self {
            Briefing::FirstScan { counts, link } => hard_cap(format!(
                "*OpsAgent first scan complete.* Open findings: {}.\n<{link}|See every finding on the dashboard>",
                severity_counts(counts)
            )),
            Briefing::Daily {
                new_critical_high,
                escalated,
                resolved_critical,
                health,
                counts,
                link,
            } => {
                let mut sections = [
                    ("New critical and high", new_critical_high.iter().collect(), counts.new_critical_high),
                    ("Escalated", escalated.iter().collect(), counts.escalated),
                    ("Resolved critical", resolved_critical.iter().collect(), counts.resolved_critical),
                ];
                let health = health.as_ref().map(health_line);
                loop {
                    let t = daily(&sections, health.as_deref(), counts, link);
                    // Over the limit: drop from the end of the last non-empty list.
                    let Some(last) = sections.iter_mut().rev().find(|s| !s.1.is_empty()) else {
                        return hard_cap(t);
                    };
                    if t.len() <= SLACK_MAX {
                        return t;
                    }
                    last.1.pop();
                }
            }
        }
    }
}

type Section<'a> = (&'static str, Vec<&'a Item>, usize);

fn daily(
    sections: &[Section; 3],
    health: Option<&str>,
    counts: &DailyCounts,
    link: &str,
) -> String {
    let mut out = String::from("*OpsAgent morning briefing*\n");
    let mut hidden = 0;
    for (name, items, total) in sections.iter().filter(|s| s.2 > 0) {
        out += &format!("*{name}* ({total})\n");
        for i in items {
            out += &format!(
                "• {}: {}\n",
                severity_label(i.severity),
                slack_item(&i.title)
            );
        }
        hidden += total - items.len();
    }
    if let Some(h) = health {
        out += &format!("*Connection health:* {h}\n");
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
        parts.push(slack_item(r));
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

/// Escapes Slack's control characters (`&`, `<`, `>`), then caps at ITEM_MAX with an ellipsis.
fn slack_item(s: &str) -> String {
    let e = s
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    if e.chars().count() <= ITEM_MAX {
        return e;
    }
    let mut cut: String = e.chars().take(ITEM_MAX - 1).collect();
    // Never leave half an entity behind.
    if let Some(i) = cut.rfind('&').filter(|&i| !cut[i..].contains(';')) {
        cut.truncate(i);
    }
    cut + "…"
}

/// Last resort when even an item-free message is too long (an absurd link): cut on a char boundary.
fn hard_cap(mut s: String) -> String {
    if s.len() > SLACK_MAX {
        let mut i = SLACK_MAX;
        while !s.is_char_boundary(i) {
            i -= 1;
        }
        s.truncate(i);
    }
    debug_assert!(s.len() <= SLACK_MAX);
    s
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
        let plain = |s: &str| s.to_string();
        let mut out = weekly_lines(self, &plain, &plain).concat();
        out += &weekly_tail(self, &format!("Dashboard: {}", self.link));
        out
    }
}

/// The weekly as Slack mrkdwn: escaped, bold labels, and fitted under SLACK_MAX
/// by dropping trailing lines (the dashboard and "Need a human?" lines always stay).
pub fn render_slack(w: &Weekly) -> String {
    let bold = |s: &str| format!("*{s}*");
    let mut lines = weekly_lines(w, &slack_item, &bold);
    let tail = weekly_tail(w, &format!("<{}|Open the dashboard>", w.link));
    let note = "(truncated; full report on the dashboard)\n";
    if lines.concat().len() + tail.len() <= SLACK_MAX {
        return lines.concat() + &tail;
    }
    while !lines.is_empty() && lines.concat().len() + note.len() + tail.len() > SLACK_MAX {
        lines.pop();
    }
    hard_cap(lines.concat() + note + &tail)
}

fn weekly_tail(w: &Weekly, dashboard: &str) -> String {
    format!("\n{dashboard}\nNeed a human? {}\n", w.need_a_human_url)
}

type Fmt<'a> = &'a dyn Fn(&str) -> String;

/// One entry per line (each ends with `\n`); `esc` wraps user-derived text, `label` section names.
fn weekly_lines(w: &Weekly, esc: Fmt, label: Fmt) -> Vec<String> {
    let mut out = vec![format!(
        "{} {}\n\n",
        label("OpsAgent weekly report:"),
        esc(&w.connection_name)
    )];
    if w.first_week {
        out.push("This is the first week; baselines forming.\n".into());
        out.push(format!(
            "{} {}\n",
            label("Inventory:"),
            severity_counts(&w.inventory)
        ));
        return out;
    }
    let s = &w.spend;
    out.push(format!(
        "{} {} this week vs {} last week ({})\n",
        label("Spend:"),
        usd(&s.this_week_usd),
        usd(&s.last_week_usd),
        signed_usd(&s.delta_usd)
    ));
    for (day, amount, baseline) in &s.anomalies {
        out.push(format!(
            "  Anomaly {day}: {} vs baseline {}\n",
            usd(amount),
            usd(baseline)
        ));
    }
    out.push(match &w.recommended_cost_action {
        Some(a) => format!(
            "{} {} (saves {}/month)\n",
            label("Recommended cost action:"),
            esc(&a.title),
            usd(&a.savings_monthly_usd)
        ),
        None => format!("{} none this week\n", label("Recommended cost action:")),
    });
    let posture = match (w.posture.score, w.posture.delta) {
        (Some(score), Some(d)) => format!("{score} ({})", signed(&d)),
        (Some(score), None) => score.to_string(),
        _ => "not yet scored".into(),
    };
    out.push(format!("{} {posture}\n", label("Posture score:")));
    out.push(format!(
        "{} {} open ({} new, {} resolved this week)\n",
        label("IAM:"),
        w.iam.open,
        w.iam.opened,
        w.iam.resolved
    ));
    let restore = w
        .backups
        .last_restore_test_on
        .map_or("not recorded".into(), |d| d.to_string());
    out.push(format!(
        "{} {} open issues; last successful restore test {restore}\n",
        label("Backups:"),
        w.backups.open_issues
    ));
    list(
        &mut out,
        label("Certificate calendar:"),
        &w.certificates,
        esc,
    );
    out.push(match w.untagged_spend_pct {
        Some(p) => format!("{} {p:.1}%\n", label("Untagged spend:")),
        None => format!("{} unknown\n", label("Untagged spend:")),
    });
    list(
        &mut out,
        label("Awaiting your decision:"),
        &w.awaiting_decision,
        esc,
    );
    out.push(format!("{}\n", label("What the agent would have done:")));
    out.extend(
        w.would_have_done
            .iter()
            .map(|l| format!("  - {}\n", esc(l))),
    );
    out
}

fn list(out: &mut Vec<String>, name: String, items: &[Item], esc: Fmt) {
    out.push(format!("{name}\n"));
    if items.is_empty() {
        out.push("  none\n".into());
    }
    for i in items {
        out.push(format!(
            "  - [{}] {}\n",
            severity_label(i.severity),
            esc(&i.title)
        ));
    }
}
