//! Weekly email HTML. Askama autoescapes every interpolation in `.html` templates.
use askama::Template;

use crate::model::{severity_label, Item, Weekly};
use crate::render_text::{severity_counts, signed, signed_usd, usd};
use opsagent_core::finding::Severity;

const BAD: &str = "#dc2626";
const WARN: &str = "#d97706";
const OK: &str = "#059669";
const TEXT: &str = "#1f2937";

#[derive(Template)]
#[template(path = "weekly.html")]
struct WeeklyHtml<'a> {
    w: &'a Weekly,
    preheader: String,
    unsubscribe_url: &'a Option<String>,
}

impl WeeklyHtml<'_> {
    fn inventory(&self) -> String {
        severity_counts(&self.w.inventory)
    }
    fn spend(&self) -> String {
        match &self.w.spend {
            Some(s) => format!(
                "{} this week vs {} last week ({})",
                usd(&s.this_week_usd),
                usd(&s.last_week_usd),
                signed_usd(&s.delta_usd)
            ),
            None => "Not tracked yet".into(),
        }
    }
    fn spend_color(&self) -> &'static str {
        match &self.w.spend {
            Some(s) if s.delta_usd > 0.0 => WARN,
            _ => TEXT,
        }
    }
    fn anomaly(&self, day: &chrono::NaiveDate, amount: &f64, baseline: &f64) -> String {
        format!("{day}: {} vs baseline {}", usd(amount), usd(baseline))
    }
    fn cost_action(&self) -> String {
        match &self.w.recommended_cost_action {
            Some(a) => format!("{} (saves {}/month)", a.title, usd(&a.savings_monthly_usd)),
            None => "None this week".into(),
        }
    }
    fn posture(&self) -> String {
        match (self.w.posture.score, self.w.posture.delta) {
            (Some(s), Some(d)) => format!("{s} ({})", signed(&d)),
            (Some(s), None) => s.to_string(),
            _ => "Not yet scored".into(),
        }
    }
    fn posture_color(&self) -> &'static str {
        match self.w.posture.delta {
            Some(d) if d < 0.0 => BAD,
            Some(d) if d > 0.0 => OK,
            _ => TEXT,
        }
    }
    fn iam(&self) -> String {
        let i = &self.w.iam;
        format!(
            "{} open ({} new, {} resolved this week)",
            i.open, i.opened, i.resolved
        )
    }
    fn backups(&self) -> String {
        let b = &self.w.backups;
        let restore = b
            .last_restore_test_on
            .map_or("not recorded".into(), |d| d.to_string());
        format!(
            "{} open issues; last successful restore test {restore}",
            b.open_issues
        )
    }
    fn backups_color(&self) -> &'static str {
        if self.w.backups.open_issues > 0 {
            WARN
        } else {
            TEXT
        }
    }
    fn untagged(&self) -> String {
        self.w
            .untagged_spend_pct
            .map_or("Unknown".into(), |p| format!("{p:.1}%"))
    }
    /// (severity label, colour, title) per item.
    fn item_rows(&self, items: &[Item]) -> Vec<(&'static str, &'static str, String)> {
        items
            .iter()
            .map(|i| {
                let color = match i.severity {
                    Severity::Critical | Severity::High => BAD,
                    Severity::Medium => WARN,
                    _ => "#6b7280",
                };
                (severity_label(i.severity), color, i.title.clone())
            })
            .collect()
    }
}

pub fn render_html(w: &Weekly) -> String {
    // shortcut: render only fails on a template Display error, which our types never raise.
    WeeklyHtml {
        w,
        preheader: format!("Weekly report for {}", w.connection_name),
        unsubscribe_url: &w.unsubscribe_url,
    }
    .render()
    .unwrap_or_default()
}
