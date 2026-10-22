//! Weekly email HTML. Askama autoescapes every interpolation in `.html` templates.
use askama::Template;

use crate::model::{severity_label, Weekly};
use crate::render_text::{severity_counts, signed, signed_usd, usd};

#[derive(Template)]
#[template(path = "weekly.html")]
struct WeeklyHtml<'a> {
    w: &'a Weekly,
}

impl WeeklyHtml<'_> {
    fn usd(&self, x: &f64) -> String {
        usd(x)
    }
    fn signed_usd(&self, x: &f64) -> String {
        signed_usd(x)
    }
    fn signed(&self, x: &f64) -> String {
        signed(x)
    }
    fn sev(&self, s: &opsagent_core::finding::Severity) -> &'static str {
        severity_label(*s)
    }
    fn inventory(&self) -> String {
        severity_counts(&self.w.inventory)
    }
}

pub fn render_html(w: &Weekly) -> String {
    // shortcut: render only fails on a template Display error, which our types never raise.
    WeeklyHtml { w }.render().unwrap_or_default()
}
