//! Briefing and weekly documents (pure: snapshots in, text out), schedule maths, and the
//! delivery repository ports. No I/O, no logging.
pub mod alert;
pub mod briefing;
pub mod model;
pub mod render_html;
pub mod render_text;
pub mod repo;
pub mod route;
pub mod schedule;
pub mod weekly;

pub use render_html::render_html;
pub use render_text::{render_slack, render_text, RenderText, SLACK_MAX};
