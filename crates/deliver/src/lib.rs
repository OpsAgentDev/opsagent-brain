//! Briefing and weekly documents. Pure: snapshots in, text out; no I/O, no logging.
pub mod briefing;
pub mod model;
pub mod render_html;
pub mod render_text;
pub mod route;
pub mod weekly;

pub use render_html::render_html;
pub use render_text::{render_text, RenderText};
