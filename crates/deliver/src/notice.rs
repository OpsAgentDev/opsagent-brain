//! Branded HTML for text-only mails: heading, paragraphs, optional button and footnote.
use askama::Template;

pub struct NoticeEmail {
    /// Hidden inbox preview line.
    pub preheader: String,
    pub heading: String,
    pub paragraphs: Vec<String>,
    /// (label, url)
    pub button: Option<(String, String)>,
    pub footnote: Option<String>,
    pub unsubscribe_url: Option<String>,
    /// A one-time code shown in a large monospace block after the paragraphs.
    pub code: Option<String>,
}

#[derive(Template)]
#[template(path = "notice.html")]
struct NoticeHtml<'a> {
    preheader: &'a str,
    heading: &'a str,
    paragraphs: &'a [String],
    button: &'a Option<(String, String)>,
    footnote: &'a Option<String>,
    unsubscribe_url: &'a Option<String>,
    code: &'a Option<String>,
}

impl NoticeHtml<'_> {
    /// A list line ending in `: <url>` (a briefing's finding) as (text, url), so the text links.
    /// Only a url on the trusted button's origin links: mails can carry customer-written lines
    /// (contact forwards, review requests), whose urls must never hide behind link text.
    fn linked<'p>(&self, p: &'p str) -> Option<(&'p str, &'p str)> {
        let (text, url) = p.strip_prefix("• ").and(p.rsplit_once(": "))?;
        let (_, trusted) = self.button.as_ref()?;
        let origin = trusted.splitn(4, '/').take(3).collect::<Vec<_>>().join("/");
        (origin.starts_with("http") && url.starts_with(&format!("{origin}/")) && !url.contains(' '))
            .then_some((text, url))
    }
}

pub fn render_notice(n: &NoticeEmail) -> String {
    // shortcut: render only fails on a template Display error, which our types never raise.
    NoticeHtml {
        preheader: &n.preheader,
        heading: &n.heading,
        paragraphs: &n.paragraphs,
        button: &n.button,
        footnote: &n.footnote,
        unsubscribe_url: &n.unsubscribe_url,
        code: &n.code,
    }
    .render()
    .unwrap_or_default()
}
