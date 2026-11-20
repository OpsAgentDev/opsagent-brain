//! Customer-written text (organisation, person and connection names, finding titles) as it may
//! appear in a mail sent to someone who did not write it: nothing a mail client turns into a
//! link. Names in the app are untouched.
use opsagent_core::org::is_bidi;

/// The full stop and what clients also read as a domain dot (ideographic, full-width).
const DOTS: [char; 4] = ['.', '\u{3002}', '\u{FF0E}', '\u{FF61}'];

fn word(c: Option<&char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || *c == '_')
}

/// `raw` on one line with no link in it:
/// - control and text-direction characters, `/` and `\` become a space (no path, no `//`);
/// - a `:` directly before a non-space becomes a space (no `https:`, `mailto:`, `tel:` scheme);
/// - a dot directly between two word characters, or after `www`, becomes `[.]` (no domain, no
///   address), so "Acme Inc." and "Dr. No" stay as written;
/// - runs of whitespace collapse to one space.
pub fn mail_safe_text(raw: &str) -> String {
    let raw: Vec<char> = raw.chars().collect();
    let scheme = |i: usize| raw.get(i + 1).is_some_and(|n| !n.is_whitespace());
    let c: Vec<char> = raw
        .iter()
        .enumerate()
        .map(|(i, &c)| match c {
            '/' | '\\' => ' ',
            ':' if scheme(i) => ' ',
            c if c.is_control() || is_bidi(c) => ' ',
            c => c,
        })
        .collect();
    let mut out = String::with_capacity(c.len());
    for (i, &ch) in c.iter().enumerate() {
        let (before, after) = (i.checked_sub(1).and_then(|j| c.get(j)), c.get(i + 1));
        let www = i >= 3 && c[i - 3..i].iter().all(|w| w.eq_ignore_ascii_case(&'w'));
        if DOTS.contains(&ch) && (www || (word(before) && word(after))) {
            out.push_str("[.]");
        } else {
            out.push(ch);
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `mail_safe_text` for a name in a subject or sentence: at most 60 characters.
pub fn mail_safe_name(raw: &str) -> String {
    const MAX: usize = 60;
    let clean = mail_safe_text(raw);
    if clean.chars().count() > MAX {
        format!("{}…", clean.chars().take(MAX - 1).collect::<String>())
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::{mail_safe_name, mail_safe_text, word};

    #[test]
    fn links_cannot_survive() {
        for (raw, want) in [
            (
                "Visit https://evil.example/login",
                "Visit https evil[.]example login",
            ),
            ("www.evil.example", "www[.]evil[.]example"),
            ("WWW. evil", "WWW[.] evil"),
            ("mailto:ceo@evil.example", "mailto ceo@evil[.]example"),
            ("tel:+15550100", "tel +15550100"),
            ("evil.example", "evil[.]example"),
            ("evil\u{3002}example", "evil[.]example"),
            ("\\\\host\\share", "host share"),
            ("a.b.c_d.e", "a[.]b[.]c_d[.]e"),
            (
                "Log group /aws/lambda/api.prod",
                "Log group aws lambda api[.]prod",
            ),
            ("10.0.0.1 costs 12.50", "10[.]0[.]0[.]1 costs 12[.]50"),
        ] {
            assert_eq!(mail_safe_text(raw), want, "{raw}");
        }
    }

    #[test]
    fn ordinary_names_stay_as_written() {
        for name in [
            "Acme Inc.",
            "Dr. No",
            "Urgent: prod",
            "Ann & Co. (EU)",
            "J. R. R. Tolkien",
            "Zoë O'Neil-Smith, Jr.",
            "ops@acme",
            "Wait...",
            "Production #2",
        ] {
            assert_eq!(mail_safe_text(name), name);
        }
    }

    /// Whatever goes in, the result holds the rule (launch-readiness L2).
    #[test]
    fn result_never_holds_a_scheme_path_www_or_domain_dot() {
        let nasty = [
            "http://a.b/c?d=e.f",
            "HTTPS://A.B",
            "x:y:z.w//",
            ".a.b.",
            "www.www.a",
            "wwww.a",
            "a./b",
            "a.:b",
            "a:.b",
            "a\u{202E}.b",
            "a.\nb.c\r\nBcc: x@y.z",
            "ftp://u:p@h.t/p",
            "a..b...c.d",
            "://.//:.",
        ];
        for raw in nasty {
            let s = mail_safe_text(raw);
            let c: Vec<char> = s.chars().collect();
            assert!(
                !s.contains(['/', '\\', '\n', '\r', '\u{202E}']),
                "{raw}: {s}"
            );
            assert!(!s.to_lowercase().contains("www."), "{raw}: {s}");
            for (i, ch) in c.iter().enumerate() {
                let (before, after) = (i.checked_sub(1).and_then(|j| c.get(j)), c.get(i + 1));
                assert!(!(*ch == '.' && word(before) && word(after)), "{raw}: {s}");
                assert!(
                    !(*ch == ':' && after.is_some_and(|n| !n.is_whitespace())),
                    "{raw}: {s}"
                );
            }
            assert_eq!(mail_safe_text(&s), s, "not stable for {raw}");
        }
    }

    #[test]
    fn name_is_capped_and_has_no_control_chars() {
        let n = mail_safe_name(&format!("Evil\r\nBcc: x@y.z\u{202E}{}", "a".repeat(100)));
        assert!(!n.contains(['\r', '\n', '\u{202E}']), "{n}");
        assert_eq!(n.chars().count(), 60);
        assert_eq!(mail_safe_name("  Acme  Ltd "), "Acme Ltd");
    }
}
