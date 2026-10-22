//! Redacts secret-shaped strings from evidence before storage (PRD 7.4).
use std::sync::LazyLock;

use regex::Regex;

static RULES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
            "[redacted:private_key]",
        ),
        (r"\bA(KIA|SIA)[0-9A-Z]{16}\b", "[redacted:aws_key_id]"),
        (
            r"(?i)(aws_secret_access_key[\s:=]+)[A-Za-z0-9/+=]{40}",
            "${1}[redacted:aws_secret]",
        ),
        (
            r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+",
            "${1}[redacted:token]",
        ),
        (
            r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s:/@]+:[^\s@/]+@",
            "${1}[redacted:userinfo]@",
        ),
        (
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "[redacted:email]",
        ),
    ]
    .into_iter()
    .map(|(p, r)| (Regex::new(p).expect("redaction regex"), r))
    .collect()
});

/// The redacted text and whether anything was replaced.
pub fn redact(text: &str) -> (String, bool) {
    let mut out = text.to_owned();
    for (re, rep) in RULES.iter() {
        if re.is_match(&out) {
            out = re.replace_all(&out, *rep).into_owned();
        }
    }
    let changed = out != text;
    (out, changed)
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn redacts_secret_shapes() {
        let cases = [
            (
                "key AKIAIOSFODNN7EXAMPLE used",
                "key [redacted:aws_key_id] used",
            ),
            (
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_secret_access_key = [redacted:aws_secret]",
            ),
            (
                "Authorization: Bearer eyJhbGciOi.x-y_z",
                "Authorization: Bearer [redacted:token]",
            ),
            (
                "url=postgres://admin:hunter2@db.internal:5432/app",
                "url=postgres://[redacted:userinfo]@db.internal:5432/app",
            ),
            ("owner ops@example.com", "owner [redacted:email]"),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY----- tail",
                "[redacted:private_key] tail",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), (want.to_owned(), true), "{input}");
        }
        assert_eq!(
            redact("state=running cpu=2"),
            ("state=running cpu=2".into(), false)
        );
    }
}
