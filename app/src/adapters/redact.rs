//! Redacts secret-shaped strings from evidence before storage (PRD 7.4).
use std::sync::LazyLock;

use regex::Regex;

static RULES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (
            r"-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY( BLOCK)?-----|$)",
            "[redacted:private_key]",
        ),
        (r"\bA(KIA|SIA)[0-9A-Z]{16}\b", "[redacted:aws_key_id]"),
        (
            r#"(?i)(["']?(aws_secret_access_key|secretaccesskey|secret_access_key)["']?\s*[:=]\s*["']?)[A-Za-z0-9/+=]{40}"#,
            "${1}[redacted:aws_secret]",
        ),
        (r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+", "${1}[redacted:token]"),
        // Greedy up to the last `@` before the path, so passwords containing `@` are covered.
        (
            r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/]*@",
            "${1}[redacted:userinfo]@",
        ),
        (
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "[redacted:email]",
        ),
        (
            r#"(?i)(\b(secret|password|passwd|token|api[_-]?key)\b["']?\s*[:=]\s*["']?)[^\s"']{8,}"#,
            "${1}[redacted:secret]",
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

/// A resource as stored: its tag values and name redacted, as evidence is. Tags and names are
/// written by anyone with tagging rights in the customer's account and shown to every member.
pub fn redact_resource(r: &opsagent_core::resource::Resource) -> opsagent_core::resource::Resource {
    let mut out = r.clone();
    out.name = redact(&r.name).0;
    out.tags.clear();
    for (k, v) in &r.tags {
        let key = redact(k).0;
        // Decided on the key: the evidence rule misses `db_password`, spaces and short values.
        let value = if sensitive_key(k) {
            "[redacted:secret]".to_owned()
        } else {
            redact(v).0
        };
        // Two keys can redact to the same text; keep both values.
        let mut slot = key.clone();
        let mut n = 2;
        while out.tags.contains_key(&slot) {
            slot = format!("{key} #{n}");
            n += 1;
        }
        out.tags.insert(slot, value);
    }
    out
}

/// A tag key whose value is a credential by name, whatever the value looks like.
fn sensitive_key(k: &str) -> bool {
    let k: String = k
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();
    [
        "secret",
        "password",
        "passwd",
        "pwd",
        "token",
        "apikey",
        "privatekey",
        "credential",
        "auth",
    ]
    .iter()
    .any(|w| k.contains(w))
}

#[cfg(test)]
mod tests {
    use super::{redact, redact_resource};

    #[test]
    fn redacts_tags_with_their_keys_and_the_name() {
        let r = opsagent_core::resource::Resource {
            provider: opsagent_core::resource::Provider::Fake,
            account: "1".into(),
            region: "r".into(),
            kind: opsagent_core::resource::ResourceKind::Compute,
            identity: "i-1".into(),
            name: "db password=hunter2hunter2".into(),
            tags: [
                ("env".into(), "prod".into()),
                ("deploy_key".into(), "AKIAIOSFODNN7EXAMPLE".into()),
                ("password".into(), "hunter2hunter2".into()),
                ("db_password".into(), "short".into()),
                ("API-Key".into(), "two words".into()),
                ("team".into(), "payments".into()),
                ("AKIAIOSFODNN7EXAMPLE".into(), "a".into()),
                ("AKIAIOSFODNN8EXAMPLE".into(), "b".into()),
            ]
            .into(),
            attributes: serde_json::json!({}),
            observed_at: "2026-11-17T00:00:00Z".parse().unwrap(),
        };
        let s = redact_resource(&r);
        assert_eq!(s.tags["env"], "prod");
        assert_eq!(s.tags["deploy_key"], "[redacted:aws_key_id]");
        assert_eq!(s.tags["password"], "[redacted:secret]");
        assert_eq!(s.tags["db_password"], "[redacted:secret]");
        assert_eq!(s.tags["API-Key"], "[redacted:secret]");
        assert_eq!(s.tags["team"], "payments");
        // A key that is itself a secret is redacted, and a clash keeps both values.
        let mut clashed = [
            &s.tags["[redacted:aws_key_id]"],
            &s.tags["[redacted:aws_key_id] #2"],
        ];
        clashed.sort();
        assert_eq!(clashed, [&"a".to_string(), &"b".to_string()]);
        assert_eq!(s.tags.len(), 8);
        assert_eq!(s.name, "db password=[redacted:secret]");
        assert_eq!((s.identity, s.attributes), (r.identity, r.attributes));
    }

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

    #[test]
    fn redacts_quoted_userinfo_pgp_and_generic_values() {
        let cases = [
            (
                r#"{"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}"#,
                r#"{"SecretAccessKey": "[redacted:aws_secret]"}"#,
            ),
            (
                r#"'aws_secret_access_key' : 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"#,
                r#"'aws_secret_access_key' : '[redacted:aws_secret]'"#,
            ),
            (
                "postgres://admin:p@ss@word@db.internal:5432/app",
                "postgres://[redacted:userinfo]@db.internal:5432/app",
            ),
            (
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK----- x",
                "[redacted:private_key] x",
            ),
            ("password=hunter2hunter2 next", "password=[redacted:secret] next"),
            (r#""api_key": "abcd1234efgh""#, r#""api_key": "[redacted:secret]""#),
            ("TOKEN: s3cr3tvalue!", "TOKEN: [redacted:secret]"),
        ];
        for (input, want) in cases {
            assert_eq!(redact(input), (want.to_owned(), true), "{input}");
        }
    }

    #[test]
    fn leaves_ordinary_token_text_alone() {
        for t in [
            "rotate the token before Friday",
            "token: short",
            "the api key policy",
        ] {
            assert_eq!(redact(t), (t.to_owned(), false), "{t}");
        }
    }
}
