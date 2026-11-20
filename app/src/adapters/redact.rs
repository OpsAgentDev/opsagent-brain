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
        // Unlabelled tokens, by their issuer's shape: GitHub, Slack, Stripe, Google, JWT.
        (
            r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|x(ox[abeprs]|app)-[0-9]+-[A-Za-z0-9-]{8,}|(sk|rk)_(live|test)_[A-Za-z0-9]{10,}|whsec_[A-Za-z0-9]{10,}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)",
            "[redacted:token]",
        ),
        // Greedy up to the last `@` before the path, so passwords containing `@` are covered.
        (
            r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/]*@",
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

/// A value after a name that is or ends in one of these words (`DB_PASSWORD`, `PGPASSWORD`,
/// `client_secret`, `GITHUB_TOKEN`, `signing_key`). A bare `key` is an object key or a tag key,
/// so `key` counts only after an underscore or as `api key`. Runs last: see `redact`.
static LABELLED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(\b[a-z0-9_]*(secret|password|passwd|token|api[_-]?key|_key)\b["']?\s*[:=]\s*["']?)([^\s"']{8,})"#,
    )
    .expect("redaction regex")
});

/// Exactly a label an earlier rule wrote, nothing before or after it.
fn is_label(value: &str) -> bool {
    value
        .strip_prefix("[redacted:")
        .and_then(|v| v.strip_suffix(']'))
        .is_some_and(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
}

/// The redacted text and whether anything was replaced.
pub fn redact(text: &str) -> (String, bool) {
    let mut out = text.to_owned();
    for (re, rep) in RULES.iter() {
        if re.is_match(&out) {
            out = re.replace_all(&out, *rep).into_owned();
        }
    }
    // A value that is exactly an earlier label keeps it; anything else after the name goes,
    // including one that merely starts with `[` or has text around a label.
    if LABELLED.is_match(&out) {
        out = LABELLED
            .replace_all(&out, |c: &regex::Captures<'_>| {
                if is_label(&c[3]) {
                    c[0].to_owned()
                } else {
                    format!("{}[redacted:secret]", &c[1])
                }
            })
            .into_owned();
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

/// Audit metadata as shown to a customer: fields named like a credential (`sensitive_key`) or
/// naming a session or a network address are left out, and every string is redacted.
pub fn redact_json(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    const NEVER: [&str; 3] = ["session_id", "ip", "user_agent"];
    match v {
        Value::String(s) => Value::String(redact(s).0),
        Value::Array(a) => Value::Array(a.iter().map(redact_json).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .filter(|(k, _)| !sensitive_key(k) && !NEVER.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), redact_json(v)))
                .collect(),
        ),
        other => other.clone(),
    }
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
    use super::{redact, redact_json, redact_resource};

    #[test]
    fn redact_json_drops_secret_named_fields_and_redacts_strings() {
        let v = serde_json::json!({
            "scope": "opsagent.read",
            "access_token": "abc",
            "session_id": "s-1",
            "ip": "203.0.113.9",
            "nested": { "client_secret": "x", "note": "key AKIAIOSFODNN7EXAMPLE used", "n": 2 },
            "list": ["Bearer abc.def", 1],
        });
        assert_eq!(
            redact_json(&v),
            serde_json::json!({
                "scope": "opsagent.read",
                "nested": { "note": "key [redacted:aws_key_id] used", "n": 2 },
                "list": ["Bearer [redacted:token]", 1],
            })
        );
    }

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
    fn redacts_values_of_names_ending_in_a_secret_word() {
        // Assembled here so no line of this file reads as a credential to a secret scanner.
        let v = "hunter2hunter2";
        for (before, after) in [
            ("DB_PASSWORD=", " x"),
            ("PGPASSWORD=", ""),
            ("MYSQL_ROOT_PASSWORD: '", "'"),
            ("client_secret=", ""),
            (r#"{"OAUTH_CLIENT_SECRET": ""#, r#""}"#),
            ("NPM_TOKEN=", ""),
            ("SIGNING_KEY = ", ""),
            ("export SESSION_SECRET=", ""),
        ] {
            let want = format!("{before}[redacted:secret]{after}");
            let input = format!("{before}{v}{after}");
            assert_eq!(redact(&input), (want, true), "{input}");
        }
    }

    #[test]
    fn redacts_unlabelled_vendor_tokens_and_jwts() {
        // Prefix and body are joined here, for the same reason.
        let (a36, a24) = ("a1B2".repeat(9), "a1B2".repeat(6));
        let (head, body) = ("eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0");
        let tokens = [
            ("ghp_", a36.clone()),
            ("ghs_", a36.clone()),
            ("github_pat_", format!("{a24}_{a36}")),
            ("xoxb-", format!("123456789012-123456789012-{a24}")),
            ("xoxp-", format!("123456789012-{a24}")),
            ("xapp-", format!("1-A0123456789-{a24}")),
            ("sk_live_", a24.clone()),
            ("rk_test_", a24.clone()),
            ("whsec_", a24.clone()),
            ("AIza", "aB3_-".repeat(7)),
            ("ya29.", a36.clone()),
            (head, format!(".{body}.dBjftJeZ4CVP-mB92K27uhbUJU1p")),
            (head, format!(".{body}.")),
        ];
        for (prefix, rest) in tokens {
            let (out, changed) = redact(&format!("found {prefix}{rest} in user data"));
            assert_eq!(out, "found [redacted:token] in user data", "{prefix}");
            assert!(changed);
        }
    }

    #[test]
    fn leaves_ordinary_token_text_alone() {
        for t in [
            "rotate the token before Friday",
            "token: short",
            "the api key policy",
            // Not credentials: object and tag keys, short values, look-alike words.
            "Key: terraform/prod.tfstate",
            r#"{"Key": "Environment", "Value": "production"}"#,
            "monkey=bananas-and-more",
            "DB_PASSWORD=short",
            "kms_key_id=alias/aws/ebs",
            "task_live_migration and sk_test mode",
            "ghp_short xoxo-gossip-girl-fans AIzaShort eyJ.is.base64",
            "pk_live_a1B2a1B2a1B2a1B2a1B2a1B2",
            "state=running cpu=2 next_page=abcdefghijkl",
        ] {
            assert_eq!(redact(t), (t.to_owned(), false), "{t}");
        }
    }

    #[test]
    fn a_labelled_value_starting_with_a_bracket_is_still_redacted() {
        for (before, after) in [
            ("password=[hunter2hunter2", "password=[redacted:secret]"),
            ("DB_PASSWORD=[abc]defghijk", "DB_PASSWORD=[redacted:secret]"),
            (
                "token=[redacted:token]tail-of-the-secret",
                "token=[redacted:secret]",
            ),
            (
                "GITHUB_TOKEN=[redacted:token]",
                "GITHUB_TOKEN=[redacted:token]",
            ),
        ] {
            assert_eq!(redact(before).0, after, "{before}");
        }
    }
}
