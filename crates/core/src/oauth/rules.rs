//! Pure OAuth validation rules: redirect URIs, resource indicators, PKCE, consent return paths.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// `(scheme lowercased, authority, rest)` for `scheme://authority rest`; `None` without `//`.
fn split_hier(uri: &str) -> Option<(String, &str, &str)> {
    let (scheme, after) = uri.split_once("://")?;
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    Some((scheme.to_ascii_lowercase(), &after[..end], &after[end..]))
}

/// Host (lowercased, brackets kept for IPv6) and optional port text; `None` if malformed.
fn host_port(authority: &str) -> Option<(String, Option<&str>)> {
    if authority.contains('@') {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']')?;
        let port = match &authority[close + 1..] {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (&authority[..=close], port)
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    (!host.is_empty() && port_ok).then(|| (host.to_ascii_lowercase(), port))
}

fn loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "[::1]" | "localhost")
}

/// `http` on a loopback host: the native-app redirect shape (RFC 8252 section 7.3).
pub fn is_loopback(uri: &str) -> bool {
    split_hier(uri).is_some_and(|(scheme, auth, _)| {
        scheme == "http" && host_port(auth).is_some_and(|(h, _)| loopback_host(&h))
    })
}

/// Registration-time check of a redirect URI.
pub fn redirect_uri_allowed(registered: &str) -> bool {
    if registered.contains('#')
        || registered
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    if let Some((scheme, auth, _)) = split_hier(registered) {
        match scheme.as_str() {
            "https" => return host_port(auth).is_some(),
            "http" => return is_loopback(registered),
            _ => {}
        }
    }
    let Some((scheme, _)) = registered.split_once(':') else {
        return false;
    };
    let scheme = scheme.to_ascii_lowercase();
    let valid = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'));
    // `javascript`, `data` and `file` have no dot and are not allow-listed, so they fall out.
    valid && (scheme.contains('.') || matches!(scheme.as_str(), "cursor" | "vscode"))
}

/// Loopback redirects match ignoring the port; everything else is an exact string match.
pub fn redirect_uri_matches(registered: &str, presented: &str) -> bool {
    if is_loopback(registered) && is_loopback(presented) {
        let (Some((s1, a1, r1)), Some((s2, a2, r2))) =
            (split_hier(registered), split_hier(presented))
        else {
            return false;
        };
        let host = |a| host_port(a).map(|(h, _)| h);
        return s1 == s2 && host(a1) == host(a2) && r1 == r2;
    }
    registered == presented
}

/// RFC 8707 resource: trailing slash and host case ignored; scheme, port and path otherwise exact.
pub fn resource_matches(expected: &str, presented: &str) -> bool {
    let norm = |u: &str| {
        let (scheme, auth, rest) = split_hier(u)?;
        let (host, port) = host_port(auth)?;
        let path = rest.strip_suffix('/').unwrap_or(rest);
        Some((scheme, host, port.map(str::to_owned), path.to_owned()))
    };
    matches!((norm(expected), norm(presented)), (Some(a), Some(b)) if a == b)
}

/// RFC 7636 S256: the verifier is 43-128 unreserved characters and hashes to the challenge.
pub fn pkce_s256_matches(challenge: &str, verifier: &str) -> bool {
    let shape = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    shape && URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge
}

/// The only post-login destination allowed: `/oauth/consent?request_id=<uuid>`, nothing else.
pub fn consent_return_to(raw: &str) -> Option<String> {
    let id = raw.strip_prefix("/oauth/consent?request_id=")?;
    // 36 chars forces the hyphenated form; `parse_str` also accepts braced and URN forms.
    if id.len() != 36 {
        return None;
    }
    let id = Uuid::parse_str(id).ok()?;
    Some(format!("/oauth/consent?request_id={id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_any_port_https_exact() {
        assert!(redirect_uri_matches(
            "http://127.0.0.1:53121/callback",
            "http://127.0.0.1:60000/callback"
        ));
        assert!(!redirect_uri_matches(
            "http://127.0.0.1:53121/callback",
            "http://127.0.0.1:60000/other"
        ));
        assert!(!redirect_uri_matches(
            "http://127.0.0.1:1/cb",
            "http://localhost:1/cb"
        ));
        assert!(!redirect_uri_matches(
            "https://a.example/cb",
            "https://a.example:8443/cb"
        ));
        assert!(redirect_uri_matches(
            "https://a.example/cb",
            "https://a.example/cb"
        ));
    }

    #[test]
    fn rejects_dangerous_schemes() {
        for u in [
            "javascript:alert(1)",
            "data:text/html,x",
            "file:///etc/passwd",
            "http://evil.example/cb",
            "https://a.example/cb#frag",
            "https://user@a.example/cb",
            "",
        ] {
            assert!(!redirect_uri_allowed(u), "{u}");
        }
        for u in [
            "https://a.example/cb",
            "http://[::1]:7/cb",
            "http://localhost/cb",
        ] {
            assert!(redirect_uri_allowed(u), "{u}");
        }
    }

    #[test]
    fn accepts_private_use() {
        assert!(redirect_uri_allowed(
            "cursor://anysphere.cursor-retrieval/oauth/callback"
        ));
        assert!(redirect_uri_allowed("com.example.app:/cb"));
        assert!(redirect_uri_allowed("vscode://x/cb"));
        assert!(!redirect_uri_allowed("myapp://cb"));
    }

    #[test]
    fn resource_trailing_slash_and_case() {
        let e = "https://brain.opsagent.dev/mcp";
        assert!(resource_matches(e, "https://Brain.OpsAgent.dev/mcp/"));
        assert!(resource_matches(e, e));
        assert!(!resource_matches(e, "https://brain.opsagent.dev/mcpx"));
        assert!(!resource_matches(e, "https://brain.opsagent.dev:8443/mcp"));
        assert!(!resource_matches(e, "http://brain.opsagent.dev/mcp"));
        assert!(!resource_matches(e, "https://brain.opsagent.dev/MCP"));
    }

    #[test]
    fn pkce_rfc7636_vector() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let c = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_s256_matches(c, v));
        assert!(!pkce_s256_matches(c, &v.replace('d', "e")));
        assert!(!pkce_s256_matches(c, &v[..42]));
    }

    #[test]
    fn return_to_only_consent_shape() {
        let id = "0192f3a4-7b1c-7d2e-8f3a-4b5c6d7e8f90";
        let ok = format!("/oauth/consent?request_id={id}");
        assert_eq!(consent_return_to(&ok).as_deref(), Some(ok.as_str()));
        for bad in [
            "//evil.example".to_string(),
            "/\\evil.example".to_string(),
            format!("{ok}&x=1"),
            "/oauth/consent?request_id=not-a-uuid".to_string(),
            format!("{ok}\t"),
            format!("/oauth/consent?request_id={{{id}}}"),
        ] {
            assert_eq!(consent_return_to(&bad), None, "{bad}");
        }
    }
}
