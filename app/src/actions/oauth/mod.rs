//! OAuth use cases (nothing here names MCP; the resource URL comes from config).
mod decide_consent;
mod get_consent;
mod register_client;
mod resolve_client;
mod start_authorization;

pub use decide_consent::{DecideConsent, Decision};
pub use get_consent::{ConsentView, GetConsent};
pub use register_client::{RegisterClient, RegistrationRequest};
pub use resolve_client::ResolveClient;
pub use start_authorization::{AuthorizeError, AuthorizeParams, StartAuthorization};

pub const CONSENT_TTL_SECS: i64 = 600;
pub const CODE_TTL_SECS: i64 = 60;

pub struct OAuth {
    pub register_client: RegisterClient,
    pub resolve_client: ResolveClient,
    pub start_authorization: StartAuthorization,
    pub get_consent: GetConsent,
    pub decide_consent: DecideConsent,
}

/// `redirect_uri` with the present `pairs` and `iss` (RFC 9207) appended to its query.
pub fn redirect_with(redirect_uri: &str, pairs: &[(&str, Option<&str>)], iss: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(redirect_uri) else {
        // Registered URIs are validated, so this is unreachable in practice.
        return redirect_uri.to_owned();
    };
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in pairs {
            if let Some(v) = v {
                q.append_pair(k, v);
            }
        }
        q.append_pair("iss", iss);
    }
    url.into()
}

#[cfg(test)]
mod tests {
    use super::redirect_with;

    #[test]
    fn redirect_keeps_existing_query_and_encodes() {
        let u = redirect_with(
            "https://a.example/cb?x=1",
            &[("state", Some("a b&c")), ("code", None)],
            "https://brain.example",
        );
        assert_eq!(
            u,
            "https://a.example/cb?x=1&state=a+b%26c&iss=https%3A%2F%2Fbrain.example"
        );
    }
}
