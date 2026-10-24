//! Sign-in use cases. Session, CSRF and OAuth state stay in the controller (transport).
mod current_user;
mod redeem_magic_link;
mod request_magic_link;
mod sign_in_github;

pub use current_user::CurrentUser;
pub use redeem_magic_link::RedeemMagicLink;
pub use request_magic_link::{MagicLinkInput, RequestMagicLink, PER_EMAIL, PER_IP};
pub use sign_in_github::{GithubProfile, SignInGithub};

pub struct Auth {
    pub request_magic_link: RequestMagicLink,
    pub redeem_magic_link: RedeemMagicLink,
    pub sign_in_github: SignInGithub,
    pub current_user: CurrentUser,
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use opsagent_core::repo::SystemClock;

    use super::RequestMagicLink;
    use crate::{
        adapters::memory::{MemRateLimiter, MemStore},
        mailers::CaptureMailer,
    };

    pub const WEB: &str = "https://web.test";

    pub fn request_link(store: &MemStore, mail: &Arc<CaptureMailer>) -> RequestMagicLink {
        RequestMagicLink::new(
            Arc::new(store.clone()),
            Arc::new(MemRateLimiter::default()),
            mail.clone(),
            WEB.into(),
            Arc::new(SystemClock),
        )
    }

    /// Exactly one `auth.sign_in` entry, by and about `user_id`.
    pub fn assert_one_sign_in(store: &MemStore, user_id: uuid::Uuid) {
        let entries: Vec<_> = store
            .audit_entries()
            .into_iter()
            .filter(|e| e.action == "auth.sign_in")
            .collect();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].actor, Some(user_id));
        assert_eq!(entries[0].target, Some(("user", user_id.to_string())));
    }

    /// The token in the last mailed link.
    pub fn last_token(mail: &CaptureMailer) -> String {
        let m = mail.sent().pop().expect("no mail sent");
        m.text
            .split_whitespace()
            .find_map(|w| w.split_once("token=").map(|(_, t)| t.to_owned()))
            .expect("no token in mail")
    }
}
