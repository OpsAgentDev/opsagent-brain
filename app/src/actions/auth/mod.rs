//! Sign-in use cases. Session, CSRF and OAuth state stay in the controller (transport).
mod accept_terms;
mod confirm_email_change;
mod current_user;
mod delete_account;
mod passkeys;
mod redeem_magic_link;
mod request_email_change;
mod request_magic_link;
mod sign_in_github;
mod sign_in_google;
mod update_marketing_ok;
mod update_name;
mod verify_code;

pub use accept_terms::AcceptTerms;
pub use confirm_email_change::ConfirmEmailChange;
pub use current_user::CurrentUser;
pub use delete_account::DeleteAccount;
pub(crate) use passkeys::passkey_invalid;
pub use passkeys::Passkeys;
pub use redeem_magic_link::RedeemMagicLink;
pub use request_email_change::RequestEmailChange;
pub use request_magic_link::{MagicLinkInput, RequestMagicLink, PER_EMAIL, PER_IP};
pub use sign_in_github::{GithubProfile, SignInGithub};
pub use sign_in_google::{GoogleProfile, SignInGoogle};
pub use update_marketing_ok::UpdateMarketingOk;
pub use update_name::UpdateName;
pub use verify_code::{VerifyCode, VerifyCodeInput};

pub struct Auth {
    pub request_magic_link: RequestMagicLink,
    pub redeem_magic_link: RedeemMagicLink,
    pub verify_code: VerifyCode,
    pub sign_in_github: SignInGithub,
    pub sign_in_google: SignInGoogle,
    pub current_user: CurrentUser,
    pub accept_terms: AcceptTerms,
    pub update_name: UpdateName,
    pub update_marketing_ok: UpdateMarketingOk,
    pub request_email_change: RequestEmailChange,
    pub confirm_email_change: ConfirmEmailChange,
    pub delete_account: DeleteAccount,
    pub passkeys: Passkeys,
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
    pub const SECRET: &str = "test-session-secret";

    pub fn request_link(store: &MemStore, mail: &Arc<CaptureMailer>) -> RequestMagicLink {
        RequestMagicLink::new(
            Arc::new(store.clone()),
            (Arc::new(MemRateLimiter::default()), 1000),
            mail.clone(),
            WEB.into(),
            Arc::new(SystemClock),
            SECRET.into(),
            Default::default(),
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
        assert_eq!(
            entries[0].actor,
            opsagent_core::audit::Actor::Member(user_id)
        );
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

    /// The 6-digit code in the last mail's subject.
    pub fn last_code(mail: &CaptureMailer) -> String {
        let m = mail.sent().pop().expect("no mail sent");
        m.subject.rsplit(' ').next().expect("no code").to_owned()
    }
}
