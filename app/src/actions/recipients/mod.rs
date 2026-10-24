//! Email recipients of deliveries (PRD 7, delivery.md): owner adds (an email confirms by link, a
//! member is active at once), public confirm by single-use token (SHA-256 at rest), and
//! unsubscribe by a stable HMAC token. `MailGuard` decides whether any mail may go out.
mod confirm_recipient;
mod create_recipient;
mod delete_recipient;
mod list_recipients;
pub mod mail_guard;
pub mod tokens;
mod unsubscribe;

use std::sync::Arc;

pub use confirm_recipient::ConfirmRecipient;
pub use create_recipient::{CreateRecipient, NewRecipient};
pub use delete_recipient::DeleteRecipient;
pub use list_recipients::ListRecipients;
pub use mail_guard::MailGuard;
pub use unsubscribe::Unsubscribe;

pub struct Recipients {
    pub list_recipients: ListRecipients,
    pub create_recipient: CreateRecipient,
    pub delete_recipient: DeleteRecipient,
    pub confirm_recipient: ConfirmRecipient,
    pub unsubscribe: Unsubscribe,
    /// Shared with the delivery workers.
    pub mail_guard: Arc<MailGuard>,
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use opsagent_core::{
        org::{Member, NewOrganisation, OrganisationsRepo, Role},
        repo::{PageRequest, SystemClock},
        user::{Email, UsersRepo},
    };
    use opsagent_secrets::{generate_dek, EnvKek, Kek};
    use uuid::Uuid;

    use super::{CreateRecipient, MailGuard};
    use crate::{
        adapters::memory::{MemRateLimiter, MemStore},
        mailers::CaptureMailer,
    };

    pub const PAGE: PageRequest = PageRequest {
        after: None,
        limit: 50,
    };

    pub fn kek() -> EnvKek {
        EnvKek::new([7; 32], 1, None)
    }

    /// A live organisation with a DEK wrapped by `kek()`.
    pub async fn org(store: &MemStore, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        let wrapped = kek().wrap(id, &generate_dek()).unwrap();
        let new = NewOrganisation {
            id,
            slug: format!("o-{}", id.simple()),
            name: name.into(),
            timezone: "UTC".into(),
            kek_version: wrapped.version as i32,
            wrapped_dek: wrapped.blob,
        };
        store.insert(new).await.unwrap().id
    }

    pub async fn member(store: &MemStore, org: Uuid, email: &str, role: Role) -> Member {
        let email = Email::parse(email).unwrap();
        let user = store.find_or_create_by_email(&email).await.unwrap();
        store.add_member(org, user.id, role).await.unwrap()
    }

    pub fn guard(store: &MemStore) -> Arc<MailGuard> {
        let limiter = Arc::new(MemRateLimiter::default());
        Arc::new(MailGuard::new(Arc::new(store.clone()), limiter))
    }

    pub fn create(store: &MemStore, mail: &Arc<CaptureMailer>) -> CreateRecipient {
        let uow = Arc::new(store.clone());
        let clock = Arc::new(SystemClock);
        CreateRecipient::new(uow, guard(store), mail.clone(), "https://web.test/", clock)
    }
}
