//! Organisation use cases.
mod create_org;
mod delete_org;
mod get_org;
mod is_owner_anywhere;
mod list_orgs;
mod scope;
mod update_org;

pub use create_org::{CreateOrg, CreateOrgInput, ORGS_PER_USER_PER_DAY};
pub use delete_org::DeleteOrg;
pub use get_org::GetOrg;
pub use is_owner_anywhere::IsOwnerAnywhere;
pub use list_orgs::ListOrgs;
pub use scope::{OrgScope, ResolveOrgScope};
pub use update_org::UpdateOrg;

use crate::error::{AppError, AppResult};

pub struct Orgs {
    pub resolve_scope: ResolveOrgScope,
    pub create_org: CreateOrg,
    pub list_orgs: ListOrgs,
    pub get_org: GetOrg,
    pub update_org: UpdateOrg,
    pub delete_org: DeleteOrg,
    pub is_owner_anywhere: IsOwnerAnywhere,
}

fn valid_name(raw: &str) -> AppResult<String> {
    opsagent_core::org::valid_name(raw).map_err(|e| AppError::Invalid(e.into()))
}

fn valid_timezone(raw: &str) -> AppResult<String> {
    raw.parse::<chrono_tz::Tz>()
        .map(|_| raw.into())
        .map_err(|_| {
            AppError::Invalid("timezone must be an IANA name such as Europe/Berlin".into())
        })
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use opsagent_core::{
        org::Organisation,
        user::{Email, User, UsersRepo},
    };
    use opsagent_secrets::{EnvKek, Kek};

    use super::{CreateOrg, CreateOrgInput, OrgScope, ResolveOrgScope};
    use crate::adapters::memory::{MemRateLimiter, MemStore};

    pub fn kek() -> Arc<dyn Kek> {
        Arc::new(EnvKek::new([7; 32], 1, None))
    }

    pub async fn user(store: &MemStore, email: &str) -> User {
        let email = Email::parse(email).unwrap();
        store.find_or_create_by_email(&email).await.unwrap()
    }

    pub fn create_org(store: &MemStore) -> CreateOrg {
        CreateOrg::new(
            Arc::new(store.clone()),
            kek(),
            Arc::new(MemRateLimiter::default()),
        )
    }

    /// A new user and the organisation `name` they own.
    pub async fn owned_org(store: &MemStore, email: &str, name: &str) -> (User, Organisation) {
        let owner = user(store, email).await;
        let input = CreateOrgInput {
            user_id: owner.id,
            name: name.into(),
            timezone: "UTC".into(),
        };
        let org = create_org(store).run(input).await.unwrap();
        (owner, org)
    }

    pub async fn scope(store: &MemStore, org: &Organisation, user: &User) -> OrgScope {
        let resolve = ResolveOrgScope::new(Arc::new(store.clone()));
        resolve.run(user.id, &org.slug).await.unwrap()
    }
}
