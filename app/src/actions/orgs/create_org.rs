use std::sync::Arc;

use opsagent_core::{
    audit::AuditEntry,
    org::{slugify, NewOrganisation, Organisation, Role},
    repo::RepoError,
};
use opsagent_secrets::{generate_dek, Kek};
use rand::RngCore;
use uuid::Uuid;

use super::{valid_name, valid_timezone};
use crate::{
    actions::{uow::UnitOfWork, RateLimiter, DAY_SECS},
    error::{AppError, AppResult},
};

/// Organisations a user may create per day (each gets a DEK, and owners can send mail).
pub const ORGS_PER_USER_PER_DAY: i64 = 5;

pub struct CreateOrgInput {
    pub user_id: Uuid,
    pub name: String,
    /// IANA zone.
    pub timezone: String,
}

/// Creates an organisation with a fresh wrapped DEK and makes the user its owner.
pub struct CreateOrg {
    uow: Arc<dyn UnitOfWork>,
    kek: Arc<dyn Kek>,
    limiter: Arc<dyn RateLimiter>,
}

impl CreateOrg {
    pub fn new(uow: Arc<dyn UnitOfWork>, kek: Arc<dyn Kek>, limiter: Arc<dyn RateLimiter>) -> Self {
        Self { uow, kek, limiter }
    }

    pub async fn run(&self, input: CreateOrgInput) -> AppResult<Organisation> {
        let name = valid_name(&input.name)?;
        let timezone = valid_timezone(&input.timezone)?;
        self.limit(input.user_id).await?;
        let id = Uuid::new_v4();
        let internal = |e: &dyn std::fmt::Display| AppError::Internal(e.to_string());
        let wrapped = self
            .kek
            .wrap(id, &generate_dek())
            .map_err(|e| internal(&e))?;
        let mut new = NewOrganisation {
            id,
            slug: slugify(&name),
            name,
            timezone,
            kek_version: i32::try_from(wrapped.version).map_err(|e| internal(&e))?,
            wrapped_dek: wrapped.blob,
        };
        let tx = self.uow.begin().await?;
        let org = match tx.orgs().insert(new.clone()).await {
            Err(RepoError::Conflict("slug")) => {
                new.slug = suffixed(&new.slug);
                // A second collision is not a client error (the route documents no 409): 500.
                tx.orgs().insert(new).await.map_err(|e| internal(&e))?
            }
            other => other?,
        };
        tx.orgs().add_member(id, input.user_id, Role::Owner).await?;
        let target = Some(("organisation", id.to_string()));
        let entry = AuditEntry::member(Some(id), input.user_id, "org.create", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(org)
    }

    /// Counts one creation; `RateLimited` past the daily cap. Fails closed.
    async fn limit(&self, user_id: Uuid) -> AppResult<()> {
        let key = format!("ratelimit:org_create:user:{user_id}");
        if self
            .limiter
            .hit(&key, ORGS_PER_USER_PER_DAY, DAY_SECS)
            .await?
        {
            return Ok(());
        }
        // shortcut: Retry-After is the window length, an upper bound; read the key TTL if exactness matters.
        Err(AppError::RateLimited {
            detail: "At most 5 organisations can be created per day.".into(),
            retry_after_secs: DAY_SECS.unsigned_abs(),
        })
    }
}

/// `slug` with a random 6-hex suffix, for a name whose slug is taken.
fn suffixed(slug: &str) -> String {
    let mut b = [0u8; 3];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{slug}-{:02x}{:02x}{:02x}", b[0], b[1], b[2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{actions::orgs::test_support::*, adapters::memory::MemStore};

    #[tokio::test]
    async fn create_org_duplicate_name_gets_suffixed_slug() {
        let store = MemStore::default();
        let (owner, first) = owned_org(&store, "a@example.com", "Acme Ltd").await;
        assert_eq!(first.slug, "acme-ltd");
        let input = CreateOrgInput {
            user_id: owner.id,
            name: "Acme Ltd".into(),
            timezone: "Europe/Berlin".into(),
        };
        let second = create_org(&store).run(input).await.unwrap();
        let suffix = second.slug.strip_prefix("acme-ltd-").expect(&second.slug);
        assert_eq!(suffix.len(), 6);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "{suffix}");
        assert_eq!(second.timezone, "Europe/Berlin");
        // Each gets its owner and its audit row.
        let scope = scope(&store, &second, &owner).await;
        scope.require_owner().unwrap();
        let created = store.audit_entries();
        assert_eq!(
            created.iter().filter(|e| e.action == "org.create").count(),
            2
        );
    }
}
