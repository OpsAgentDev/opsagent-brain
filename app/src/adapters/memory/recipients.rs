use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    org::{OrganisationsRepo, Role},
    repo::{PageOf, PageRequest, RepoError, RepoResult},
};
use opsagent_deliver::{
    repo::{
        NewRecipient, RecipientRow, RecipientsRepo, Suppression, ACTIVE, PENDING, SUPPRESSION_DAYS,
    },
    route::Recipient,
};
use uuid::Uuid;

use super::{page, MemRecipient, MemStore, SuppressionRow};

#[async_trait]
impl RecipientsRepo for MemStore {
    async fn list(
        &self,
        organisation_id: Uuid,
        req: PageRequest,
    ) -> RepoResult<PageOf<RecipientRow>> {
        let s = self.state();
        let rows = s.recipients.iter().map(|r| r.row.clone());
        let mine = rows
            .filter(|r| r.organisation_id == organisation_id)
            .collect();
        Ok(page(mine, |r| (r.created_at.fixed_offset(), r.id), req))
    }

    async fn insert(&self, organisation_id: Uuid, new: NewRecipient) -> RepoResult<RecipientRow> {
        let mut s = self.state();
        let taken = s.recipients.iter().any(|r| {
            let same = (
                r.row.organisation_id,
                r.row.connection_id,
                r.row.email.as_str(),
            ) == (organisation_id, new.connection_id, new.email.as_str());
            let token = |c: &Option<(String, _)>| c.as_ref().map(|c| c.0.clone());
            same || (new.confirm.is_some() && token(&r.confirm) == token(&new.confirm))
        });
        if taken {
            return Err(RepoError::Conflict("recipient"));
        }
        let row = RecipientRow {
            id: Uuid::new_v4(),
            organisation_id,
            connection_id: new.connection_id,
            email: new.email,
            member_id: new.member_id,
            status: if new.confirm.is_some() {
                PENDING
            } else {
                ACTIVE
            }
            .into(),
            unsubscribed_at: None,
            created_at: Utc::now(),
        };
        s.recipients.push(MemRecipient {
            row: row.clone(),
            confirm: new.confirm,
        });
        Ok(row)
    }

    async fn delete(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<bool> {
        let mut s = self.state();
        let before = s.recipients.len();
        s.recipients
            .retain(|r| (r.row.organisation_id, r.row.id) != (organisation_id, id));
        Ok(s.recipients.len() < before)
    }

    async fn confirm(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<RecipientRow>> {
        let mut s = self.state();
        let found = s.recipients.iter_mut().find(|r| {
            r.row.status == PENDING
                && r.confirm
                    .as_ref()
                    .is_some_and(|(h, exp)| h == token_hash && *exp > now)
        });
        Ok(found.map(|r| {
            r.confirm = None;
            r.row.status = ACTIVE.into();
            r.row.clone()
        }))
    }

    async fn by_id_unscoped(&self, id: Uuid) -> RepoResult<Option<RecipientRow>> {
        let s = self.state();
        Ok(s.recipients
            .iter()
            .find(|r| r.row.id == id)
            .map(|r| r.row.clone()))
    }

    async fn unsubscribe(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        at: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let mut s = self.state();
        let found = s.recipients.iter_mut().find(|r| {
            (r.row.organisation_id, r.row.id) == (organisation_id, id)
                && r.row.unsubscribed_at.is_none()
        });
        Ok(found.map(|r| r.row.unsubscribed_at = Some(at)).is_some())
    }

    async fn for_connection(
        &self,
        organisation_id: Uuid,
        connection_id: Option<Uuid>,
    ) -> RepoResult<Vec<Recipient>> {
        let s = self.state();
        let mut rows: Vec<&RecipientRow> = s
            .recipients
            .iter()
            .map(|r| &r.row)
            .filter(|r| {
                (r.organisation_id, r.connection_id) == (organisation_id, connection_id)
                    && r.status == ACTIVE
                    && r.unsubscribed_at.is_none()
            })
            .collect();
        rows.sort_by_key(|r| r.created_at);
        Ok(rows
            .into_iter()
            .map(|r| Recipient {
                id: r.id,
                email: r.email.to_lowercase(),
                member: r.member_id.is_some(),
            })
            .collect())
    }

    async fn owners(&self, organisation_id: Uuid) -> RepoResult<Vec<Recipient>> {
        let mut owners = self.members(organisation_id).await?;
        owners.retain(|m| m.role == Role::Owner);
        owners.sort_by_key(|m| m.created_at);
        Ok(owners
            .into_iter()
            .map(|m| Recipient {
                id: m.user_id,
                email: m.email.as_str().to_lowercase(),
                member: true,
            })
            .collect())
    }

    async fn suppress(
        &self,
        organisation_id: Option<Uuid>,
        email_hash: &str,
        kind: Suppression,
    ) -> RepoResult<()> {
        let expires_at = (kind != Suppression::Unsubscribed)
            .then(|| Utc::now() + Duration::days(SUPPRESSION_DAYS));
        let mut s = self.state();
        let found = s
            .suppressions
            .iter_mut()
            .find(|r| (r.organisation_id, r.email_hash.as_str()) == (organisation_id, email_hash));
        match found {
            Some(r) if kind == Suppression::Unsubscribed || r.kind == kind => {
                (r.kind, r.expires_at) = (kind, expires_at);
            }
            Some(_) => {}
            None => s.suppressions.push(SuppressionRow {
                organisation_id,
                email_hash: email_hash.into(),
                kind,
                expires_at,
            }),
        }
        Ok(())
    }

    async fn suppressed(
        &self,
        organisation_id: Uuid,
        email_hash: &str,
    ) -> RepoResult<Vec<Suppression>> {
        let now = Utc::now();
        let s = self.state();
        Ok(s.suppressions
            .iter()
            .filter(|r| {
                r.email_hash == email_hash
                    && r.organisation_id.is_none_or(|o| o == organisation_id)
                    && r.expires_at.is_none_or(|t| t > now)
            })
            .map(|r| r.kind)
            .collect())
    }

    async fn ids_by_email(
        &self,
        organisation_id: Uuid,
        emails: &[String],
    ) -> RepoResult<HashMap<String, Uuid>> {
        let s = self.state();
        let mut rows: Vec<_> = s
            .recipients
            .iter()
            .map(|r| &r.row)
            .filter(|r| r.organisation_id == organisation_id)
            .filter(|r| emails.contains(&r.email.to_lowercase()))
            .collect();
        rows.sort_by_key(|r| (r.created_at, r.id));
        let mut map = HashMap::new();
        for r in rows {
            map.entry(r.email.to_lowercase()).or_insert(r.id);
        }
        Ok(map)
    }
}
