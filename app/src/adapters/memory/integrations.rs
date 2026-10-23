use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::repo::{RepoError, RepoResult};
use opsagent_deliver::repo::{Integration, IntegrationsRepo, SealedToken, ACTIVE, REVOKED, SLACK};
use uuid::Uuid;

use super::MemStore;

fn active_slack(i: &Integration) -> bool {
    i.kind == SLACK && i.status == ACTIVE
}

#[async_trait]
impl IntegrationsRepo for MemStore {
    async fn upsert_slack(
        &self,
        organisation_id: Uuid,
        config: serde_json::Value,
        token: SealedToken,
    ) -> RepoResult<()> {
        let mut s = self.state();
        let held = s.integrations.iter().any(|i| {
            i.organisation_id != organisation_id
                && active_slack(i)
                && i.config["team_id"] == config["team_id"]
        });
        if held {
            return Err(RepoError::Conflict("slack_workspace"));
        }
        let now = Utc::now();
        let found = s
            .integrations
            .iter_mut()
            .find(|i| i.organisation_id == organisation_id && i.kind == SLACK);
        match found {
            Some(i) => {
                (i.config, i.ciphertext, i.nonce) = (config, token.ciphertext, token.nonce);
                (i.status, i.updated_at) = (ACTIVE.into(), now);
            }
            None => s.integrations.push(Integration {
                id: Uuid::new_v4(),
                organisation_id,
                kind: SLACK.into(),
                status: ACTIVE.into(),
                config,
                ciphertext: token.ciphertext,
                nonce: token.nonce,
                created_at: now,
                updated_at: now,
            }),
        }
        Ok(())
    }

    async fn list(&self, organisation_id: Uuid) -> RepoResult<Vec<Integration>> {
        let s = self.state();
        let mut all: Vec<Integration> = s
            .integrations
            .iter()
            .filter(|i| i.organisation_id == organisation_id)
            .cloned()
            .collect();
        all.sort_by_key(|i| i.created_at);
        Ok(all)
    }

    async fn active_slack(&self, organisation_id: Uuid) -> RepoResult<Option<Integration>> {
        let s = self.state();
        let found = s
            .integrations
            .iter()
            .find(|i| i.organisation_id == organisation_id && active_slack(i));
        Ok(found.cloned())
    }

    async fn mark_revoked(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        at: DateTime<Utc>,
    ) -> RepoResult<()> {
        let mut s = self.state();
        let found = s
            .integrations
            .iter_mut()
            .find(|i| (i.organisation_id, i.id) == (organisation_id, id));
        if let Some(i) = found {
            (i.status, i.updated_at) = (REVOKED.into(), at);
        }
        Ok(())
    }

    async fn delete(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<bool> {
        let mut s = self.state();
        let before = s.integrations.len();
        s.integrations
            .retain(|i| (i.organisation_id, i.id) != (organisation_id, id));
        Ok(s.integrations.len() < before)
    }
}
