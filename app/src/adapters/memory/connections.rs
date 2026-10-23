use async_trait::async_trait;
use chrono::Utc;
use opsagent_core::{
    connection::{
        Connection, ConnectionPatch, ConnectionStatus, ConnectionsRepo, NewConnection, SealedCreds,
    },
    repo::{RepoError, RepoResult},
};
use uuid::Uuid;

use super::{MemState, MemStore};

impl MemState {
    fn connection_mut(
        &mut self,
        organisation_id: Uuid,
        id: Uuid,
    ) -> RepoResult<&mut (Connection, SealedCreds)> {
        self.connections
            .iter_mut()
            .find(|(c, _)| c.id == id && c.organisation_id == organisation_id)
            .ok_or(RepoError::NotFound)
    }
}

#[async_trait]
impl ConnectionsRepo for MemStore {
    async fn insert(&self, new: NewConnection, creds: SealedCreds) -> RepoResult<Connection> {
        let now = Utc::now();
        let c = Connection {
            id: Uuid::new_v4(),
            organisation_id: new.organisation_id,
            provider: new.provider,
            display_name: Some(new.display_name),
            status: ConnectionStatus::Pending,
            status_reason: None,
            external_account_id: None,
            template_version: new.template_version,
            scan_time_local: None,
            briefing_time_local: None,
            api_rate_ceiling: None,
            slack_channel_id: None,
            first_connected_at: None,
            billable_from: None,
            created_at: now,
            updated_at: now,
        };
        self.state().connections.push((c.clone(), creds));
        Ok(c)
    }

    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Connection>> {
        let mut s = self.state();
        Ok(s.connection_mut(organisation_id, id)
            .ok()
            .map(|(c, _)| c.clone()))
    }

    async fn lock(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Connection>> {
        self.get(organisation_id, id).await
    }

    async fn list(&self, organisation_id: Uuid) -> RepoResult<Vec<Connection>> {
        let s = self.state();
        let mine = s.connections.iter().map(|(c, _)| c);
        Ok(mine
            .filter(|c| c.organisation_id == organisation_id)
            .cloned()
            .collect())
    }

    async fn update(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        p: ConnectionPatch,
    ) -> RepoResult<Connection> {
        let mut s = self.state();
        let (c, _) = s.connection_mut(organisation_id, id)?;
        if let Some(n) = p.display_name {
            c.display_name = Some(n);
        }
        if let Some(t) = p.scan_time_local {
            c.scan_time_local = Some(t);
        }
        if let Some(t) = p.briefing_time_local {
            c.briefing_time_local = Some(t);
        }
        if let Some(r) = p.api_rate_ceiling {
            c.api_rate_ceiling = Some(r);
        }
        if let Some(ch) = p.slack_channel_id {
            c.slack_channel_id = ch;
        }
        c.updated_at = Utc::now();
        Ok(c.clone())
    }

    async fn cas_status(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        from: ConnectionStatus,
        to: ConnectionStatus,
        reason: Option<&str>,
    ) -> RepoResult<bool> {
        let mut s = self.state();
        let Ok((c, _)) = s.connection_mut(organisation_id, id) else {
            return Ok(false);
        };
        if c.status != from {
            return Ok(false);
        }
        c.status = to;
        if let Some(r) = reason {
            c.status_reason = Some(r.into());
        }
        c.updated_at = Utc::now();
        Ok(true)
    }

    async fn load_creds(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<SealedCreds> {
        Ok(self.state().connection_mut(organisation_id, id)?.1.clone())
    }

    async fn save_creds(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        creds: SealedCreds,
    ) -> RepoResult<()> {
        self.state().connection_mut(organisation_id, id)?.1 = creds;
        Ok(())
    }
}
