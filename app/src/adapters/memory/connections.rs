use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    connection::{
        Connection, ConnectionPatch, ConnectionStatus, ConnectionsRepo, NewConnection, SealedCreds,
        Verification, Verified,
    },
    repo::{RepoError, RepoResult},
};
use uuid::Uuid;

use super::{MemState, MemStore};

/// The statuses `connections_provider_account_uniq` covers.
const CLAIMED: [ConnectionStatus; 3] = [
    ConnectionStatus::Connected,
    ConnectionStatus::Degraded,
    ConnectionStatus::Revoked,
];

impl MemState {
    /// The Postgres unique index: `Conflict("account")` when connection `id`, in `status` with
    /// `account`, would claim an account another connection of its provider holds.
    fn check_claim(
        &self,
        id: Uuid,
        status: ConnectionStatus,
        account: Option<&str>,
    ) -> RepoResult<()> {
        let Some((c, _)) = self.connections.iter().find(|(c, _)| c.id == id) else {
            return Ok(());
        };
        let taken = self.connections.iter().any(|(o, _)| {
            o.id != id
                && o.provider == c.provider
                && CLAIMED.contains(&o.status)
                && o.external_account_id.as_deref() == account
        });
        if CLAIMED.contains(&status) && account.is_some() && taken {
            return Err(RepoError::Conflict("account"));
        }
        Ok(())
    }

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
            verify_denied_streak: 0,
            verify_denied_first_at: None,
            urgent_alerts: true,
            disconnected_at: None,
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

    async fn last_verification(
        &self,
        organisation_id: Uuid,
        id: Uuid,
    ) -> RepoResult<Option<Verification>> {
        let mut s = self.state();
        if s.connection_mut(organisation_id, id).is_err() {
            return Ok(None);
        }
        let mine = s.verifications.iter().filter(|(c, _)| *c == id);
        // The latest record; on equal times the later one, as it was written last.
        Ok(mine.map(|(_, v)| v).max_by_key(|v| v.at).cloned())
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
        if let Some(u) = p.urgent_alerts {
            c.urgent_alerts = u;
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
        let account = c.external_account_id.clone();
        s.check_claim(id, to, account.as_deref())?;
        let (c, _) = s.connection_mut(organisation_id, id)?;
        c.status = to;
        if let Some(r) = reason {
            c.status_reason = Some(r.into());
        }
        c.updated_at = Utc::now();
        if to == ConnectionStatus::Disconnected {
            c.disconnected_at = Some(c.updated_at);
        }
        Ok(true)
    }

    async fn record_verification(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        _run_id: Uuid,
        v: &Verification,
    ) -> RepoResult<()> {
        let mut s = self.state();
        s.connection_mut(organisation_id, id)?;
        s.verifications.push((id, v.clone()));
        Ok(())
    }

    async fn record_verified(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        v: Verified,
    ) -> RepoResult<()> {
        let mut s = self.state();
        let status = s.connection_mut(organisation_id, id)?.0.status;
        if let Some(a) = v.account.as_deref() {
            s.check_claim(id, status, Some(a))?;
        }
        let (c, _) = s.connection_mut(organisation_id, id)?;
        c.status_reason = v.reason;
        c.verify_denied_streak = 0;
        c.verify_denied_first_at = None;
        if v.account.is_some() {
            c.external_account_id = v.account;
        }
        if let Some(at) = v.first_connected_at {
            (c.first_connected_at, c.billable_from) = (Some(at), Some(at));
        }
        c.updated_at = Utc::now();
        Ok(())
    }

    async fn record_denial(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        streak: i32,
        first_at: DateTime<Utc>,
    ) -> RepoResult<()> {
        let mut s = self.state();
        let (c, _) = s.connection_mut(organisation_id, id)?;
        (c.verify_denied_streak, c.verify_denied_first_at) = (streak, Some(first_at));
        c.updated_at = Utc::now();
        Ok(())
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

    async fn by_id_unscoped(&self, id: Uuid) -> RepoResult<Option<Connection>> {
        let s = self.state();
        Ok(s.connections
            .iter()
            .find(|(c, _)| c.id == id)
            .map(|(c, _)| c.clone()))
    }
}
