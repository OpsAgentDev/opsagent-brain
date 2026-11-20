use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    ai::{
        AiRepo, Explanation, KeySource, KeyStatus, ModelKey, NewModelKey, OrgKeys, RoleModels,
        Slot, UsageRow,
    },
    repo::RepoResult,
    retention::PurgeCounts,
};
use sea_orm::prelude::Decimal;
use uuid::Uuid;

use super::{purge::drain, MemStore};

#[derive(Clone, Default)]
pub(super) struct AiState {
    enabled: HashSet<Uuid>,
    topup: HashMap<Uuid, Decimal>,
    ceilings: HashMap<Uuid, Decimal>,
    keys: Vec<ModelKey>,
    /// With when each was recorded.
    pub(super) usage: Vec<(UsageRow, DateTime<Utc>)>,
    /// `(organisation, stripe event id)`.
    grants: Vec<(Uuid, String)>,
    explanations: Vec<(Uuid, Explanation)>,
    notices: HashSet<(Uuid, String)>,
}

impl AiState {
    /// Removes every row of `org` (the switch and balance are the organisation row's).
    pub(super) fn purge(&mut self, org: Uuid, c: &mut PurgeCounts) {
        self.enabled.remove(&org);
        self.topup.remove(&org);
        self.ceilings.remove(&org);
        c.insert(
            "ai_usage",
            drain(&mut self.usage, |u| u.0.organisation_id == org),
        );
        c.insert(
            "explanations",
            drain(&mut self.explanations, |e| e.0 == org),
        );
        c.insert("ai_credit_grants", drain(&mut self.grants, |g| g.0 == org));
        let n = self.notices.len();
        self.notices.retain(|k| k.0 != org);
        c.insert("ai_notices", (n - self.notices.len()) as u64);
        c.insert(
            "model_keys",
            drain(&mut self.keys, |k| k.organisation_id == org),
        );
    }
}

impl MemStore {
    /// Every metered call, oldest first.
    pub fn ai_usage_rows(&self) -> Vec<UsageRow> {
        self.state().ai.usage.iter().map(|u| u.0.clone()).collect()
    }

    fn key_mut<T>(&self, org: Uuid, slot: Slot, f: impl FnOnce(&mut ModelKey) -> T) -> Option<T> {
        let mut s = self.state();
        let mut found = s.ai.keys.iter_mut();
        found
            .find(|k| k.organisation_id == org && k.slot == slot)
            .map(f)
    }
}

#[async_trait]
impl AiRepo for MemStore {
    async fn enabled(&self, organisation_id: Uuid) -> RepoResult<bool> {
        let mut s = self.state();
        s.org_mut(organisation_id)?;
        Ok(s.ai.enabled.contains(&organisation_id))
    }

    async fn set_enabled(&self, organisation_id: Uuid, on: bool) -> RepoResult<()> {
        let mut s = self.state();
        s.org_mut(organisation_id)?;
        match on {
            true => s.ai.enabled.insert(organisation_id),
            false => s.ai.enabled.remove(&organisation_id),
        };
        Ok(())
    }

    async fn keys(&self, organisation_id: Uuid) -> RepoResult<OrgKeys> {
        let s = self.state();
        let ours =
            s.ai.keys
                .iter()
                .filter(|k| k.organisation_id == organisation_id);
        let of = |slot| ours.clone().find(|k| k.slot == slot).cloned();
        Ok(OrgKeys {
            primary: of(Slot::Primary),
            backup: of(Slot::Backup),
        })
    }

    async fn put_key(&self, organisation_id: Uuid, k: &NewModelKey) -> RepoResult<ModelKey> {
        let key = ModelKey {
            id: Uuid::now_v7(),
            organisation_id,
            provider: k.provider,
            last4: k.last4.clone(),
            status: KeyStatus::Ok,
            status_since: Utc::now(),
            models: k.models.clone(),
            slot: k.slot,
            base_url: k.base_url.clone(),
            ciphertext: k.ciphertext.clone(),
            nonce: k.nonce.clone(),
            kek_version: k.kek_version,
        };
        let mut s = self.state();
        s.org_mut(organisation_id)?;
        s.ai.keys
            .retain(|o| !(o.organisation_id == organisation_id && o.slot == k.slot));
        s.ai.keys.push(key.clone());
        Ok(key)
    }

    async fn update_key_models(
        &self,
        organisation_id: Uuid,
        slot: Slot,
        models: &RoleModels,
    ) -> RepoResult<bool> {
        let done = self.key_mut(organisation_id, slot, |k| k.models = models.clone());
        Ok(done.is_some())
    }

    async fn delete_key(&self, organisation_id: Uuid, slot: Slot) -> RepoResult<bool> {
        let mut s = self.state();
        let gone = drain(&mut s.ai.keys, |k| {
            k.organisation_id == organisation_id && k.slot == slot
        });
        if gone > 0 && slot == Slot::Primary {
            let backup = s.ai.keys.iter_mut();
            let mut backup = backup.filter(|k| k.organisation_id == organisation_id);
            if let Some(k) = backup.find(|k| k.slot == Slot::Backup) {
                k.slot = Slot::Primary;
            }
        }
        Ok(gone > 0)
    }

    async fn credit_ceiling(&self, organisation_id: Uuid) -> RepoResult<Option<Decimal>> {
        let mut s = self.state();
        s.org_mut(organisation_id)?;
        Ok(s.ai.ceilings.get(&organisation_id).copied())
    }

    async fn set_credit_ceiling(
        &self,
        organisation_id: Uuid,
        ceiling: Option<Decimal>,
    ) -> RepoResult<()> {
        let mut s = self.state();
        s.org_mut(organisation_id)?;
        match ceiling {
            Some(c) => s.ai.ceilings.insert(organisation_id, c),
            None => s.ai.ceilings.remove(&organisation_id),
        };
        Ok(())
    }

    async fn set_key_status(
        &self,
        organisation_id: Uuid,
        key_id: Uuid,
        status: KeyStatus,
        at: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let mut s = self.state();
        let mut ours = s.ai.keys.iter_mut();
        let found = ours.find(|k| k.organisation_id == organisation_id && k.id == key_id);
        Ok(found.is_some_and(|k| {
            let change = k.status != status;
            if change {
                (k.status, k.status_since) = (status, at);
            }
            change
        }))
    }

    async fn record_usage(&self, row: &UsageRow, topup_debit: Decimal) -> RepoResult<()> {
        let mut s = self.state();
        s.org_mut(row.organisation_id)?;
        s.ai.usage.push((row.clone(), Utc::now()));
        let balance = s.ai.topup.entry(row.organisation_id).or_default();
        *balance = (*balance - topup_debit).max(Decimal::ZERO);
        Ok(())
    }

    async fn credits_used(
        &self,
        organisation_id: Uuid,
        source: KeySource,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> RepoResult<Decimal> {
        let s = self.state();
        let rows = s.ai.usage.iter().filter(|(u, at)| {
            u.organisation_id == organisation_id
                && u.key_source == source
                && *at >= since
                && *at < until
        });
        Ok(rows.map(|(u, _)| u.credits).sum())
    }

    async fn topup_balance(&self, organisation_id: Uuid) -> RepoResult<Decimal> {
        let mut s = self.state();
        s.org_mut(organisation_id)?;
        Ok(s.ai
            .topup
            .get(&organisation_id)
            .copied()
            .unwrap_or_default())
    }

    async fn grant_topup(
        &self,
        organisation_id: Uuid,
        credits: Decimal,
        stripe_event_id: &str,
    ) -> RepoResult<bool> {
        let mut s = self.state();
        s.org_mut(organisation_id)?;
        if s.ai.grants.iter().any(|g| g.1 == stripe_event_id) {
            return Ok(false);
        }
        s.ai.grants.push((organisation_id, stripe_event_id.into()));
        *s.ai.topup.entry(organisation_id).or_default() += credits;
        Ok(true)
    }

    async fn explanation(
        &self,
        organisation_id: Uuid,
        check_id: &str,
        hash: &str,
    ) -> RepoResult<Option<Explanation>> {
        let s = self.state();
        let found = s.ai.explanations.iter().find(|(o, e)| {
            *o == organisation_id && e.check_id == check_id && e.evidence_hash == hash
        });
        Ok(found.map(|(_, e)| e.clone()))
    }

    async fn put_explanation(
        &self,
        organisation_id: Uuid,
        e: &Explanation,
    ) -> RepoResult<Explanation> {
        let mut s = self.state();
        s.org_mut(organisation_id)?;
        let kept = s.ai.explanations.iter().find(|(o, k)| {
            *o == organisation_id && k.check_id == e.check_id && k.evidence_hash == e.evidence_hash
        });
        if let Some((_, kept)) = kept {
            return Ok(kept.clone());
        }
        s.ai.explanations.push((organisation_id, e.clone()));
        Ok(e.clone())
    }

    async fn notice_once(&self, organisation_id: Uuid, key: &str) -> RepoResult<bool> {
        let mut s = self.state();
        s.org_mut(organisation_id)?;
        Ok(s.ai.notices.insert((organisation_id, key.into())))
    }
}
