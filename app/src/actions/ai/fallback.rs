//! One metered model call on a plan's connection, falling back to the payer's backup before
//! the first text delta only (ai-connections.md, When the backup is tried).
use std::net::SocketAddr;

use opsagent_core::{
    ai::{quota_period, KeySource, Purpose, Slot},
    billing::OrgBilling,
    endpoint::{check_url, pin},
    model::{Endpoint, ModelError, ModelRequest, ModelTurn, TextSink},
};
use sea_orm::prelude::Decimal;
use uuid::Uuid;

use super::{
    access::{AiAccess, CallPlan, Conn},
    failures::AiCallError,
};
use crate::actions::orgs::OrgScope;

/// Passes deltas on and notes whether any text reached the client.
struct Tracked<'a> {
    inner: &'a mut dyn TextSink,
    sent: bool,
}

impl TextSink for Tracked<'_> {
    fn delta(&mut self, text: &str) {
        self.sent |= !text.is_empty();
        self.inner.delta(text);
    }
}

impl AiAccess {
    /// One model call on `plan`, metered. Text deltas go to `sink` as they arrive. Only a
    /// plan's first call may fall back; the connection that serves it serves the rest.
    pub async fn call(
        &self,
        scope: &OrgScope,
        plan: &mut CallPlan,
        purpose: Purpose,
        req: ModelRequest,
        sink: &mut dyn TextSink,
    ) -> Result<ModelTurn, AiCallError> {
        let org = scope.organisation.id;
        self.recheck(org, &plan.conn).await?;
        let backup = plan.backup.take();
        // With a backup waiting, a rate-limited primary gets one retry, not three.
        let n = if backup.is_some() { 1 } else { usize::MAX };
        let waits = &self.s.backoff[..n.min(self.s.backoff.len())];
        let mut sink = Tracked {
            inner: sink,
            sent: false,
        };
        let e = match self.on_conn(scope, plan, &req, waits, &mut sink).await? {
            Ok(turn) => return self.served(scope, plan, purpose, turn).await,
            Err(e) => e,
        };
        let Some(b) = backup.filter(|_| !sink.sent && !matches!(e, ModelError::Other(_))) else {
            return Err(self.failed(scope, plan, e, false).await);
        };
        // The primary's own status follows its failure; the backup's error is the caller's.
        let _ = self.failed(scope, plan, e, true).await;
        plan.conn = b;
        let waits = &self.s.backoff[..];
        match self.on_conn(scope, plan, &req, waits, &mut sink).await? {
            Ok(turn) => self.served(scope, plan, purpose, turn).await,
            Err(e) => Err(self.failed(scope, plan, e, false).await),
        }
    }

    async fn served(
        &self,
        scope: &OrgScope,
        plan: &CallPlan,
        purpose: Purpose,
        turn: ModelTurn,
    ) -> Result<ModelTurn, AiCallError> {
        self.meter(scope, plan, purpose, &turn.usage).await?;
        let c = &plan.conn;
        // Ruling 10: told when the backup serves, so a backup that also fails sends only
        // "has stopped". A failed notice must not fail the answered call.
        let byok_backup = c.source == KeySource::Byok && c.slot == Slot::Backup;
        if byok_backup && self.backup_notice(scope.organisation.id).await.is_err() {
            tracing::warn!(error_code = "ai_notice_failed", "ai backup notice failed");
        }
        Ok(turn)
    }

    /// The call on `plan.conn`, with today's one replacement of a gone BYOK model (the
    /// plan then uses the replacement). The outer error is bookkeeping, never fallback.
    async fn on_conn(
        &self,
        scope: &OrgScope,
        plan: &mut CallPlan,
        req: &ModelRequest,
        waits: &[std::time::Duration],
        sink: &mut Tracked<'_>,
    ) -> Result<Result<ModelTurn, ModelError>, AiCallError> {
        let mut req = req.clone();
        req.model = plan.model().to_owned();
        let r = self.attempt(&plan.conn, &req, waits, sink).await;
        if !matches!(r, Err(ModelError::ModelGone)) || plan.source() != KeySource::Byok {
            return Ok(r);
        }
        let Some(model) = self.replace_model(scope, plan).await? else {
            return Ok(r);
        };
        self.recheck(scope.organisation.id, &plan.conn).await?;
        req.model = model;
        Ok(self.attempt(&plan.conn, &req, waits, sink).await)
    }

    /// The addresses a call on `c` may connect to: a custom BYOK URL is checked again and
    /// resolved now, and a refusal counts as an outage (plan ruling 3).
    pub(super) async fn pinned(&self, c: &Conn) -> Result<Vec<SocketAddr>, ModelError> {
        if !c.custom {
            return Ok(vec![]);
        }
        let policy = self.s.policy;
        let u = check_url(&c.base_url, policy).map_err(|_| ModelError::Outage)?;
        pin(&*self.resolver, &u, policy)
            .await
            .map_err(|_| ModelError::Outage)
    }

    /// `c` as the adapters' endpoint, on `pin`.
    pub(super) fn endpoint<'a>(c: &'a Conn, pin: &'a [SocketAddr]) -> Endpoint<'a> {
        Endpoint {
            base_url: &c.base_url,
            api_key: &c.api_key,
            custom: c.base_host.is_some(),
            pin,
        }
    }

    /// The call on `c`, retried after each of `waits` while rate limited.
    async fn attempt(
        &self,
        c: &Conn,
        req: &ModelRequest,
        waits: &[std::time::Duration],
        sink: &mut Tracked<'_>,
    ) -> Result<ModelTurn, ModelError> {
        let pin = self.pinned(c).await?;
        let p = self.models.get(c.style);
        let mut waits = waits.iter();
        loop {
            match p.stream(&Self::endpoint(c, &pin), req, &mut *sink).await {
                Err(ModelError::RateLimited) => match waits.next() {
                    Some(d) => tokio::time::sleep(*d).await,
                    None => return Err(ModelError::RateLimited),
                },
                r => return r,
            }
        }
    }

    /// Credits still left right before a provider call (plan() checked once per turn, and
    /// concurrent turns spend the same credits): the period quota plus top-ups on OpsAgent's
    /// key, the monthly ceiling across both connections on BYOK. Overshoot is then one call
    /// per concurrent request.
    async fn recheck(&self, org: Uuid, c: &Conn) -> Result<(), AiCallError> {
        let ai = self.uow.ai();
        let left = match c.source {
            KeySource::Byok => {
                let Some(ceiling) = ai.credit_ceiling(org).await? else {
                    return Ok(());
                };
                let (since, until) = quota_period(&OrgBilling::default(), self.clock.now());
                ceiling - ai.credits_used(org, KeySource::Byok, since, until).await?
            }
            KeySource::OpsAgent => {
                let q = self.quota(&*self.uow, org).await?;
                (q.quota - q.used).max(Decimal::ZERO) + ai.topup_balance(org).await?
            }
        };
        match left > Decimal::ZERO {
            true => Ok(()),
            false => Err(AiCallError::QuotaReached),
        }
    }
}
