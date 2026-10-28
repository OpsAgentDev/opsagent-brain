//! `deliver_alert` (urgent-alerts spec): after a scan, each open critical finding not yet
//! alerted goes to the connection's Slack channel, or by email to the owners. The first
//! delivery of a connection baselines instead: one summary, every critical marked alerted.
//! Caps: 5 messages a run, 20 a rolling day, the rest in a roll-up at most once an hour.
use chrono::Duration;
use opsagent_core::{
    connection::{Connection, ConnectionStatus},
    finding::Finding,
    repo::PageRequest,
    resource::ResourceFilter,
    run::RunStatus,
};
use opsagent_deliver::{
    alert::{plan_alerts, render_alert, render_baseline, render_rollup, ConnectionInfo},
    repo::{Integration, ALERT, FALLBACK_EMAIL},
};
use opsagent_ledger::{
    lease::{self, claim, unclaim},
    run_chunked, ChunkOutcome, EffectState, LedgerError, RunChunkedOptions, RunRow,
};
use uuid::Uuid;

use super::{
    delivery_out::{plain, Out},
    outcome, Kit,
};
use crate::{
    actions::runs::classify::{lerr, LResult},
    mailers::{magic_link::mail_safe_name, Mail},
};

const CHUNK: &str = "deliver";
const BASELINE: &str = "alert:baseline";
/// How long a delivery holds its connection: far longer than five posts and a roll-up take,
/// short enough that a crashed run blocks the next deliveries only briefly.
const CLAIM_TTL: std::time::Duration = std::time::Duration::from_secs(300);
/// A resource lookup by exact identity: at most one row per connection.
const LOOKUP: PageRequest = PageRequest {
    after: None,
    limit: 1,
};

#[derive(Clone)]
pub struct DeliverAlert {
    kit: Kit,
}

/// One message: Slack text (the email body is its plain form) and the email subject.
struct Msg {
    text: String,
    subject: String,
}

/// Where this run's messages go; Slack stays off for the rest of the run once it failed.
struct Route<'a> {
    out: Out<'a>,
    c: &'a Connection,
    slack: Option<(Integration, String)>,
}

impl DeliverAlert {
    pub fn new(kit: Kit) -> Self {
        Self { kit }
    }

    /// Runs (or resumes) alert run `run_id`. The run row must exist.
    pub async fn run(&self, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
        let storage = self.kit.uow.ledger();
        let run = storage.load_run(run_id).await?;
        if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
            return Ok(run.status); // duplicate delivery of a finished run
        }
        // One delivery per connection at a time, or two runs could send the same finding; the
        // run id owns the claim, so a resumed run passes and any other run is skipped (the
        // next scan's delivery picks up what it would have sent).
        let conn = run.key.connection_id.ok_or(LedgerError::NotFound)?;
        let (key, owner) = (
            format!("lease:conn:{conn}:deliver_alert"),
            run_id.to_string(),
        );
        if !claim(&self.kit.redis, &key, &owner, CLAIM_TTL).await? {
            return self.skip(&run, &opts).await;
        }
        let chunks = vec![CHUNK.to_owned()];
        let res = run_chunked(storage, &self.kit.redis, run_id, chunks, opts, |_, _| {
            self.deliver(&run)
        })
        .await;
        // A worker that took over this run's lease is still delivering: leave the claim to it.
        let after = storage.load_run(run_id).await.map(|r| r.status);
        if !matches!(after, Ok(RunStatus::Running)) {
            unclaim(&self.kit.redis, &key, &owner).await;
        }
        res
    }

    /// Ends the run `skipped: overlap` under a run lease of its own.
    async fn skip(&self, run: &RunRow, opts: &RunChunkedOptions) -> LResult<RunStatus> {
        let (storage, redis) = (self.kit.uow.ledger(), &self.kit.redis);
        let l = lease::acquire(storage, redis, run.id, &opts.worker_id, opts.lease_ttl).await?;
        let l = l.ok_or(LedgerError::LeaseHeld)?;
        let skip = RunStatus::Skipped;
        let res = storage
            .set_status(run.id, l.fence, skip, Some("overlap".into()))
            .await;
        lease::release(redis, &l).await;
        res.map(|()| skip)
    }

    async fn deliver(&self, run: &RunRow) -> LResult<ChunkOutcome> {
        let r = &*self.kit.uow;
        let Some(c) = eligible(r, run).await? else {
            return Ok(outcome("skipped", "not_eligible"));
        };
        let org = c.organisation_id;
        let now = self.kit.clock.now();
        let candidates = r
            .findings()
            .alert_candidates(org, c.id)
            .await
            .map_err(lerr)?;
        let since = now - Duration::hours(24);
        let tally = r.deliveries().alert_tally(org, c.id, run.id, since);
        let tally = tally.await.map_err(lerr)?;
        let mut route = self.route(run, &c).await?;
        let base = &self.kit.web_base_url;
        let account = account(&c);
        // `alert:baseline` ledger entries must never be pruned: retention that drops them
        // would re-baseline the connection and swallow its next criticals into a summary.
        if !tally.baselined {
            let n = candidates.len();
            let msg = (n > 0).then(|| Msg {
                text: render_baseline(n, base),
                subject: format!("First scan: {n} critical findings ({account})"),
            });
            route.once(BASELINE, msg, &ids(&candidates)).await?;
            return Ok(outcome("delivered", "baseline"));
        }
        let plan = plan_alerts(
            &candidates,
            tally.since,
            tally.this_run,
            tally.last_rollup_at,
            now,
        );
        for f in candidates
            .iter()
            .filter(|f| plan.individual.contains(&f.id))
        {
            let msg = Msg {
                text: render_alert(f, &self.info(&c, f).await?, base),
                subject: format!("Urgent: {} ({account})", mail_safe_name(&f.title)),
            };
            route
                .once(&format!("alert:{}", f.id), Some(msg), &[f.id])
                .await?;
        }
        if !plan.rollup.is_empty() {
            let n = plan.rollup.len();
            if plan.rollup_allowed {
                let msg = Msg {
                    text: render_rollup(n, base),
                    subject: format!("Urgent: {n} more urgent findings ({account})"),
                };
                let key = format!("alert:rollup:{}", run.id);
                route.once(&key, Some(msg), &plan.rollup).await?;
            } else {
                // Over the caps and a roll-up went out within the hour: marked, never sent.
                r.findings()
                    .mark_alerted(org, &plan.rollup, now)
                    .await
                    .map_err(lerr)?;
            }
        }
        Ok(outcome("alerted", &plan.individual.len().to_string()))
    }

    async fn route<'a>(&'a self, run: &'a RunRow, c: &'a Connection) -> LResult<Route<'a>> {
        let r = &*self.kit.uow;
        let integration = r
            .integrations()
            .active_slack(c.organisation_id)
            .await
            .map_err(lerr)?;
        let slack = integration.zip(c.slack_channel_id.clone());
        let out = Out {
            kit: &self.kit,
            run,
            organisation_id: c.organisation_id,
            connection_id: Some(c.id),
            kind: ALERT,
        };
        Ok(Route { out, c, slack })
    }

    /// Where `f` lives, as the message names it.
    async fn info(&self, c: &Connection, f: &Finding) -> LResult<ConnectionInfo> {
        let identity = &f.key.resource_identity;
        let filter = ResourceFilter {
            connection_id: Some(c.id),
            identity: Some(identity.clone()),
            ..Default::default()
        };
        let rows = self
            .kit
            .uow
            .resources()
            .list(c.organisation_id, filter, LOOKUP);
        let rows = rows.await.map_err(lerr)?.items;
        let row = rows.into_iter().next();
        Ok(ConnectionInfo {
            account: account(c),
            resource: row
                .as_ref()
                .and_then(|r| r.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| identity.clone()),
            region: row.and_then(|r| r.region).filter(|r| !r.is_empty()),
        })
    }
}

impl Route<'_> {
    /// Sends `msg` once for effect `key` (Slack, else the owners by email), then records the
    /// effect and `alerted_at` on `ids` in one transaction. A done `key` sends nothing.
    async fn once(&mut self, key: &str, msg: Option<Msg>, ids: &[Uuid]) -> LResult<()> {
        let (run, uow) = (self.out.run, &*self.out.kit.uow);
        if let EffectState::Done(_) = uow.ledger().effect_begin(run.id, key).await? {
            return Ok(());
        }
        if let Some(m) = msg {
            self.send(key, m).await?;
        }
        let now = self.out.kit.clock.now();
        let tx = uow.begin().await.map_err(lerr)?;
        tx.ledger().effect_done(run.id, key, None).await?;
        let org = self.c.organisation_id;
        tx.findings()
            .mark_alerted(org, ids, now)
            .await
            .map_err(lerr)?;
        tx.commit().await.map_err(lerr)
    }

    async fn send(&mut self, key: &str, m: Msg) -> LResult<()> {
        if let Some((i, ch)) = &self.slack {
            match self
                .out
                .slack(&format!("{key}:slack"), i, self.c, ch, &m.text)
                .await?
            {
                Ok(()) => return Ok(()),
                Err(e) => match self.out.retry_later(&e) {
                    Some(retry) => return Err(retry),
                    None => self.slack = None,
                },
            }
        }
        let uow = &*self.out.kit.uow;
        let owners = uow
            .recipients()
            .owners(self.c.organisation_id)
            .await
            .map_err(lerr)?;
        let body = plain(&m.text);
        for o in owners {
            let mail = Mail {
                to: o.email,
                subject: m.subject.clone(),
                text: body.clone(),
                ..Default::default()
            };
            let k = format!("{key}:{}", o.id);
            self.out.email(&k, mail, o.member, FALLBACK_EMAIL).await?;
        }
        Ok(())
    }
}

/// The run's connection while it takes urgent alerts: organisation not deleted, connected
/// or degraded, switch on.
async fn eligible(r: &dyn crate::actions::uow::Repos, run: &RunRow) -> LResult<Option<Connection>> {
    let (Some(org), Some(id)) = (run.key.organisation_id, run.key.connection_id) else {
        return Err(LedgerError::NotFound);
    };
    let c = r.connections().get(org, id).await.map_err(lerr)?;
    let c = c.ok_or(LedgerError::NotFound)?;
    let gone = r.orgs().is_deleted(org).await.map_err(lerr)?;
    let live = matches!(
        c.status,
        ConnectionStatus::Connected | ConnectionStatus::Degraded
    );
    Ok((!gone && live && c.urgent_alerts).then_some(c))
}

/// The connection's alias, else its account id.
fn account(c: &Connection) -> String {
    let name = c.display_name.as_deref().filter(|n| !n.is_empty());
    mail_safe_name(
        name.or(c.external_account_id.as_deref())
            .unwrap_or(&c.provider),
    )
}

fn ids(f: &[Finding]) -> Vec<Uuid> {
    f.iter().map(|f| f.id).collect()
}
