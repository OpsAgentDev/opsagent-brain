//! `deliver_briefing` (delivery.md, PRD 7.6): the morning briefing to the connection's Slack
//! channel; to the owners by email when Slack is not routed, revoked, gone, or still failing
//! once retries are spent. Nothing changed since the last briefing: no message, no row.
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_deliver::{
    render_text,
    repo::{BRIEFING, FALLBACK_EMAIL},
};
use opsagent_ledger::{run_chunked, ChunkOutcome, JobKind, RunChunkedOptions, RunRow};
use uuid::Uuid;

use super::{
    delivery_out::{plain, Out},
    options, outcome,
    snapshots::{briefing, live_connection, route},
    Kit,
};
use crate::{
    adapters::slack::SlackError,
    error::{AppError, AppResult},
    mailers::{magic_link::mail_safe_name, Mail},
    workers::common::{lerr, LResult},
};

const CHUNK: &str = "deliver";

pub struct DeliverBriefing {
    kit: Kit,
}

impl DeliverBriefing {
    pub fn new(kit: Kit) -> Self {
        Self { kit }
    }

    /// Runs (or resumes) briefing run `run_id`. The run row must exist.
    pub async fn run(&self, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
        let storage = self.kit.uow.ledger();
        let run = storage.load_run(run_id).await?;
        if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
            return Ok(run.status); // duplicate delivery of a finished run
        }
        let chunks = vec![CHUNK.to_owned()];
        run_chunked(storage, &self.kit.redis, run_id, chunks, opts, |_, _| {
            self.deliver(&run)
        })
        .await
    }

    async fn deliver(&self, run: &RunRow) -> LResult<ChunkOutcome> {
        let r = &*self.kit.uow;
        let Some(c) = live_connection(r, run).await? else {
            return Ok(outcome("skipped", "not_deliverable"));
        };
        let link_base = &self.kit.settings.web_base_url;
        let now = self.kit.clock.now();
        let Some(b) = briefing(r, &c, run.key.scheduled_at, now, link_base)
            .await
            .map_err(lerr)?
        else {
            return Ok(outcome("skipped", "nothing_changed"));
        };
        let text = render_text(&b);
        let out = Out {
            kit: &self.kit,
            run,
            organisation_id: c.organisation_id,
            connection_id: Some(c.id),
            kind: BRIEFING,
        };
        let integration = r
            .integrations()
            .active_slack(c.organisation_id)
            .await
            .map_err(lerr)?;
        let channel = route(r, &c, integration.is_some())
            .await
            .map_err(lerr)?
            .slack_channel;
        let mut channel_gone = false;
        if let (Some(i), Some(ch)) = (&integration, &channel) {
            match out.slack(BRIEFING, i, &c, ch, &text).await? {
                Ok(()) => return Ok(outcome("delivered", "slack")),
                Err(e) => match out.retry_later(&e) {
                    Some(retry) => return Err(retry),
                    None => channel_gone = e == SlackError::ChannelGone,
                },
            }
        }
        let notice = if channel_gone {
            CHANNEL_GONE_NOTICE
        } else if r
            .deliveries()
            .revoke_notice_due(c.organisation_id, c.id, run.key.scheduled_at)
            .await
            .map_err(lerr)?
        {
            REVOKED_NOTICE
        } else {
            ""
        };
        let subject = format!(
            "OpsAgent morning briefing: {}",
            mail_safe_name(c.display_name.as_deref().unwrap_or(&c.provider))
        );
        let body = format!("{notice}{}", plain(&text));
        for o in r
            .recipients()
            .owners(c.organisation_id)
            .await
            .map_err(lerr)?
        {
            let mail = Mail {
                to: o.email,
                subject: subject.clone(),
                text: body.clone(),
                ..Default::default()
            };
            out.email(
                &format!("fallback:{}", o.id),
                mail,
                o.member,
                FALLBACK_EMAIL,
            )
            .await?;
        }
        Ok(outcome("delivered", "fallback_email"))
    }
}

const REVOKED_NOTICE: &str = "Slack disconnected: OpsAgent's access was revoked. Briefings come \
     by email until an owner reconnects Slack.\n\n";
// shortcut: the channel notice still comes only from the run that found the channel gone (a
// weekly finding it first clears the channel silently); derive it from stored state like the
// revoke notice once connections record when their channel was cleared.
const CHANNEL_GONE_NOTICE: &str = "Slack channel unavailable: it was archived or deleted. \
     Briefings come by email until a new channel is chosen.\n\n";

/// `deliver:briefing connection:<id>`: creates a briefing run now and delivers it inline
/// (local and e2e use).
pub struct DeliverBriefingNow {
    kit: Kit,
    deliver: DeliverBriefing,
}

impl DeliverBriefingNow {
    pub fn new(kit: Kit) -> Self {
        Self {
            deliver: DeliverBriefing::new(kit.clone()),
            kit,
        }
    }

    pub async fn run(&self, connection_id: Uuid) -> AppResult<RunStatus> {
        // tenancy: operator task; the connection id names its organisation.
        let c = self
            .kit
            .uow
            .connections()
            .by_id_unscoped(connection_id)
            .await?
            .ok_or(AppError::NotFound)?;
        let job = JobKind::DeliverBriefing.as_str();
        let key = RunKey {
            organisation_id: Some(c.organisation_id),
            connection_id: Some(c.id),
            job_type: job.into(),
            scheduled_at: self.kit.clock.now(),
        };
        let run = self.kit.uow.ledger().create_run(key).await?.run;
        let status = self.deliver.run(run.id, options(job)).await?;
        tracing::info!(run_id = %run.id, status = ?status, "deliver_briefing finished");
        Ok(status)
    }
}
