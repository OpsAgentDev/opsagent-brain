//! `deliver_briefing` job (delivery.md, PRD 7.6): the morning briefing to the connection's Slack
//! channel; to the owners by email when Slack is not routed, revoked, gone, or still failing
//! once retries are spent. Nothing changed since the last briefing: no message, no row.
use async_trait::async_trait;
use chrono::Utc;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_core::run::RunStatus;
use opsagent_deliver::render_text;
use opsagent_ledger::{run_chunked, ChunkOutcome, LedgerError, RunChunkedOptions, RunRow, Storage};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    common::{err, lerr, redis_client, LResult},
    delivery::{plain, Out},
};
use crate::{
    adapters::slack::SlackError,
    mailers::{magic_link::mail_safe_name, Mail},
    models::ledger_storage::PgStorage,
    services::deliveries::{
        briefing, live_connection, options, outcome, owners, revoke_notice_due, route,
        slack_integration, BRIEFING, FALLBACK_EMAIL,
    },
    settings::Settings,
};

pub const JOB: &str = "deliver_briefing";
const CHUNK: &str = "deliver";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverBriefingArgs {
    pub run_id: Uuid,
}

pub struct DeliverBriefingWorker {
    ctx: AppContext,
}

#[async_trait]
impl BackgroundWorker<DeliverBriefingArgs> for DeliverBriefingWorker {
    fn build(ctx: &AppContext) -> Self {
        Self { ctx: ctx.clone() }
    }

    async fn perform(&self, args: DeliverBriefingArgs) -> Result<()> {
        match run(&self.ctx, args.run_id, options(JOB)).await {
            // Another worker holds or took over the run; it decides the outcome.
            Ok(_) | Err(LedgerError::LeaseHeld | LedgerError::StaleFence) => Ok(()),
            Err(e) => Err(err(e)),
        }
    }
}

/// Runs (or resumes) briefing run `run_id`. The run row must exist.
pub async fn run(ctx: &AppContext, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
    let storage = PgStorage::new(ctx.db.clone());
    let run = storage.load_run(run_id).await?;
    if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
        return Ok(run.status); // duplicate delivery of a finished run
    }
    let redis = redis_client(ctx).map_err(lerr)?;
    let chunks = vec![CHUNK.to_owned()];
    run_chunked(&storage, &redis, run_id, chunks, opts, |_, _| {
        deliver(ctx, &storage, &run)
    })
    .await
}

async fn deliver(ctx: &AppContext, storage: &PgStorage, run: &RunRow) -> LResult<ChunkOutcome> {
    let db = &ctx.db;
    let Some(c) = live_connection(db, run).await? else {
        return Ok(outcome("skipped", "not_deliverable"));
    };
    let link_base = Settings::get(ctx).web_base_url;
    let Some(b) = briefing(db, &c, run.key.scheduled_at, Utc::now(), &link_base)
        .await
        .map_err(lerr)?
    else {
        return Ok(outcome("skipped", "nothing_changed"));
    };
    let text = render_text(&b);
    let out = Out {
        ctx,
        storage,
        run,
        organisation_id: c.organisation_id,
        connection_id: Some(c.id),
        kind: BRIEFING,
    };
    let integration = slack_integration(db, c.organisation_id)
        .await
        .map_err(lerr)?;
    let channel = route(db, &c, integration.is_some())
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
    } else if revoke_notice_due(db, &c, run.key.scheduled_at)
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
    for o in owners(db, c.organisation_id).await.map_err(lerr)? {
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

const REVOKED_NOTICE: &str = "Slack disconnected: OpsAgent's access was revoked. Briefings come \
     by email until an owner reconnects Slack.\n\n";
// shortcut: the channel notice still comes only from the run that found the channel gone (a
// weekly finding it first clears the channel silently); derive it from stored state like the
// revoke notice once connections record when their channel was cleared.
const CHANNEL_GONE_NOTICE: &str = "Slack channel unavailable: it was archived or deleted. \
     Briefings come by email until a new channel is chosen.\n\n";
