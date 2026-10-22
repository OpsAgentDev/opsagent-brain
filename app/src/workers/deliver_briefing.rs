//! `deliver_briefing` job (delivery.md, PRD 7.6): the morning briefing to the connection's Slack
//! channel; to the owners by email when Slack is not routed, revoked, gone, or still failing
//! once retries are spent. Nothing changed since the last briefing: no message, no row.
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_core::run::RunStatus;
use opsagent_deliver::render_text;
use opsagent_ledger::{run_chunked, ChunkOutcome, LedgerError, RunChunkedOptions, RunRow, Storage};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::{
    common::{err, lerr, redis_client, LResult},
    delivery::{plain, Out},
};
use crate::{
    adapters::slack::SlackError,
    mailers::{magic_link::mail_safe_name, Mail},
    models::{_entities::connections, ledger_storage::PgStorage, organisations},
    services::deliveries::{
        briefing, deliverable, owners, route, slack_integration, BRIEFING, FALLBACK_EMAIL,
    },
    settings::Settings,
};

pub const JOB: &str = "deliver_briefing";
const LEASE_TTL: Duration = Duration::from_secs(60);
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

/// Lease options for a delivery job.
pub fn options(job: &str) -> RunChunkedOptions {
    RunChunkedOptions {
        worker_id: format!("{job}-{}", Uuid::new_v4()),
        lease_ttl: LEASE_TTL,
        heartbeat_every: Duration::from_secs(20),
        ..Default::default()
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

pub(crate) fn outcome(key: &str, value: &str) -> ChunkOutcome {
    ChunkOutcome {
        stats: json!({ key: value }),
    }
}

/// The run's connection, or `None` when its organisation is deleted or it takes no deliveries.
pub(crate) async fn live_connection(
    db: &DatabaseConnection,
    run: &RunRow,
) -> LResult<Option<connections::Model>> {
    let id = run.key.connection_id.ok_or(LedgerError::NotFound)?;
    let c = connections::Entity::find_by_id(id)
        .filter(connections::Column::OrganisationId.eq(run.key.organisation_id))
        .one(db)
        .await
        .map_err(lerr)?
        .ok_or(LedgerError::NotFound)?;
    let gone = organisations::deleted(db, c.organisation_id)
        .await
        .map_err(lerr)?;
    Ok((!gone && deliverable(&c)).then_some(c))
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
    let mut notice = None;
    if let (Some(i), Some(ch)) = (&integration, &channel) {
        match out.slack(BRIEFING, i, &c, ch, &text).await? {
            Ok(()) => return Ok(outcome("delivered", "slack")),
            Err(e) => match out.retry_later(&e) {
                Some(retry) => return Err(retry),
                None => notice = notice_for(&e),
            },
        }
    }
    let subject = format!(
        "OpsAgent morning briefing: {}",
        mail_safe_name(c.display_name.as_deref().unwrap_or(&c.provider))
    );
    let body = format!("{}{}", notice.unwrap_or_default(), plain(&text));
    for o in owners(db, c.organisation_id).await.map_err(lerr)? {
        let mail = Mail {
            to: o.email,
            subject: subject.clone(),
            text: body.clone(),
            ..Default::default()
        };
        out.email(&format!("fallback:{}", o.id), mail, FALLBACK_EMAIL)
            .await?;
    }
    Ok(outcome("delivered", "fallback_email"))
}

/// The one-time note on the run that found Slack unusable (later runs skip Slack silently).
fn notice_for(e: &SlackError) -> Option<&'static str> {
    match e {
        SlackError::Revoked => Some(
            "Slack disconnected: OpsAgent's access was revoked. Briefings come by email until \
             an owner reconnects Slack.\n\n",
        ),
        SlackError::ChannelGone => Some(
            "Slack channel unavailable: it was archived or deleted. Briefings come by email \
             until a new channel is chosen.\n\n",
        ),
        _ => None,
    }
}
