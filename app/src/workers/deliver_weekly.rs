//! `deliver_weekly` job (delivery.md): a connection run emails the weekly to its route's
//! recipients (the owners when none are set) and posts it to its Slack channel; an
//! organisation run (no connection) emails one summary of every connection to the owners.
//! Opt-in non-members get the unsubscribe footer; members do not.
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_core::org::OrganisationsRepo;
use opsagent_core::run::RunStatus;
use opsagent_deliver::{
    model::{Weekly, WeeklyExtras},
    render_html, render_slack, render_text,
    repo::{DeliveriesRepo, IntegrationsRepo, RecipientsRepo},
    route::Recipient,
    weekly::build_weekly,
};
use opsagent_ledger::{run_chunked, ChunkOutcome, LedgerError, RunChunkedOptions, RunRow, Storage};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    common::{err, lerr, redis_client, LResult},
    delivery::Out,
};
use crate::{
    adapters::db::Pg,
    mailers::{magic_link::mail_safe_name, Mail},
    models::{
        _entities::{connections, organisations as orgs},
        ledger_storage::PgStorage,
    },
    services::{
        deliveries::{deliverable, live_connection, options, outcome, route, SENT, WEEKLY},
        recipients::unsubscribe_url,
    },
    settings::Settings,
};

pub const JOB: &str = "deliver_weekly";
const LEASE_TTL: Duration = Duration::from_secs(120);
const EMAIL: &str = "email";
const SLACK: &str = "slack";
const SUMMARY: &str = "summary";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverWeeklyArgs {
    pub run_id: Uuid,
}

pub struct DeliverWeeklyWorker {
    ctx: AppContext,
}

#[async_trait]
impl BackgroundWorker<DeliverWeeklyArgs> for DeliverWeeklyWorker {
    fn build(ctx: &AppContext) -> Self {
        Self { ctx: ctx.clone() }
    }

    async fn perform(&self, args: DeliverWeeklyArgs) -> Result<()> {
        let opts = RunChunkedOptions {
            lease_ttl: LEASE_TTL,
            ..options(JOB)
        };
        match run(&self.ctx, args.run_id, opts).await {
            Ok(_) | Err(LedgerError::LeaseHeld | LedgerError::StaleFence) => Ok(()),
            Err(e) => Err(err(e)),
        }
    }
}

/// Runs (or resumes) weekly run `run_id`: chunks `email`, `slack` for a connection, `summary`
/// for an organisation. The run row must exist.
pub async fn run(ctx: &AppContext, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
    let storage = PgStorage::new(ctx.db.clone());
    let run = storage.load_run(run_id).await?;
    if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
        return Ok(run.status); // duplicate delivery of a finished run
    }
    let redis = redis_client(ctx).map_err(lerr)?;
    let chunks = match run.key.connection_id {
        Some(_) => vec![EMAIL.to_owned(), SLACK.to_owned()],
        None => vec![SUMMARY.to_owned()],
    };
    run_chunked(&storage, &redis, run_id, chunks, opts, |chunk, _| {
        step(ctx, &storage, &run, chunk)
    })
    .await
}

async fn step(
    ctx: &AppContext,
    storage: &PgStorage,
    run: &RunRow,
    chunk: String,
) -> LResult<ChunkOutcome> {
    let org = run.key.organisation_id.ok_or(LedgerError::NotFound)?;
    let out = Out {
        ctx,
        storage,
        run,
        organisation_id: org,
        connection_id: run.key.connection_id,
        kind: WEEKLY,
    };
    if chunk == SUMMARY {
        return summary(&out).await;
    }
    let Some(c) = live_connection(&ctx.db, run).await? else {
        return Ok(outcome("skipped", "not_deliverable"));
    };
    let w = weekly(ctx, &c).await?;
    let repo = Pg::new(&ctx.db);
    let integration = repo.active_slack(org).await.map_err(lerr)?;
    let r = route(&ctx.db, &c, integration.is_some())
        .await
        .map_err(lerr)?;
    if chunk == EMAIL {
        let to = match r.recipients {
            v if v.is_empty() => repo.owners(org).await.map_err(lerr)?,
            v => v,
        };
        let s = Settings::get(ctx);
        for rc in &to {
            let mail = weekly_mail(&w, rc, &s);
            out.email(&format!("weekly:{}", rc.id), mail, rc.member, SENT)
                .await?;
        }
        return Ok(outcome(EMAIL, "done"));
    }
    if let (Some(i), Some(ch)) = (&integration, &r.slack_channel) {
        if let Err(e) = out.slack(WEEKLY, i, &c, ch, &render_slack(&w)).await? {
            if let Some(retry) = out.retry_later(&e) {
                return Err(retry);
            }
        }
    }
    Ok(outcome(SLACK, "done"))
}

/// The weekly for `c` over the last 7 days.
async fn weekly(ctx: &AppContext, c: &connections::Model) -> LResult<Weekly> {
    let now = Utc::now();
    let repo = Pg::new(&ctx.db);
    let (org, id) = (c.organisation_id, c.id);
    let conn = repo.connection_snapshot(org, id).await.map_err(lerr)?;
    let findings = repo
        .finding_snapshots(org, id, now - chrono::Duration::days(7))
        .await
        .map_err(lerr)?;
    // shortcut: spend, restore-test dates, untagged spend and write candidates are not stored
    // yet, so those sections read "not tracked yet"/unknown; fill them when the scan persists them.
    let link_base = Settings::get(ctx).web_base_url;
    Ok(build_weekly(
        &conn,
        &findings,
        None,
        &WeeklyExtras::default(),
        now,
        &link_base,
    ))
}

fn weekly_mail(w: &Weekly, to: &Recipient, s: &Settings) -> Mail {
    let (mut text, mut html) = (render_text(w), render_html(w));
    if !to.member {
        let url = unsubscribe_url(&s.web_base_url, s.unsubscribe_key(), to.id);
        text += &format!("\nUnsubscribe: {url}\n");
        let footer = format!("<p><a href=\"{url}\">Unsubscribe</a></p>\n</body>");
        html = html.replacen("</body>", &footer, 1);
    }
    Mail {
        to: to.email.clone(),
        subject: format!(
            "OpsAgent weekly report: {}",
            mail_safe_name(&w.connection_name)
        ),
        text,
        html: Some(html),
        idempotency_key: None,
    }
}

/// One email to each owner with every deliverable connection's weekly, in creation order;
/// skipped with fewer than two, where it would only repeat the connection's own weekly.
async fn summary(out: &Out<'_>) -> LResult<ChunkOutcome> {
    let (ctx, org) = (out.ctx, out.organisation_id);
    if Pg::new(&ctx.db).is_deleted(org).await.map_err(lerr)? {
        return Ok(outcome("skipped", "organisation_deleted"));
    }
    let all = connections::Entity::find()
        .filter(connections::Column::OrganisationId.eq(org))
        .all(&ctx.db)
        .await
        .map_err(lerr)?;
    let mut parts = Vec::new();
    let mut live: Vec<_> = all.into_iter().filter(deliverable).collect();
    match live.len() {
        0 => return Ok(outcome("skipped", "no_connections")),
        // The connection's own weekly already reaches the owners; a summary would repeat it.
        1 => return Ok(outcome("skipped", "single_connection")),
        _ => {}
    }
    live.sort_by_key(|c| c.created_at);
    for c in &live {
        parts.push(render_text(&weekly(ctx, c).await?));
    }
    let name = orgs::Entity::find_by_id(org)
        .one(&ctx.db)
        .await
        .map_err(lerr)?
        .map(|o| o.name)
        .unwrap_or_default();
    let subject = format!("OpsAgent weekly summary: {}", mail_safe_name(&name));
    let text = parts.join("\n----\n\n");
    for o in Pg::new(&ctx.db).owners(org).await.map_err(lerr)? {
        let mail = Mail {
            to: o.email,
            subject: subject.clone(),
            text: text.clone(),
            ..Default::default()
        };
        out.email(&format!("summary:{}", o.id), mail, o.member, SENT)
            .await?;
    }
    Ok(outcome(SUMMARY, "done"))
}
