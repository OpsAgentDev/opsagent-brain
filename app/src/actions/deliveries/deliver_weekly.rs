//! `deliver_weekly` (delivery.md): a connection run emails the weekly to its route's
//! recipients (the owners when none are set) and posts it to its Slack channel; an
//! organisation run (no connection) emails one summary of every connection to the owners.
//! Opt-in non-members get the unsubscribe footer; members do not.
use opsagent_core::{connection::Connection, run::RunStatus};
use opsagent_deliver::{
    model::{Weekly, WeeklyExtras},
    render_html, render_slack, render_text,
    repo::{SENT, WEEKLY},
    route::Recipient,
    weekly::build_weekly,
};
use opsagent_ledger::{run_chunked, ChunkOutcome, LedgerError, RunChunkedOptions, RunRow};
use uuid::Uuid;

use super::{
    delivery_out::Out,
    outcome,
    snapshots::{deliverable, live_connection, route},
    Kit,
};
use crate::{
    actions::recipients::tokens::unsubscribe_url,
    actions::runs::classify::{lerr, LResult},
    mailers::{magic_link::mail_safe_name, Mail},
};

const EMAIL: &str = "email";
const SLACK: &str = "slack";
const SUMMARY: &str = "summary";

#[derive(Clone)]
pub struct DeliverWeekly {
    kit: Kit,
}

impl DeliverWeekly {
    pub fn new(kit: Kit) -> Self {
        Self { kit }
    }

    /// Runs (or resumes) weekly run `run_id`: chunks `email`, `slack` for a connection,
    /// `summary` for an organisation. The run row must exist.
    pub async fn run(&self, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
        let storage = self.kit.uow.ledger();
        let run = storage.load_run(run_id).await?;
        if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
            return Ok(run.status); // duplicate delivery of a finished run
        }
        let chunks = match run.key.connection_id {
            Some(_) => vec![EMAIL.to_owned(), SLACK.to_owned()],
            None => vec![SUMMARY.to_owned()],
        };
        run_chunked(
            storage,
            &self.kit.redis,
            run_id,
            chunks,
            opts,
            |chunk, _| self.step(&run, chunk),
        )
        .await
    }

    async fn step(&self, run: &RunRow, chunk: String) -> LResult<ChunkOutcome> {
        let org = run.key.organisation_id.ok_or(LedgerError::NotFound)?;
        let out = Out {
            kit: &self.kit,
            run,
            organisation_id: org,
            connection_id: run.key.connection_id,
            kind: WEEKLY,
        };
        if chunk == SUMMARY {
            return self.summary(&out).await;
        }
        let r = &*self.kit.uow;
        let Some(c) = live_connection(r, run).await? else {
            return Ok(outcome("skipped", "not_deliverable"));
        };
        let w = self.weekly(&c).await?;
        let integration = r.integrations().active_slack(org).await.map_err(lerr)?;
        let rt = route(r, &c, integration.is_some()).await.map_err(lerr)?;
        if chunk == EMAIL {
            let to = match rt.recipients {
                v if v.is_empty() => r.recipients().owners(org).await.map_err(lerr)?,
                v => v,
            };
            for rc in &to {
                let mail = self.weekly_mail(&w, rc);
                out.email(&format!("weekly:{}", rc.id), mail, rc.member, SENT)
                    .await?;
            }
            return Ok(outcome(EMAIL, "done"));
        }
        if let (Some(i), Some(ch)) = (&integration, &rt.slack_channel) {
            if let Err(e) = out.slack(WEEKLY, i, &c, ch, &render_slack(&w)).await? {
                if let Some(retry) = out.retry_later(&e) {
                    return Err(retry);
                }
            }
        }
        Ok(outcome(SLACK, "done"))
    }

    /// The weekly for `c` over the last 7 days.
    async fn weekly(&self, c: &Connection) -> LResult<Weekly> {
        let now = self.kit.clock.now();
        let d = self.kit.uow.deliveries();
        let (org, id) = (c.organisation_id, c.id);
        let conn = d.connection_snapshot(org, id).await.map_err(lerr)?;
        let findings = d
            .finding_snapshots(org, id, now - chrono::Duration::days(7))
            .await
            .map_err(lerr)?;
        // shortcut: spend, restore-test dates, untagged spend and write candidates are not
        // stored yet, so those sections read "not tracked yet"/unknown; fill them when the
        // scan persists them.
        Ok(build_weekly(
            &conn,
            &findings,
            None,
            &WeeklyExtras::default(),
            now,
            &self.kit.web_base_url,
        ))
    }

    fn weekly_mail(&self, w: &Weekly, to: &Recipient) -> Mail {
        let k = &self.kit;
        let (mut text, mut html) = (render_text(w), render_html(w));
        if !to.member {
            let url = unsubscribe_url(&k.web_base_url, &k.unsubscribe_key, to.id);
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
    async fn summary(&self, out: &Out<'_>) -> LResult<ChunkOutcome> {
        let (r, org) = (&*self.kit.uow, out.organisation_id);
        if r.orgs().is_deleted(org).await.map_err(lerr)? {
            return Ok(outcome("skipped", "organisation_deleted"));
        }
        let all = r.connections().list(org).await.map_err(lerr)?;
        let mut live: Vec<_> = all.into_iter().filter(deliverable).collect();
        match live.len() {
            0 => return Ok(outcome("skipped", "no_connections")),
            // The connection's own weekly already reaches the owners; a summary would repeat it.
            1 => return Ok(outcome("skipped", "single_connection")),
            _ => {}
        }
        live.sort_by_key(|c| c.created_at);
        let mut parts = Vec::new();
        for c in &live {
            parts.push(render_text(&self.weekly(c).await?));
        }
        let name = r
            .orgs()
            .get(org)
            .await
            .map_err(lerr)?
            .map(|o| o.name)
            .unwrap_or_default();
        let subject = format!("OpsAgent weekly summary: {}", mail_safe_name(&name));
        let text = parts.join("\n----\n\n");
        for o in r.recipients().owners(org).await.map_err(lerr)? {
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
}
