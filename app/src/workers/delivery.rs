//! Shared by `deliver_briefing` and `deliver_weekly`: one email or one Slack post per run and
//! effect key (side-effect ledger), each with its `deliveries` row. Logs codes only: never
//! message text, tokens or addresses (logging.md).
use loco_rs::app::AppContext;
use opsagent_ledger::{effects::with_effect, retry::backoff, EffectState, LedgerError, RunRow};
use uuid::Uuid;

use super::common::{lerr, LResult};
use crate::{
    adapters::slack::SlackError,
    app::kek,
    mailers::Mail,
    middleware::{mailer, slack},
    models::{
        _entities::{connections, integrations},
        integrations::open_token,
        ledger_storage::PgStorage,
    },
    services::{
        deliveries::{clear_channel, mark_revoked, record, Row, FAILED, SENT, SUPPRESSED},
        mail_guard,
    },
};

/// The run delivering, and what its rows are about.
pub(crate) struct Out<'a> {
    pub ctx: &'a AppContext,
    pub storage: &'a PgStorage,
    pub run: &'a RunRow,
    pub organisation_id: Uuid,
    pub connection_id: Option<Uuid>,
    pub kind: &'static str,
}

impl Out<'_> {
    async fn row(&self, key: &str, channel: &str, target: &str, status: &str) -> LResult<()> {
        self.row_ref(key, channel, target, status, None).await
    }

    async fn row_ref(
        &self,
        key: &str,
        channel: &str,
        target: &str,
        status: &str,
        external_ref: Option<String>,
    ) -> LResult<()> {
        let row = Row {
            organisation_id: self.organisation_id,
            connection_id: self.connection_id,
            kind: self.kind,
            channel,
            target,
            status,
            external_ref,
        };
        record(&self.ctx.db, self.run.id, key, row)
            .await
            .map_err(lerr)
    }

    /// Mails `mail` once for effect `key` (`Idempotency-Key` `{run_id}:{key}`); its row gets
    /// `status`. A refusal by `mail_guard` sends nothing and writes the row `suppressed`.
    /// `member`: the address is a member or owner (`Recipient.member`).
    pub async fn email(
        &self,
        key: &str,
        mut mail: Mail,
        member: bool,
        status: &str,
    ) -> LResult<()> {
        let db = &self.ctx.db;
        let to = mail.to.clone();
        if !mail_guard::may_deliver(db, self.organisation_id, &to, member)
            .await
            .map_err(lerr)?
        {
            return self.row(key, "email", &to, SUPPRESSED).await;
        }
        mail.idempotency_key = Some(format!("{}:{key}", self.run.id));
        let mailer = mailer(self.ctx);
        with_effect(self.storage, self.run.id, key, true, || async move {
            mailer.send(mail).await.map(|()| None).map_err(|_| {
                tracing::warn!(error_code = "mail_failed", "delivery mail failed");
                LedgerError::Job {
                    code: "mail_failed".into(),
                    retry: true,
                }
            })
        })
        .await?;
        self.row(key, "email", &to, status).await
    }

    /// Posts `text` to `channel` once for effect `key` (`client_msg_id` `{run_id}:{key}`). On
    /// a Slack error the row is `failed`, a revoked token marks the integration `revoked`, a
    /// gone channel is cleared from `c`, and the error is handed back for the fallback.
    pub async fn slack(
        &self,
        key: &str,
        i: &integrations::Model,
        c: &connections::Model,
        channel: &str,
        text: &str,
    ) -> LResult<Result<(), SlackError>> {
        let db = &self.ctx.db;
        let kek = kek(self.ctx).map_err(lerr)?;
        let token = open_token(db, kek.as_ref(), i)
            .await
            .map_err(|_| LedgerError::Job {
                code: "token_unreadable".into(),
                retry: false,
            })?;
        let (client, msg_id) = (slack(self.ctx), format!("{}:{key}", self.run.id));
        let mut failed = None;
        // shortcut: a crash between the post and the ledger record, or a retried lost response,
        // reposts, since Slack does not guarantee `client_msg_id` dedupe; accept until Slack
        // offers an idempotent post.
        let res = with_effect(self.storage, self.run.id, key, true, || async {
            match client.post_message(&token, channel, text, &msg_id).await {
                Ok(ts) => Ok(Some(ts)),
                Err(e) => {
                    let code = e.code().to_owned();
                    failed = Some(e);
                    Err(LedgerError::Job { code, retry: true })
                }
            }
        })
        .await;
        let e = match (res, failed) {
            (Ok(EffectState::Done(ts)), _) => {
                self.row_ref(key, "slack", channel, SENT, ts).await?;
                return Ok(Ok(()));
            }
            (Ok(_), _) => return Ok(Ok(())), // not reached: idempotent effects always run
            (Err(_), Some(e)) => e,
            (Err(e), None) => return Err(e),
        };
        tracing::warn!(error_code = e.code(), "slack post failed");
        match e {
            SlackError::Revoked => mark_revoked(db, i).await.map_err(lerr)?,
            SlackError::ChannelGone => clear_channel(db, c, channel).await.map_err(lerr)?,
            _ => {}
        }
        self.row(key, "slack", channel, FAILED).await?;
        Ok(Err(e))
    }

    /// For a rate limit or outage while retries remain: the error that parks the run for its
    /// next backoff step. `None`: fall back now.
    pub fn retry_later(&self, e: &SlackError) -> Option<LedgerError> {
        (e.retryable() && backoff(self.run.attempts).is_some()).then(|| LedgerError::Job {
            code: format!("slack_{}", e.code()),
            retry: true,
        })
    }
}

/// Slack mrkdwn as plain mail text: `<url|label>` becomes `label: url`, entities unescaped.
pub(crate) fn plain(mrkdwn: &str) -> String {
    let mut out = String::with_capacity(mrkdwn.len());
    let mut rest = mrkdwn;
    while let Some(open) = rest.find('<') {
        out += &rest[..open];
        let after = &rest[open + 1..];
        let Some(close) = after.find('>') else {
            rest = &rest[open..];
            break;
        };
        let link = &after[..close];
        out += &match link.split_once('|') {
            Some((url, label)) => format!("{label}: {url}"),
            None => link.to_owned(),
        };
        rest = &after[close + 1..];
    }
    out += rest;
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::plain;

    #[test]
    fn links_unwrap_and_entities_unescape() {
        assert_eq!(
            plain("*Hi* a &lt;b&gt; &amp;lt;\n<https://x.test/c/1|Open the dashboard>"),
            "*Hi* a <b> &lt;\nOpen the dashboard: https://x.test/c/1"
        );
        assert_eq!(plain("no links"), "no links");
    }
}
