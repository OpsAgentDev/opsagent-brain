//! The paid-review notice: an outbox run queued by the Stripe webhook in the transaction that
//! marks the request paid, so the paid state never depends on the mail provider. The
//! `deliver_review_notice` job sends the founder and requester mails, each once (side-effect
//! ledger), and retries what is missing with the ledger's backoff.
use std::sync::Arc;

use opsagent_core::{
    human_review::ReviewRequest,
    run::{RunKey, RunStatus},
};
use opsagent_ledger::{
    effects::with_effect, redis, run_chunked, ChunkOutcome, JobKind, LedgerError, NewJob,
    RunChunkedOptions, RunRow,
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    actions::{
        runs::classify::{lerr, LResult},
        uow::{Tx, UnitOfWork},
    },
    error::{AppError, AppResult},
    mailers::{
        human_review::{founder_paid, paid_confirmation, Notice},
        magic_link::mail_safe_name,
        Mail, Mailer,
    },
};

const CHUNK: &str = "mail";

/// Creates the notice run for `review` (just marked paid) and its job on `tx`. The run key is
/// the organisation and the `paid_at` instant that `mark_paid` set once, so a redelivered
/// event cannot queue a second notice. A taken key is an error that rolls the webhook back:
/// Stripe's redelivery pays at a new instant.
pub async fn enqueue_notice(tx: &dyn Tx, org: Uuid, review: &ReviewRequest) -> AppResult<()> {
    let at = review
        .paid_at
        .ok_or_else(|| AppError::Internal("paid review without paid_at".into()))?;
    let key = RunKey {
        organisation_id: Some(org),
        connection_id: None,
        job_type: JobKind::DeliverReviewNotice.as_str().into(),
        scheduled_at: at,
    };
    let out = tx.ledger().create_run(key).await?;
    if !out.created {
        return Err(AppError::Internal(
            "paid review notice run key taken".into(),
        ));
    }
    let job = NewJob {
        kind: JobKind::DeliverReviewNotice,
        run_id: out.run.id,
        run_at: at,
    };
    tx.queue().enqueue(job).await?;
    Ok(())
}

/// `deliver_review_notice`: sends a paid request's two mails under the run's ledger lease.
#[derive(Clone)]
pub struct DeliverReviewNotice {
    uow: Arc<dyn UnitOfWork>,
    redis: redis::Client,
    mailer: Arc<dyn Mailer>,
    contact_to: String,
}

impl DeliverReviewNotice {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        redis: redis::Client,
        mailer: Arc<dyn Mailer>,
        contact_to: String,
    ) -> Self {
        Self {
            uow,
            redis,
            mailer,
            contact_to,
        }
    }

    /// Runs (or resumes) notice run `run_id`. A mail that fails ends the run `Queued` for a
    /// retry (1 min, 5, 15, 60); the mails already sent are not sent again.
    pub async fn run(&self, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
        let storage = self.uow.ledger();
        let run = storage.load_run(run_id).await?;
        if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
            return Ok(run.status); // duplicate delivery of a finished run
        }
        let chunks = vec![CHUNK.to_owned()];
        run_chunked(storage, &self.redis, run_id, chunks, opts, |_, _| {
            self.send(&run)
        })
        .await
    }

    async fn send(&self, run: &RunRow) -> LResult<ChunkOutcome> {
        let org = run.key.organisation_id.ok_or(LedgerError::NotFound)?;
        let r = &*self.uow;
        let review = r.human_reviews().paid_at(org, run.key.scheduled_at);
        let (review, organisation) = (review.await.map_err(lerr)?, r.orgs().get(org).await);
        let (Some(review), Some(organisation)) = (review, organisation.map_err(lerr)?) else {
            tracing::warn!(run = %run.id, "paid review notice for a request or organisation that is gone");
            return Ok(ChunkOutcome {
                stats: json!({ "skip_reason": "gone" }),
                ..Default::default()
            });
        };
        let check_id = match review.finding_id {
            Some(id) => r.findings().get(org, id).await.map_err(lerr)?,
            None => None,
        };
        let reference = match (review.finding_id, review.connection_id, check_id) {
            (Some(id), _, Some(f)) => format!("finding {} ({id})", f.key.check_id),
            (Some(id), _, None) => format!("finding {id}"),
            (_, Some(id), _) => format!("connection {id}"),
            _ => String::new(),
        };
        let notice = Notice {
            org_name: &mail_safe_name(&organisation.name),
            org_slug: &organisation.slug,
            requester: &review.requester_email,
            kind: review.kind,
            price_cents: review.price_cents,
            // Stored through `mail_safe_name` when asked.
            label: &review.target_label,
            reference: &reference,
            note: review.note.as_deref(),
        };
        let mails = [
            ("founder", founder_paid(&self.contact_to, &notice)),
            ("requester", paid_confirmation(&notice)),
        ];
        // Both are tried even if the first fails, so one bad address cannot hold back the other.
        let mut failed = false;
        for (who, mail) in mails {
            failed |= !self.send_once(run.id, review.id, who, mail).await?;
        }
        if failed {
            return Err(LedgerError::Job {
                code: "mail_failed".into(),
                retry: true,
            });
        }
        Ok(ChunkOutcome {
            stats: json!({ "sent": 2 }),
            ..Default::default()
        })
    }

    /// Sends `mail` unless the run's ledger says it went out. `false`: the send failed (logged).
    /// A crash mid-send re-sends under the same Idempotency-Key, which Resend delivers once.
    async fn send_once(&self, run: Uuid, review: Uuid, who: &str, mail: Mail) -> LResult<bool> {
        let key = format!("human_review:{review}:paid:{who}");
        let mail = Mail {
            idempotency_key: Some(key.clone()),
            ..mail
        };
        let sent = with_effect(self.uow.ledger(), run, &key, true, || async {
            match self.mailer.send(mail).await {
                Ok(()) => Ok(None),
                Err(_) => {
                    tracing::error!(error_code = "mail_failed", who, "paid review mail failed");
                    Err(LedgerError::Job {
                        code: "mail_failed".into(),
                        retry: true,
                    })
                }
            }
        })
        .await;
        match sent {
            Err(LedgerError::Job { .. }) => Ok(false),
            r => r.map(|_| true),
        }
    }
}
