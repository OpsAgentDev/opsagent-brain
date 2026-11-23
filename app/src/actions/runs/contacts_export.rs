//! The weekly contacts export (crm-plan.md, section 5): one CSV row per organisation owner,
//! written over `contacts/contacts-v1.csv` in a private bucket. Switched off by default
//! (`CRM_EXPORT_ENABLED`). The file is customer data: it is never logged, only its row count.
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::run::RunStatus;
use opsagent_ledger::{
    effects::with_effect, redis, ChunkOutcome, LedgerError, RunChunkedOptions, RunRow,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    classify::{lerr, LResult},
    clean_source, one_chunk_run,
};
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// The one object the export keeps; the bucket's lifecycle expires old versions.
pub const OBJECT_KEY: &str = "contacts/contacts-v1.csv";

const HEADER: &str = "email,name,company,product,external_id,kind,plan,status,signed_up_at,source,marketing_ok,opted_out";

/// An organisation owner as the database holds them, before the export's mapping.
#[derive(Debug, Clone)]
pub struct OwnerRow {
    pub email: String,
    pub name: Option<String>,
    pub org_id: Uuid,
    pub org_name: String,
    pub org_created_at: DateTime<Utc>,
    pub org_deleted: bool,
    pub billing_tier: Option<String>,
    pub billing_status: String,
    pub utm_source: Option<String>,
    pub marketing_ok: bool,
    /// The owner unsubscribed through `/unsubscribe` (a global `email_suppressions` row).
    pub opted_out: bool,
}

/// Reads every organisation owner across all organisations, internal accounts left out.
#[async_trait]
pub trait ContactRows: Send + Sync {
    async fn owners(&self) -> AppResult<Vec<OwnerRow>>;
}

/// Where the CSV goes. `put` overwrites the object at `key`.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &str, body: Vec<u8>) -> AppResult<()>;
}

#[derive(Clone)]
pub struct ContactsExport {
    rows: Arc<dyn ContactRows>,
    store: Arc<dyn ObjectStore>,
    uow: Arc<dyn UnitOfWork>,
    redis: redis::Client,
    enabled: bool,
}

impl ContactsExport {
    pub fn new(
        rows: Arc<dyn ContactRows>,
        store: Arc<dyn ObjectStore>,
        uow: Arc<dyn UnitOfWork>,
        redis: redis::Client,
        enabled: bool,
    ) -> Self {
        Self {
            rows,
            store,
            uow,
            redis,
            enabled,
        }
    }

    /// Runs (or resumes) the week's run `run_id`; its schedule slot is the once-per-week.
    pub async fn run(&self, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
        let export = |run: RunRow| async move { self.export(&run).await };
        one_chunk_run(&*self.uow, &self.redis, run_id, opts, export).await
    }

    async fn export(&self, run: &RunRow) -> LResult<ChunkOutcome> {
        if !self.enabled {
            return Ok(outcome(None));
        }
        let owners = self.rows.owners().await.map_err(lerr)?;
        let count = owners.len();
        let body = render(&owners).into_bytes();
        // An overwrite of one key, so a re-run after a crash is safe.
        with_effect(
            self.uow.ledger(),
            run.id,
            "contacts_export",
            true,
            || async {
                self.store.put(OBJECT_KEY, body).await.map_err(|_| {
                    tracing::error!(error_code = "export_failed", "contacts export write failed");
                    LedgerError::Job {
                        code: "export_failed".into(),
                        retry: true,
                    }
                })?;
                Ok(None)
            },
        )
        .await?;
        Ok(outcome(Some(count)))
    }
}

fn outcome(rows: Option<usize>) -> ChunkOutcome {
    ChunkOutcome {
        stats: json!({ "rows": rows }),
        ..Default::default()
    }
}

/// The billing state in the export format's vocabulary.
fn status(o: &OwnerRow) -> &'static str {
    if o.org_deleted {
        return "deleted";
    }
    match o.billing_status.as_str() {
        "active" => "active",
        "past_due" => "past_due",
        "paused" | "canceled" | "trial_ended" => "canceled",
        _ => "trial",
    }
}

/// One CSV cell: control characters stripped, a leading `= + - @` defused with a `'`, quoted
/// when it holds a comma or a quote.
fn cell(v: &str) -> String {
    let mut s: String = v.chars().filter(|c| !c.is_control()).collect();
    if s.starts_with(['=', '+', '-', '@']) {
        s.insert(0, '\'');
    }
    if s.contains([',', '"']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn line(o: &OwnerRow) -> String {
    let deleted = o.org_deleted;
    let blank = |v: &str| if deleted { String::new() } else { v.to_owned() };
    let source = match o.utm_source.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => clean_source(s),
        None => "unknown".into(),
    };
    let fields = [
        o.email.to_lowercase(),
        blank(o.name.as_deref().unwrap_or("")),
        blank(&o.org_name),
        "opsagent".into(),
        o.org_id.to_string(),
        "customer".into(),
        o.billing_tier.clone().unwrap_or_else(|| "trial".into()),
        status(o).into(),
        o.org_created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        source,
        o.marketing_ok.to_string(),
        o.opted_out.to_string(),
    ];
    fields.map(|f| cell(&f)).join(",")
}

/// The whole file: the header, then a row per owner, each ended by a newline.
pub fn render(owners: &[OwnerRow]) -> String {
    let mut out = format!("{HEADER}\n");
    for o in owners {
        out.push_str(&line(o));
        out.push('\n');
    }
    out
}
