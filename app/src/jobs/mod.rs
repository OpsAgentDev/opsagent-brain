//! Job handlers, the `WorkerRunner` that drains the `jobs` table, and the `Scheduler` loop
//! (app-shell.md, jobs).
//! A handler hands its run to one action; the run's ledger decides retries and resume.
mod deliver_alert;
mod deliver_briefing;
mod deliver_weekly;
mod full_scan;
mod runner;
mod scheduler;
mod verify;
mod watch_scan;

use async_trait::async_trait;
use opsagent_core::run::RunStatus;
use opsagent_ledger::{JobKind, LedgerError};
use uuid::Uuid;

use crate::error::AppResult;

pub use deliver_alert::DeliverAlertJob;
pub use deliver_briefing::DeliverBriefingJob;
pub use deliver_weekly::DeliverWeeklyJob;
pub use full_scan::FullScanJob;
pub use runner::WorkerRunner;
pub use scheduler::Scheduler;
pub use verify::VerifyJob;
pub use watch_scan::WatchScanJob;

#[async_trait]
pub trait JobHandler: Send + Sync {
    fn kind(&self) -> JobKind;
    async fn handle(&self, run_id: Uuid) -> AppResult<()>;
}

/// A chunked run's result as a job's: another worker holding or having taken over the run
/// decides its outcome, so this job is done.
fn settled(out: Result<RunStatus, LedgerError>) -> AppResult<()> {
    match out {
        Ok(_) | Err(LedgerError::LeaseHeld | LedgerError::StaleFence) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    /// Provider error text can name the customer's role and account (logging.md), so a
    /// `tracing` field must carry the error's code, never its Display. Line-based grep:
    /// flags a Display-formatted `error` field on a line that mentions a connector, provider
    /// or AWS error, and any such field in the connectors crate.
    /// shortcut: misses a provider error bound to a neutral name on another line; upgrade to
    /// a clippy lint if one slips through review.
    #[test]
    fn no_provider_error_is_logged_by_display() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        walk(&root.join("app/src"), &mut files);
        for c in std::fs::read_dir(root.join("crates")).unwrap().flatten() {
            if c.path().join("src").is_dir() {
                walk(&c.path().join("src"), &mut files);
            }
        }
        let needle = concat!("error", " = %");
        let mut hits = Vec::new();
        for f in &files {
            let in_connectors = f.components().any(|c| c.as_os_str() == "connectors");
            for (i, line) in std::fs::read_to_string(f).unwrap().lines().enumerate() {
                let l = line.to_lowercase();
                let provider = ["connectorerror", "provider", "aws"]
                    .iter()
                    .any(|w| l.contains(w));
                if line.contains(needle) && (provider || in_connectors) {
                    hits.push(format!("{}:{}: {}", f.display(), i + 1, line.trim()));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "log error_code, not the error:\n{}",
            hits.join("\n")
        );
    }
}
