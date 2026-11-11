use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::user::Email;
use sea_orm::{ConnectionTrait, DatabaseConnection, FromQueryResult};
use uuid::Uuid;

use super::ledger_storage::stmt;
use crate::{
    actions::waitlist::{AnnounceStore, WaitlistStore},
    error::AppResult,
};

pub struct PgWaitlist(pub DatabaseConnection);

#[derive(FromQueryResult)]
struct Id {
    id: Uuid,
}

#[async_trait]
impl WaitlistStore for PgWaitlist {
    async fn insert(
        &self,
        email: &Email,
        source: Option<&str>,
        token_hash: &str,
    ) -> AppResult<Option<Uuid>> {
        // RETURNING is empty for a verified address, or one mailed within the resend window
        // (a concurrent duplicate's mail has not gone yet, so it is skipped too).
        let row = Id::find_by_statement(stmt(
            "INSERT INTO waitlist_entries (id, email, source, verify_token_hash) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (email) DO UPDATE SET verify_token_hash = EXCLUDED.verify_token_hash \
             WHERE waitlist_entries.verified_at IS NULL \
               AND COALESCE(waitlist_entries.confirmation_sent_at, waitlist_entries.created_at) \
                 < now() - make_interval(secs => $5) \
             RETURNING id",
            vec![
                Uuid::now_v7().into(),
                email.as_str().into(),
                source.map(str::to_owned).into(),
                token_hash.into(),
                (crate::actions::waitlist::RESEND_AFTER_SECS as f64).into(),
            ],
        ))
        .one(&self.0)
        .await
        .map_err(super::db_err)?;
        Ok(row.map(|r| r.id))
    }

    async fn verify(&self, token_hash: &str, at: DateTime<Utc>) -> AppResult<bool> {
        let done = self
            .0
            .execute_raw(stmt(
                "UPDATE waitlist_entries SET verified_at = $2, verify_token_hash = NULL \
                 WHERE verify_token_hash = $1 AND verified_at IS NULL",
                vec![token_hash.into(), at.into()],
            ))
            .await
            .map_err(super::db_err)?;
        Ok(done.rows_affected() == 1)
    }

    async fn mark_confirmed(&self, id: Uuid, at: DateTime<Utc>) -> AppResult<()> {
        self.0
            .execute_raw(stmt(
                "UPDATE waitlist_entries SET confirmation_sent_at = $2 WHERE id = $1",
                vec![id.into(), at.into()],
            ))
            .await
            .map_err(super::db_err)?;
        Ok(())
    }
}

#[derive(FromQueryResult)]
struct Unannounced {
    id: Uuid,
    email: String,
}

#[async_trait]
impl AnnounceStore for PgWaitlist {
    async fn unannounced(&self) -> AppResult<Vec<(Uuid, String)>> {
        let rows = Unannounced::find_by_statement(stmt(
            "SELECT id, email FROM waitlist_entries WHERE announced_at IS NULL \
             AND verified_at IS NOT NULL ORDER BY created_at",
            vec![],
        ))
        .all(&self.0)
        .await
        .map_err(super::db_err)?;
        Ok(rows.into_iter().map(|r| (r.id, r.email)).collect())
    }

    async fn mark_announced(&self, id: Uuid, at: DateTime<Utc>) -> AppResult<()> {
        self.0
            .execute_raw(stmt(
                "UPDATE waitlist_entries SET announced_at = $2 WHERE id = $1",
                vec![id.into(), at.into()],
            ))
            .await
            .map_err(super::db_err)?;
        Ok(())
    }
}
