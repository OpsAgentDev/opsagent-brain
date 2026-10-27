use async_trait::async_trait;
use opsagent_core::user::Email;
use sea_orm::{DatabaseConnection, FromQueryResult};
use uuid::Uuid;

use super::ledger_storage::stmt;
use crate::{actions::waitlist::WaitlistStore, error::AppResult};

pub struct PgWaitlist(pub DatabaseConnection);

#[derive(FromQueryResult)]
struct Id {
    id: Uuid,
}

#[async_trait]
impl WaitlistStore for PgWaitlist {
    async fn insert(&self, email: &Email, source: Option<&str>) -> AppResult<Option<Uuid>> {
        // RETURNING is empty when the email was already there.
        let row = Id::find_by_statement(stmt(
            "INSERT INTO waitlist_entries (id, email, source) VALUES ($1, $2, $3) \
             ON CONFLICT (email) DO NOTHING RETURNING id",
            vec![
                Uuid::now_v7().into(),
                email.as_str().into(),
                source.map(str::to_owned).into(),
            ],
        ))
        .one(&self.0)
        .await
        .map_err(super::db_err)?;
        Ok(row.map(|r| r.id))
    }
}
