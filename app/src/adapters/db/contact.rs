use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::user::Email;
use sea_orm::{ConnectionTrait, DatabaseConnection};
use uuid::Uuid;

use super::ledger_storage::stmt;
use crate::{actions::contact::ContactStore, error::AppResult};

pub struct PgContact(pub DatabaseConnection);

#[async_trait]
impl ContactStore for PgContact {
    async fn insert(
        &self,
        name: &str,
        email: &Email,
        topic: &str,
        message: &str,
    ) -> AppResult<Uuid> {
        let id = Uuid::now_v7();
        self.0
            .execute_raw(stmt(
                "INSERT INTO contact_messages (id, name, email, topic, message) \
                 VALUES ($1, $2, $3, $4, $5)",
                vec![
                    id.into(),
                    name.into(),
                    email.as_str().into(),
                    topic.into(),
                    message.into(),
                ],
            ))
            .await
            .map_err(super::db_err)?;
        Ok(id)
    }

    async fn mark_forwarded(&self, id: Uuid, at: DateTime<Utc>) -> AppResult<()> {
        self.0
            .execute_raw(stmt(
                "UPDATE contact_messages SET forwarded_at = $2 WHERE id = $1",
                vec![id.into(), at.into()],
            ))
            .await
            .map_err(super::db_err)?;
        Ok(())
    }
}
