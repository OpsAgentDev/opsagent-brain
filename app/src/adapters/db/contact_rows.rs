//! The contacts export's read of every organisation owner.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, FromQueryResult};
use uuid::Uuid;

use super::{db_err, ledger_storage::stmt};
use crate::{
    actions::runs::{ContactRows, OwnerRow},
    error::AppResult,
};

pub struct PgContactRows(pub DatabaseConnection);

#[derive(FromQueryResult)]
struct Row {
    email: String,
    name: Option<String>,
    org_id: Uuid,
    org_name: String,
    org_created_at: DateTime<Utc>,
    org_deleted: bool,
    billing_tier: Option<String>,
    billing_status: String,
    utm_source: Option<String>,
    marketing_ok: bool,
    opted_out: bool,
}

#[async_trait]
impl ContactRows for PgContactRows {
    async fn owners(&self) -> AppResult<Vec<OwnerRow>> {
        // tenancy: the operator's export across all organisations, one row per owner;
        // @opsagent.dev owners are left out. The opt-out is the global `unsubscribed`
        // suppression `/unsubscribe` writes, keyed by the SHA-256 of the lower-cased email.
        let sql = "SELECT u.email, u.name, o.id AS org_id, o.name AS org_name, \
             o.created_at AS org_created_at, o.deleted_at IS NOT NULL AS org_deleted, \
             o.billing_tier, o.billing_status, o.signup_source->>'utm_source' AS utm_source, \
             u.marketing_ok, \
             EXISTS (SELECT 1 FROM email_suppressions s WHERE s.organisation_id IS NULL \
               AND s.reason = 'unsubscribed' \
               AND s.email_hash = encode(sha256(convert_to(lower(u.email), 'UTF8')), 'hex')) AS opted_out \
             FROM members m JOIN organisations o ON o.id = m.organisation_id \
             JOIN users u ON u.id = m.user_id \
             WHERE m.role = 'owner' AND lower(u.email) NOT LIKE '%@opsagent.dev' \
             ORDER BY o.created_at, o.id, u.email";
        let rows = Row::find_by_statement(stmt(sql, vec![]))
            .all(&self.0)
            .await
            .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|r| OwnerRow {
                email: r.email,
                name: r.name,
                org_id: r.org_id,
                org_name: r.org_name,
                org_created_at: r.org_created_at,
                org_deleted: r.org_deleted,
                billing_tier: r.billing_tier,
                billing_status: r.billing_status,
                utm_source: r.utm_source,
                marketing_ok: r.marketing_ok,
                opted_out: r.opted_out,
            })
            .collect())
    }
}
