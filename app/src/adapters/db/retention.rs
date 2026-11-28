use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::{RepoError, RepoResult},
    retention::{DueOrg, PurgeCounts, RetentionRepo, TtlTable, ACCOUNT_DELETED, ORG_PURGED},
};
use sea_orm::ConnectionTrait;
use uuid::Uuid;

use super::ledger_storage::stmt;
use super::{db_err, Conn, Pg};

/// One statement: the magic links' NO ACTION key is checked at its end, after the CTE
/// removed them. A user with a live link is mid-sign-in and is kept.
const DELETE_UNPROVEN_USERS: &str = concat!(
    "WITH doomed AS (SELECT u.id FROM users u WHERE u.created_at < $1 AND ",
    never_proved!("(l.used_at IS NOT NULL OR l.expires_at > now())"),
    " ORDER BY u.created_at LIMIT $2 FOR UPDATE SKIP LOCKED), \
  links AS (DELETE FROM magic_links WHERE user_id IN (SELECT id FROM doomed)) \
  DELETE FROM users WHERE id IN (SELECT id FROM doomed)"
);

/// One statement: the clients' NO ACTION keys are checked at its end, after the sibling CTEs
/// removed what pointed at them. A client with an unrevoked grant is still in use and is kept.
// tenancy: clients are global; the grants removed are revoked ones of a registration that
// can no longer be used, whichever organisation they were in.
const DELETE_EXPIRED_CLIENTS: &str = "WITH doomed AS ( \
    SELECT c.client_id FROM oauth_clients c \
    WHERE c.kind = 'dynamic' AND c.expires_at < $1 \
      AND NOT EXISTS (SELECT 1 FROM oauth_grants g \
        WHERE g.client_id = c.client_id AND g.revoked_at IS NULL) \
    ORDER BY c.expires_at LIMIT $2 FOR UPDATE SKIP LOCKED), \
  dead AS (SELECT id FROM oauth_grants WHERE client_id IN (SELECT client_id FROM doomed)), \
  a AS (DELETE FROM oauth_access_tokens WHERE grant_id IN (SELECT id FROM dead)), \
  r AS (DELETE FROM oauth_refresh_tokens WHERE grant_id IN (SELECT id FROM dead)), \
  q AS (DELETE FROM oauth_consent_requests WHERE client_id IN (SELECT client_id FROM doomed) \
    OR grant_id IN (SELECT id FROM dead)), \
  g AS (DELETE FROM oauth_grants WHERE id IN (SELECT id FROM dead)) \
  DELETE FROM oauth_clients WHERE client_id IN (SELECT client_id FROM doomed)";

/// The column each table expires on.
fn expiry_column(t: TtlTable) -> &'static str {
    match t {
        TtlTable::ResourceHistory => "observed_at",
        TtlTable::ApiCallsRaw => "called_at",
        TtlTable::Sessions => "expiry_date",
        TtlTable::ChatSessions => "last_message_at",
        TtlTable::AiUsage => "created_at",
        // A date, compared with the cutoff instant as midnight.
        TtlTable::CostDaily => "day::timestamptz",
        _ => "expires_at",
    }
}

/// The prunable-run rule (retention.md, goal 3), oldest first.
// tenancy: global pruning; every organisation's operational runs go, by age and kind alone.
const PRUNE_RUNS: &str = "WITH picked AS ( \
  SELECT r.id FROM runs r \
  WHERE r.scheduled_at < $1 \
    AND r.status IN ('done', 'partial', 'failed', 'skipped') \
    AND (r.job_type IN ('watch_scan', 'deliver_alert', 'billing_sync') OR r.status = 'skipped' \
         OR (r.job_type = 'billing_notice' AND r.scheduled_at < $1 - interval '46 days')) \
    AND NOT EXISTS (SELECT 1 FROM finding_events e WHERE e.run_id = r.id) \
    AND NOT EXISTS (SELECT 1 FROM evidence v WHERE v.run_id = r.id) \
    AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.first_seen_run_id = r.id) \
    AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.last_seen_run_id = r.id) \
    AND NOT EXISTS (SELECT 1 FROM side_effects s \
                    WHERE s.run_id = r.id AND s.effect_key LIKE 'alert:baseline%') \
  ORDER BY r.scheduled_at LIMIT $2), \
se AS (DELETE FROM side_effects WHERE run_id IN (SELECT id FROM picked)), \
st AS (DELETE FROM api_call_stats WHERE run_id IN (SELECT id FROM picked)), \
raw AS (DELETE FROM api_calls_raw WHERE run_id IN (SELECT id FROM picked)), \
rh AS (DELETE FROM resource_history WHERE run_id IN (SELECT id FROM picked)) \
DELETE FROM runs WHERE id IN (SELECT id FROM picked)";

/// Organisation `o` has a queued run, or a running one started after $2 (maybe still live).
macro_rules! busy {
    () => {
        "EXISTS (SELECT 1 FROM runs r WHERE r.organisation_id = o.id \
           AND (r.status = 'queued' \
                OR (r.status = 'running' AND coalesce(r.started_at, r.scheduled_at) > $2)))"
    };
}

/// Deleted organisations past the cutoff $1, each with whether it is busy.
const DUE: &str = concat!(
    "SELECT o.id, ",
    busy!(),
    " AS busy FROM organisations o WHERE o.deleted_at < $1 ORDER BY o.deleted_at"
);

/// Locks organisation $3 if it is still due and not busy.
const LOCK_DUE: &str = concat!(
    "SELECT o.id FROM organisations o WHERE o.id = $3 AND o.deleted_at < $1 AND NOT ",
    busy!(),
    " FOR UPDATE"
);

/// The purged organisation's members who belong to no other organisation.
macro_rules! orphans {
    () => {
        "SELECT m.user_id FROM members m WHERE m.organisation_id = $1 AND NOT EXISTS \
         (SELECT 1 FROM members o WHERE o.user_id = m.user_id AND o.organisation_id <> $1)"
    };
}

/// Every tenant table, children before parents (the foreign keys), each delete scoped to
/// organisation $1; `members` and `users` follow (`PURGE_MEMBERS`), then the organisation.
/// The orphaned users' own rows go here, while their memberships still identify them.
const PURGE: [(&str, &str); 36] = [
    ("audit_events", "DELETE FROM audit_events WHERE organisation_id = $1"),
    ("side_effects", "DELETE FROM side_effects WHERE run_id IN (SELECT id FROM runs WHERE organisation_id = $1)"),
    ("api_call_stats", "DELETE FROM api_call_stats WHERE run_id IN (SELECT id FROM runs WHERE organisation_id = $1)"),
    ("api_calls_raw", "DELETE FROM api_calls_raw WHERE run_id IN (SELECT id FROM runs WHERE organisation_id = $1)"),
    ("jobs", "DELETE FROM jobs WHERE run_id IN (SELECT id FROM runs WHERE organisation_id = $1)"),
    ("resource_history", "DELETE FROM resource_history WHERE resource_id IN \
      (SELECT id FROM resources WHERE organisation_id = $1) \
      OR run_id IN (SELECT id FROM runs WHERE organisation_id = $1)"),
    ("finding_events", "DELETE FROM finding_events WHERE finding_id IN \
      (SELECT id FROM findings WHERE organisation_id = $1) \
      OR run_id IN (SELECT id FROM runs WHERE organisation_id = $1)"),
    ("evidence", "DELETE FROM evidence WHERE finding_id IN \
      (SELECT id FROM findings WHERE organisation_id = $1) \
      OR run_id IN (SELECT id FROM runs WHERE organisation_id = $1)"),
    ("findings", "DELETE FROM findings WHERE organisation_id = $1"),
    ("resources", "DELETE FROM resources WHERE organisation_id = $1"),
    ("deliveries", "DELETE FROM deliveries WHERE organisation_id = $1"),
    ("schedules", "DELETE FROM schedules WHERE organisation_id = $1"),
    ("runs", "DELETE FROM runs WHERE organisation_id = $1"),
    ("recipients", "DELETE FROM recipients WHERE organisation_id = $1"),
    ("human_review_requests", "DELETE FROM human_review_requests WHERE organisation_id = $1"),
    ("oauth_consent_requests", "DELETE FROM oauth_consent_requests WHERE organisation_id = $1 \
      OR grant_id IN (SELECT id FROM oauth_grants WHERE organisation_id = $1)"),
    ("oauth_access_tokens", "DELETE FROM oauth_access_tokens WHERE organisation_id = $1"),
    ("oauth_refresh_tokens", "DELETE FROM oauth_refresh_tokens WHERE organisation_id = $1"),
    ("oauth_grants", "DELETE FROM oauth_grants WHERE organisation_id = $1"),
    ("cost_daily", "DELETE FROM cost_daily WHERE organisation_id = $1"),
    ("connection_credentials", "DELETE FROM connection_credentials WHERE connection_id IN \
      (SELECT id FROM connections WHERE organisation_id = $1)"),
    ("connection_verifications", "DELETE FROM connection_verifications WHERE connection_id IN \
      (SELECT id FROM connections WHERE organisation_id = $1)"),
    ("connections", "DELETE FROM connections WHERE organisation_id = $1"),
    ("integrations", "DELETE FROM integrations WHERE organisation_id = $1"),
    ("invites", "DELETE FROM invites WHERE organisation_id = $1"),
    ("email_suppressions", "DELETE FROM email_suppressions WHERE organisation_id = $1"),
    ("chat_messages", "DELETE FROM chat_messages WHERE organisation_id = $1"),
    ("chat_sessions", "DELETE FROM chat_sessions WHERE organisation_id = $1"),
    ("ai_usage", "DELETE FROM ai_usage WHERE organisation_id = $1"),
    ("explanations", "DELETE FROM explanations WHERE organisation_id = $1"),
    ("ai_credit_grants", "DELETE FROM ai_credit_grants WHERE organisation_id = $1"),
    ("ai_notices", "DELETE FROM ai_notices WHERE organisation_id = $1"),
    ("model_keys", "DELETE FROM model_keys WHERE organisation_id = $1"),
    // tower-sessions rows hold the signed-in user as JSON `"user_id":"<id>"` in `data`.
    ("sessions", concat!("DELETE FROM sessions s USING (", orphans!(), ") u \
      WHERE position(convert_to('\"user_id\":\"' || u.user_id || '\"', 'UTF8') IN s.data) > 0")),
    ("magic_links", concat!("DELETE FROM magic_links WHERE user_id IN (", orphans!(), ")")),
    ("passkeys", concat!("DELETE FROM passkeys WHERE user_id IN (", orphans!(), ")")),
];

/// Memberships, then the users left with none (the outer delete sees the memberships as
/// they were, hence `<> $1`; the users' foreign keys are checked at the statement's end).
const PURGE_MEMBERS: &str =
    "WITH m AS (DELETE FROM members WHERE organisation_id = $1 RETURNING user_id), \
u AS (DELETE FROM users WHERE id IN (SELECT user_id FROM m) AND NOT EXISTS \
  (SELECT 1 FROM members o WHERE o.user_id = users.id AND o.organisation_id <> $1) RETURNING 1) \
SELECT (SELECT count(*) FROM m) AS members, (SELECT count(*) FROM u) AS users";

#[async_trait]
impl<C: Conn> RetentionRepo for Pg<C> {
    async fn delete_expired(
        &self,
        table: TtlTable,
        cutoff: DateTime<Utc>,
        batch: u64,
    ) -> RepoResult<u64> {
        let (t, col) = (table.name(), expiry_column(table));
        // tenancy: global TTL; every organisation's expired rows go, by age alone.
        let sql = format!(
            "DELETE FROM {t} WHERE ctid IN (SELECT ctid FROM {t} WHERE {col} < $1 LIMIT $2)"
        );
        let done = self
            .db()
            .execute_raw(stmt(&sql, vec![cutoff.into(), (batch as i64).into()]))
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected())
    }

    async fn delete_unproven_users(&self, cutoff: DateTime<Utc>, batch: u64) -> RepoResult<u64> {
        // tenancy: users are global; only rows no organisation ever saw are deleted.
        let done = self
            .db()
            .execute_raw(stmt(
                DELETE_UNPROVEN_USERS,
                vec![cutoff.into(), (batch as i64).into()],
            ))
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected())
    }

    async fn delete_expired_clients(&self, cutoff: DateTime<Utc>, batch: u64) -> RepoResult<u64> {
        let done = self
            .db()
            .execute_raw(stmt(
                DELETE_EXPIRED_CLIENTS,
                vec![cutoff.into(), (batch as i64).into()],
            ))
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected())
    }

    async fn prune_runs(&self, older_than: DateTime<Utc>, batch: u64) -> RepoResult<u64> {
        // One statement, so one transaction; the runs' NO ACTION foreign keys are checked at
        // its end, after the sibling CTEs removed the dependents (`jobs` cascades).
        let done = self
            .db()
            .execute_raw(stmt(
                PRUNE_RUNS,
                vec![older_than.into(), (batch as i64).into()],
            ))
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected())
    }

    async fn due_orgs(
        &self,
        deleted_before: DateTime<Utc>,
        busy_since: DateTime<Utc>,
    ) -> RepoResult<Vec<DueOrg>> {
        let rows = self
            .db()
            .query_all_raw(stmt(DUE, vec![deleted_before.into(), busy_since.into()]))
            .await
            .map_err(db_err)?;
        rows.iter()
            .map(|r| {
                Ok(DueOrg {
                    id: r.try_get("", "id").map_err(db_err)?,
                    busy: r.try_get("", "busy").map_err(db_err)?,
                })
            })
            .collect()
    }

    async fn purge_org(
        &self,
        org: Uuid,
        deleted_before: DateTime<Utc>,
        busy_since: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> RepoResult<Option<PurgeCounts>> {
        self.purge_mode().await?;
        let locked = self
            .db()
            .query_one_raw(stmt(
                LOCK_DUE,
                vec![deleted_before.into(), busy_since.into(), org.into()],
            ))
            .await
            .map_err(db_err)?;
        if locked.is_none() {
            return Ok(None);
        }
        let mut counts = PurgeCounts::new();
        for (table, sql) in PURGE {
            let done = self.db().execute_raw(stmt(sql, vec![org.into()])).await;
            counts.insert(table, done.map_err(db_err)?.rows_affected());
        }
        let row = self
            .db()
            .query_one_raw(stmt(PURGE_MEMBERS, vec![org.into()]));
        let row = row
            .await
            .map_err(db_err)?
            .ok_or_else(|| db_err("no counts"))?;
        for table in ["members", "users"] {
            let n: i64 = row.try_get("", table).map_err(db_err)?;
            counts.insert(table, n as u64);
        }
        let done = self.db().execute_raw(stmt(
            "DELETE FROM organisations WHERE id = $1",
            vec![org.into()],
        ));
        counts.insert("organisations", done.await.map_err(db_err)?.rows_affected());
        let meta = serde_json::json!({ "counts": counts });
        let target = Some(("organisation", org.to_string()));
        self.record(ORG_PURGED, target, meta, at).await?;
        Ok(Some(counts))
    }

    async fn erase_account_audit(&self, user_id: Uuid, at: DateTime<Utc>) -> RepoResult<u64> {
        self.purge_mode().await?;
        let done = self
            .db()
            .execute_raw(stmt(
                "DELETE FROM audit_events WHERE organisation_id IS NULL \
                 AND ((actor_type = 'member' AND actor_id = $1) \
                   OR (target_type = 'user' AND target_id = $1))",
                vec![user_id.to_string().into()],
            ))
            .await
            .map_err(db_err)?;
        self.record(ACCOUNT_DELETED, None, serde_json::json!({}), at)
            .await?;
        Ok(done.rows_affected())
    }

    async fn delete_old_purge_records(&self, before: DateTime<Utc>) -> RepoResult<u64> {
        self.purge_mode().await?;
        let done = self
            .db()
            .execute_raw(stmt(
                "DELETE FROM audit_events WHERE organisation_id IS NULL AND action IN ($1, $2) \
                 AND created_at < $3",
                vec![ORG_PURGED.into(), ACCOUNT_DELETED.into(), before.into()],
            ))
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected())
    }
}

impl<C: Conn> Pg<C> {
    /// One organisation-less system record (`org.purged`, `user.delete`) made at `at`.
    async fn record(
        &self,
        action: &str,
        target: Option<(&str, String)>,
        meta: serde_json::Value,
        at: DateTime<Utc>,
    ) -> RepoResult<()> {
        let (kind, id) = target.map(|(k, id)| (k.to_owned(), id)).unzip();
        self.db()
            .execute_raw(stmt(
                "INSERT INTO audit_events (id, organisation_id, actor_type, action, target_type, \
                 target_id, outcome, metadata, created_at, updated_at) \
                 VALUES ($1, NULL, 'system', $2, $3, $4, 'success', $5, $6, $6)",
                vec![
                    Uuid::new_v4().into(),
                    action.into(),
                    kind.into(),
                    id.into(),
                    meta.into(),
                    at.into(),
                ],
            ))
            .await
            .map_err(db_err)?;
        Ok(())
    }

    /// Lets this transaction delete audit rows (the trigger checks the setting). Outside a
    /// transaction SET LOCAL does nothing, so the purge stops here before deleting anything.
    async fn purge_mode(&self) -> RepoResult<()> {
        let db = self.db();
        db.execute_unprepared("SET LOCAL opsagent.purge = 'on'")
            .await
            .map_err(db_err)?;
        let on = db
            .query_one_raw(stmt(
                "SELECT current_setting('opsagent.purge', true) = 'on' AS on",
                vec![],
            ))
            .await
            .map_err(db_err)?
            .and_then(|r| r.try_get::<bool>("", "on").ok());
        if on != Some(true) {
            return Err(RepoError::Storage("purge needs a transaction".into()));
        }
        Ok(())
    }
}
