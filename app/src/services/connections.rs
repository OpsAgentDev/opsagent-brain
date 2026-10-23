//! Connection use cases: create, request verification, disconnect (PRD 7.2).
use axum::http::StatusCode;
use chrono::{DurationRound, TimeDelta, Utc};
use loco_rs::app::AppContext;
use opsagent_connectors::{
    registry::{self, ProviderSpec},
    ConnectorError, Registry,
};
use opsagent_core::audit::AuditEntry;
use opsagent_core::{
    connection::{
        transition, Connection, ConnectionEvent as E, ConnectionPatch, ConnectionStatus as S,
        NewConnection,
    },
    run::RunKey,
};
use opsagent_secrets::Kek;
use sea_orm::{DatabaseConnection, TransactionTrait};
use uuid::Uuid;

use crate::{
    actions::uow::Repos,
    adapters::db::Pg,
    api_error::ApiError,
    creds::{self, Creds, Dek},
    models::schedules,
    services::runs,
};

pub const TEMPLATE_VERSION: &str = "1";

pub fn disconnected() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "connection_disconnected",
        "This connection was disconnected. Start a new connection instead.",
    )
}

/// A connection just created, with what the caller needs to show the next step.
pub struct Created {
    pub id: Uuid,
    pub creds: Creds,
    pub spec: ProviderSpec,
}

/// Creates a `pending` connection and its sealed credentials, for owner `actor`.
pub async fn create(
    db: &DatabaseConnection,
    kek: &dyn Kek,
    registry: &Registry,
    organisation_id: Uuid,
    actor: Uuid,
    provider: &str,
    name: String,
) -> Result<Created, ApiError> {
    let spec = registry
        .spec(provider)
        .map_err(|_| ApiError::invalid("provider must be aws"))?;
    let creds = registry::new_creds(provider, Uuid::new_v4().to_string(), &name);
    let txn = db.begin().await?;
    let repos = Pg::new(&txn);
    let sealed = Dek::of(repos.orgs(), kek, organisation_id)
        .await?
        .seal(organisation_id, &creds)?;
    let new = NewConnection {
        organisation_id,
        provider: provider.to_owned(),
        display_name: name,
        template_version: spec.uses_template.then(|| TEMPLATE_VERSION.to_owned()),
        credential_kind: spec.credential_kind.to_owned(),
    };
    let id = repos.connections().insert(new, sealed).await?.id;
    repos
        .audit()
        .record(AuditEntry::member(
            Some(organisation_id),
            actor,
            "connection.create",
            Some(("connection", id.to_string())),
        ))
        .await?;
    txn.commit().await?;
    Ok(Created { id, creds, spec })
}

fn role_error(e: ConnectorError, service: &str) -> ApiError {
    match e {
        ConnectorError::InvalidCredentials(m) => ApiError::invalid(m),
        e => {
            // The code only: provider text can name the customer's role and account.
            tracing::error!(error_code = %e.code(), service, "reported role check failed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "Internal error.",
            )
        }
    }
}

// shortcut: ~53 lines, one use case in one transaction; split when a step gains a second caller.
/// Stores the reported role and queues a `verify` run; returns the run id.
pub async fn request_verify(
    ctx: &AppContext,
    kek: &dyn Kek,
    c: &Connection,
    actor: Uuid,
    role_arn: &str,
) -> Result<Uuid, ApiError> {
    let from = c.status;
    if from == S::Disconnected {
        return Err(disconnected());
    }
    let creds = with_reported_role(&ctx.db, kek, c, from, role_arn).await?;
    let to = match from {
        S::Pending => transition(from, E::StackReported),
        S::Revoked => transition(from, E::RoleReturned),
        s => Ok(s),
    }
    .map_err(ApiError::internal)?;
    let txn = ctx.db.begin().await?;
    let repos = Pg::new(&txn);
    creds::save(&repos, kek, c.organisation_id, c.id, &creds).await?;
    // Guarded on the status read above, so a concurrent Disconnect or worker outcome is not lost.
    let cas = repos
        .connections()
        .cas_status(c.organisation_id, c.id, from, to, None);
    if !cas.await? {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "connection_state_changed",
            "The connection changed while this request ran. Reload and try again.",
        ));
    }
    repos
        .audit()
        .record(AuditEntry::member(
            Some(c.organisation_id),
            actor,
            "connection.verify_requested",
            Some(("connection", c.id.to_string())),
        ))
        .await?;
    txn.commit().await?;
    // A duplicate request in the same minute is the same run.
    let key = RunKey {
        organisation_id: Some(c.organisation_id),
        connection_id: Some(c.id),
        job_type: "verify".into(),
        scheduled_at: Utc::now()
            .duration_trunc(TimeDelta::minutes(1))
            .map_err(ApiError::internal)?,
    };
    Ok(runs::enqueue(ctx, key, Utc::now()).await?.run.id)
}

/// The stored credentials with the reported role. A live connection only re-verifies the
/// role it was verified with: scans must never run under a role that has not passed
/// verification.
async fn with_reported_role(
    db: &DatabaseConnection,
    kek: &dyn Kek,
    c: &Connection,
    from: S,
    raw: &str,
) -> Result<Creds, ApiError> {
    let role = registry::reported_role(&c.provider, raw).map_err(|e| role_error(e, &c.provider))?;
    let mut creds = creds::load(&Pg::new(db), kek, c.organisation_id, c.id).await?;
    if role.is_some() && role != creds.role_arn && matches!(from, S::Connected | S::Degraded) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "role_change_requires_reconnect",
            "This connection is verified with a different role. Disconnect it and connect again to use a new role.",
        ));
    }
    if role.is_some() {
        creds.role_arn = role;
    }
    Ok(creds)
}

/// Disconnects for owner `actor`; already disconnected is a no-op (idempotent DELETE).
pub async fn disconnect(
    db: &DatabaseConnection,
    c: Connection,
    actor: Uuid,
) -> Result<(), ApiError> {
    let (org_id, conn_id) = (c.organisation_id, c.id);
    let txn = db.begin().await?;
    let repos = Pg::new(&txn);
    if !end(&repos, c, "customer_disconnected").await? {
        return Ok(());
    }
    repos
        .audit()
        .record(AuditEntry::member(
            Some(org_id),
            actor,
            "connection.disconnect",
            Some(("connection", conn_id.to_string())),
        ))
        .await?;
    txn.commit().await?;
    Ok(())
}

/// Moves `c` to `disconnected` with `reason` through `repos` (the caller's transaction);
/// `false` if it already was. A status changed since `c` was read is re-read and retried.
pub async fn end(repos: &dyn Repos, mut c: Connection, reason: &str) -> Result<bool, ApiError> {
    let (org, id) = (c.organisation_id, c.id);
    loop {
        let Ok(to) = transition(c.status, E::Disconnect) else {
            return Ok(false);
        };
        let cas = repos
            .connections()
            .cas_status(org, id, c.status, to, Some(reason));
        if cas.await? {
            return Ok(true);
        }
        c = repos
            .connections()
            .get(org, id)
            .await?
            .ok_or_else(ApiError::not_found)?;
    }
}

/// Applies `p`. A new scan time rewrites the nightly `full_scan` schedule, effective from the
/// next local day so today's scan neither repeats nor moves (PRD 7.3). A new briefing time
/// rewrites `deliver_briefing`, effective from its next occurrence.
pub async fn update(
    db: &DatabaseConnection,
    c: Connection,
    p: ConnectionPatch,
) -> Result<Connection, ApiError> {
    if c.status == S::Disconnected {
        return Err(disconnected());
    }
    let (org_id, conn_id) = (c.organisation_id, c.id);
    let (scan_time, briefing_time) = (p.scan_time_local, p.briefing_time_local);
    let txn = db.begin().await?;
    let updated = Pg::new(&txn)
        .connections()
        .update(org_id, conn_id, p)
        .await?;
    if let Some(t) = scan_time {
        let now = Utc::now();
        let from = |tz: &str| schedules::end_of_local_day(tz, now);
        schedules::set_cron(
            &txn,
            org_id,
            conn_id,
            "full_scan",
            &schedules::daily_at(t),
            from,
        )
        .await?;
    }
    if let Some(t) = briefing_time {
        // From now: a later time today still briefs today; an already-sent briefing makes the
        // next one "nothing changed" unless something did.
        let now = Utc::now();
        let cron = schedules::daily_at(t);
        schedules::set_cron(&txn, org_id, conn_id, "deliver_briefing", &cron, |_| {
            Some(now)
        })
        .await?;
    }
    txn.commit().await?;
    Ok(updated)
}
