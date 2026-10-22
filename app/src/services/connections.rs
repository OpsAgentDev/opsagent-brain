//! Connection use cases: create, request verification, disconnect (PRD 7.2).
use axum::http::StatusCode;
use chrono::{DurationRound, NaiveTime, TimeDelta, Utc};
use loco_rs::app::AppContext;
use opsagent_connectors::{
    registry::{self, ProviderSpec},
    ConnectorError, Registry,
};
use opsagent_core::{
    connection::{transition, ConnectionEvent as E, ConnectionStatus as S},
    run::RunKey,
};
use opsagent_secrets::Kek;
use sea_orm::{ActiveModelTrait, ConnectionTrait, DatabaseConnection, Set, TransactionTrait};
use serde_json::json;
use uuid::Uuid;

use crate::{
    api_error::ApiError,
    models::{
        _entities::connections,
        audit,
        connections::{
            cas, insert_creds, load_creds, save_creds, status_of, status_str, Creds,
            TEMPLATE_VERSION,
        },
        now, schedules,
    },
    services::runs,
};

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
    let id = Uuid::new_v4();
    let txn = db.begin().await?;
    connections::ActiveModel {
        id: Set(id),
        organisation_id: Set(organisation_id),
        provider: Set(provider.to_owned()),
        external_account_id: Set(None),
        display_name: Set(Some(name)),
        status: Set(status_str(S::Pending)),
        status_reason: Set(None),
        template_version: Set(spec.uses_template.then(|| TEMPLATE_VERSION.to_owned())),
        scan_time_local: Set(None),
        briefing_time_local: Set(None),
        slack_channel_id: Set(None),
        recipients: Set(json!([])),
        api_rate_ceiling: Set(None),
        first_connected_at: Set(None),
        billable_from: Set(None),
        verify_denied_streak: Set(0),
        verify_denied_first_at: Set(None),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(&txn)
    .await?;
    insert_creds(&txn, kek, organisation_id, id, spec.credential_kind, &creds).await?;
    audit::record(
        &txn,
        Some(organisation_id),
        actor,
        "connection.create",
        Some(("connection", id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok(Created { id, creds, spec })
}

fn role_error(e: ConnectorError) -> ApiError {
    match e {
        ConnectorError::InvalidCredentials(m) => ApiError::invalid(m),
        e => ApiError::internal(e),
    }
}

/// Stores the reported role and queues a `verify` run; returns the run id. A duplicate
/// request in the same minute is the same run.
pub async fn request_verify(
    ctx: &AppContext,
    kek: &dyn Kek,
    c: &connections::Model,
    actor: Uuid,
    role_arn: &str,
) -> Result<Uuid, ApiError> {
    let from = status_of(c)?;
    if from == S::Disconnected {
        return Err(disconnected());
    }
    let role = registry::reported_role(&c.provider, role_arn).map_err(role_error)?;
    let mut creds = load_creds(&ctx.db, kek, c).await?;
    // A live connection only re-verifies the role it was verified with: scans must never run
    // under a role that has not passed verification.
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
    let to = match from {
        S::Pending => transition(from, E::StackReported),
        S::Revoked => transition(from, E::RoleReturned),
        s => Ok(s),
    }
    .map_err(ApiError::internal)?;
    let txn = ctx.db.begin().await?;
    save_creds(&txn, kek, c, &creds).await?;
    // Guarded on the status read above, so a concurrent Disconnect or worker outcome is not lost.
    let mut a = <connections::ActiveModel as ActiveModelTrait>::default();
    if to != from {
        a.status = Set(status_str(to));
    }
    a.updated_at = Set(now());
    if !cas(&txn, c, a).await? {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "connection_state_changed",
            "The connection changed while this request ran. Reload and try again.",
        ));
    }
    audit::record(
        &txn,
        Some(c.organisation_id),
        actor,
        "connection.verify_requested",
        Some(("connection", c.id.to_string())),
    )
    .await?;
    txn.commit().await?;
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

/// Disconnects for owner `actor`; already disconnected is a no-op (idempotent DELETE).
pub async fn disconnect(
    db: &DatabaseConnection,
    c: connections::Model,
    actor: Uuid,
) -> Result<(), ApiError> {
    let (org_id, conn_id) = (c.organisation_id, c.id);
    let txn = db.begin().await?;
    if !end(&txn, c, "customer_disconnected").await? {
        return Ok(());
    }
    audit::record(
        &txn,
        Some(org_id),
        actor,
        "connection.disconnect",
        Some(("connection", conn_id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

/// Moves `c` to `disconnected` with `reason` on `db` (the caller's transaction); `false` if it
/// already was.
pub async fn end(
    db: &impl ConnectionTrait,
    c: connections::Model,
    reason: &str,
) -> Result<bool, ApiError> {
    let Ok(to) = transition(status_of(&c)?, E::Disconnect) else {
        return Ok(false);
    };
    let mut a: connections::ActiveModel = c.into();
    a.status = Set(status_str(to));
    a.status_reason = Set(Some(reason.into()));
    a.updated_at = Set(now());
    a.update(db).await?;
    Ok(true)
}

/// Validated `PATCH` fields; `None` leaves a field as it is.
pub struct Patch {
    pub display_name: Option<String>,
    pub scan_time_local: Option<NaiveTime>,
    pub briefing_time_local: Option<NaiveTime>,
    pub api_rate_ceiling: Option<i32>,
}

/// Applies `p`. A new scan time rewrites the nightly `full_scan` schedule, effective from the
/// next local day so today's scan neither repeats nor moves (PRD 7.3).
pub async fn update(
    db: &DatabaseConnection,
    c: connections::Model,
    p: Patch,
) -> Result<connections::Model, ApiError> {
    if status_of(&c)? == S::Disconnected {
        return Err(disconnected());
    }
    let (org_id, conn_id) = (c.organisation_id, c.id);
    let mut a: connections::ActiveModel = c.into();
    if let Some(n) = p.display_name {
        a.display_name = Set(Some(n));
    }
    if let Some(t) = p.scan_time_local {
        a.scan_time_local = Set(Some(t));
    }
    if let Some(t) = p.briefing_time_local {
        a.briefing_time_local = Set(Some(t));
    }
    if let Some(r) = p.api_rate_ceiling {
        a.api_rate_ceiling = Set(Some(r));
    }
    a.updated_at = Set(now());
    let txn = db.begin().await?;
    let updated = a.update(&txn).await?;
    if let Some(t) = p.scan_time_local {
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
    txn.commit().await?;
    Ok(updated)
}
