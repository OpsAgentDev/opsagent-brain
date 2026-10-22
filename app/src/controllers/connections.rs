use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DurationRound, NaiveTime, TimeDelta, Utc};
use loco_rs::{
    app::AppContext,
    bgworker::BackgroundWorker,
    controller::Routes,
    prelude::{get, post},
};
use opsagent_connectors::aws::client::{parse_role_arn, short_id};
use opsagent_core::{
    connection::{transition, ConnectionEvent as E, ConnectionStatus as S},
    run::RunKey,
};
use opsagent_ledger::Storage;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    api_error::{ApiError, ApiJson},
    middleware::org_scope::OrgScope,
    models::{
        _entities::{connection_credentials, connection_verifications, connections},
        audit,
        connections::{
            cas, open_creds, org_dek, seal_creds, status_of, status_str, Creds, TEMPLATE_VERSION,
        },
        ledger_storage::PgStorage,
        now,
        organisations::valid_name,
    },
    workers::verify::{VerifyArgs, VerifyWorker},
};

fn hhmm(t: Option<NaiveTime>) -> Option<String> {
    t.map(|t| t.format("%H:%M").to_string())
}

/// Grant labels are `action on resources when ...`; the API shows action names only.
fn grant_names(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|g| g.split(" on ").next().unwrap_or(g).to_owned())
        .collect()
}

fn view(c: &connections::Model, last: Option<&connection_verifications::Model>) -> Value {
    json!({
        "id": c.id, "provider": c.provider, "display_name": c.display_name,
        "status": c.status, "status_reason": c.status_reason,
        "external_account_id": c.external_account_id, "template_version": c.template_version,
        "scan_time_local": hhmm(c.scan_time_local), "briefing_time_local": hhmm(c.briefing_time_local),
        "api_rate_ceiling": c.api_rate_ceiling,
        "first_connected_at": c.first_connected_at, "billable_from": c.billable_from,
        "created_at": c.created_at,
        "last_verification": last.map(|v| json!({
            "outcome": v.outcome, "at": v.created_at,
            "assume_with_ok": v.assume_with_ok, "assume_without_denied": v.assume_without_denied,
            "policy_matches": v.policy_matches,
            "extra_grants": grant_names(&v.extra_grants), "missing_grants": grant_names(&v.missing_grants),
        })),
    })
}

fn stack_name(organisation_id: Uuid) -> String {
    format!("OpsAgent-Read-{}", short_id(&organisation_id))
}

fn disconnected() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "connection_disconnected",
        "This connection was disconnected. Start a new connection instead.",
    )
}

fn fake_enabled() -> bool {
    std::env::var("OPSAGENT_CONNECTORS").as_deref() == Ok("fake")
}

/// Org-filtered lookup: another org's id is the same 404 as an unknown one.
async fn find(
    ctx: &AppContext,
    scope: &OrgScope,
    id: &str,
) -> Result<connections::Model, ApiError> {
    let id: Uuid = id.parse().map_err(|_| ApiError::not_found())?;
    connections::Entity::find_by_id(id)
        .filter(connections::Column::OrganisationId.eq(scope.organisation_id))
        .one(&ctx.db)
        .await?
        .ok_or_else(ApiError::not_found)
}

fn quick_create_url(organisation_id: Uuid, external_id: &str) -> Result<String, ApiError> {
    let principal = std::env::var("OPSAGENT_AWS_OUTBOUND_ROLE_ARN")
        .map_err(|_| ApiError::internal("OPSAGENT_AWS_OUTBOUND_ROLE_ARN is not set"))?;
    let base = std::env::var("OPSAGENT_TEMPLATE_BASE_URL")
        .unwrap_or_else(|_| "https://templates.opsagent.dev".into());
    let template = format!(
        "{}/aws/opsagent-read-role-v{TEMPLATE_VERSION}.yaml",
        base.trim_end_matches('/')
    );
    let e = |s: &str| urlencoding::encode(s).into_owned();
    Ok(format!(
        "https://console.aws.amazon.com/cloudformation/home#/stacks/quickcreate?templateURL={}&stackName={}\
         &param_ExternalId={}&param_OpsAgentPrincipal={}&param_OrgShortId={}&param_TemplateVersion={TEMPLATE_VERSION}",
        e(&template),
        stack_name(organisation_id),
        e(external_id),
        e(&principal),
        short_id(&organisation_id),
    ))
}

#[derive(Deserialize)]
struct NewConnection {
    provider: String,
    display_name: String,
}

async fn create(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiJson(body): ApiJson<NewConnection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    scope.require_owner()?;
    let name = valid_name(&body.display_name)?;
    let fake = match body.provider.as_str() {
        "aws" => false,
        "fake" if fake_enabled() => true,
        _ => return Err(ApiError::invalid("provider must be aws")),
    };
    let org_id = scope.organisation_id;
    let creds = Creds {
        external_id: Uuid::new_v4().to_string(),
        role_arn: None,
        fake_account: fake.then(|| name.clone()),
    };
    let url = if fake {
        None
    } else {
        Some(quick_create_url(org_id, &creds.external_id)?)
    };
    let dek = org_dek(&ctx.db, org_id).await?;
    let sealed = seal_creds(&dek, org_id, &creds)?;
    let id = Uuid::new_v4();
    let txn = ctx.db.begin().await?;
    connections::ActiveModel {
        id: Set(id),
        organisation_id: Set(org_id),
        provider: Set(body.provider.clone()),
        external_account_id: Set(None),
        display_name: Set(Some(name)),
        status: Set(status_str(S::Pending)),
        status_reason: Set(None),
        template_version: Set((!fake).then(|| TEMPLATE_VERSION.to_owned())),
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
    connection_credentials::ActiveModel {
        connection_id: Set(id),
        kind: Set(if fake { "fake" } else { "aws_role" }.into()),
        ciphertext: Set(sealed.ciphertext),
        nonce: Set(sealed.nonce.to_vec()),
        kek_version: Set(dek.version),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(&txn)
    .await?;
    audit::record(
        &txn,
        Some(org_id),
        scope.user_id,
        "connection.create",
        Some(("connection", id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "quick_create_url": url, "template_version": TEMPLATE_VERSION })),
    ))
}

async fn list(
    State(ctx): State<AppContext>,
    scope: OrgScope,
) -> Result<Json<Vec<Value>>, ApiError> {
    let rows = connections::Entity::find()
        .filter(connections::Column::OrganisationId.eq(scope.organisation_id))
        .order_by_asc(connections::Column::CreatedAt)
        .all(&ctx.db)
        .await?;
    Ok(Json(rows.iter().map(|c| view(c, None)).collect()))
}

async fn show(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let c = find(&ctx, &scope, &id).await?;
    let last = connection_verifications::Entity::find()
        .filter(connection_verifications::Column::ConnectionId.eq(c.id))
        .order_by_desc(connection_verifications::Column::CreatedAt)
        .one(&ctx.db)
        .await?;
    Ok(Json(view(&c, last.as_ref())))
}

#[derive(Deserialize)]
struct Patch {
    display_name: Option<String>,
    scan_time_local: Option<String>,
    briefing_time_local: Option<String>,
    api_rate_ceiling: Option<i32>,
}

fn valid_hhmm(field: &str, s: &str) -> Result<NaiveTime, ApiError> {
    (s.len() == 5)
        .then(|| NaiveTime::parse_from_str(s, "%H:%M").ok())
        .flatten()
        .ok_or_else(|| ApiError::invalid(format!("{field} must be HH:MM")))
}

async fn update(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(body): ApiJson<Patch>,
) -> Result<Json<Value>, ApiError> {
    scope.require_owner()?;
    let c = find(&ctx, &scope, &id).await?;
    if status_of(&c)? == S::Disconnected {
        return Err(disconnected());
    }
    let mut a: connections::ActiveModel = c.into();
    if let Some(n) = &body.display_name {
        a.display_name = Set(Some(valid_name(n)?));
    }
    if let Some(t) = &body.scan_time_local {
        a.scan_time_local = Set(Some(valid_hhmm("scan_time_local", t)?));
    }
    if let Some(t) = &body.briefing_time_local {
        a.briefing_time_local = Set(Some(valid_hhmm("briefing_time_local", t)?));
    }
    if let Some(r) = body.api_rate_ceiling {
        if r < 1 {
            return Err(ApiError::invalid("api_rate_ceiling must be at least 1"));
        }
        a.api_rate_ceiling = Set(Some(r));
    }
    a.updated_at = Set(now());
    Ok(Json(view(&a.update(&ctx.db).await?, None)))
}

#[derive(Deserialize)]
struct VerifyBody {
    #[serde(default)]
    role_arn: String,
}

async fn verify(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(body): ApiJson<VerifyBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    scope.require_owner()?;
    let c = find(&ctx, &scope, &id).await?;
    let from = status_of(&c)?;
    if from == S::Disconnected {
        return Err(disconnected());
    }
    let dek = org_dek(&ctx.db, c.organisation_id).await?;
    let cred_row = connection_credentials::Entity::find_by_id(c.id)
        .one(&ctx.db)
        .await?
        .ok_or_else(|| ApiError::internal("connection has no credentials"))?;
    let mut creds = open_creds(&dek, c.organisation_id, &cred_row)?;
    if c.provider == "aws" {
        let arn = parse_role_arn(body.role_arn.trim())
            .map_err(|_| ApiError::invalid("role_arn must be an IAM role ARN"))?;
        if arn.partition != "aws" {
            return Err(ApiError::invalid(format!(
                "the {} partition is not supported",
                arn.partition
            )));
        }
        creds.role_arn = Some(body.role_arn.trim().to_owned());
    }
    let to = match from {
        S::Pending => transition(from, E::StackReported),
        S::Revoked => transition(from, E::RoleReturned),
        s => Ok(s),
    }
    .map_err(ApiError::internal)?;
    let sealed = seal_creds(&dek, c.organisation_id, &creds)?;
    let txn = ctx.db.begin().await?;
    let mut cr: connection_credentials::ActiveModel = cred_row.into();
    cr.ciphertext = Set(sealed.ciphertext);
    cr.nonce = Set(sealed.nonce.to_vec());
    cr.kek_version = Set(dek.version);
    cr.updated_at = Set(now());
    cr.update(&txn).await?;
    let (org_id, conn_id) = (c.organisation_id, c.id);
    // Guarded on the status read above, so a concurrent Disconnect or worker outcome is not lost.
    let mut a = <connections::ActiveModel as ActiveModelTrait>::default();
    if to != from {
        a.status = Set(status_str(to));
    }
    a.updated_at = Set(now());
    if !cas(&txn, &c, a).await? {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "connection_state_changed",
            "The connection changed while this request ran. Reload and try again.",
        ));
    }
    audit::record(
        &txn,
        Some(org_id),
        scope.user_id,
        "connection.verify_requested",
        Some(("connection", conn_id.to_string())),
    )
    .await?;
    txn.commit().await?;
    // Ledger first: the run row exists before the job is enqueued, so a lost enqueue is
    // recoverable from `runs` and a duplicate request in the same minute is the same run.
    let run = PgStorage::new(ctx.db.clone())
        .create_run(RunKey {
            organisation_id: Some(org_id),
            connection_id: Some(conn_id),
            job_type: "verify".into(),
            scheduled_at: Utc::now()
                .duration_trunc(TimeDelta::minutes(1))
                .map_err(ApiError::internal)?,
        })
        .await
        .map_err(ApiError::internal)?;
    VerifyWorker::perform_later(&ctx, VerifyArgs { run_id: run.id }).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "run_id": run.id }))))
}

async fn disconnect(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    scope.require_owner()?;
    let c = find(&ctx, &scope, &id).await?;
    let (org_id, conn_id) = (c.organisation_id, c.id);
    // Already disconnected: answer the same way (idempotent DELETE).
    if let Ok(to) = transition(status_of(&c)?, E::Disconnect) {
        let txn = ctx.db.begin().await?;
        let mut a: connections::ActiveModel = c.into();
        a.status = Set(status_str(to));
        a.status_reason = Set(Some("customer_disconnected".into()));
        a.updated_at = Set(now());
        a.update(&txn).await?;
        audit::record(
            &txn,
            Some(org_id),
            scope.user_id,
            "connection.disconnect",
            Some(("connection", conn_id.to_string())),
        )
        .await?;
        txn.commit().await?;
    }
    Ok(Json(json!({
        "status": "disconnected",
        "next_step": format!(
            "Delete the CloudFormation stack {} in your account to revoke access.",
            stack_name(org_id)
        ),
    })))
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("/v1/orgs/{org}/connections")
        .add("/", post(create).get(list))
        .add("/{id}", get(show).patch(update).delete(disconnect))
        .add("/{id}/verify", post(verify))
}
