use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DurationRound, NaiveTime, TimeDelta, Utc};
use loco_rs::{app::AppContext, bgworker::BackgroundWorker};
use opsagent_connectors::aws::client::{parse_role_arn, short_id};
use opsagent_core::{
    connection::{transition, ConnectionEvent as E, ConnectionStatus as S},
    run::RunKey,
};
use opsagent_ledger::Storage;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, OrgPath, RunAccepted};
use crate::{
    api_error::{ApiError, ApiJson, Problem},
    middleware::org_scope::OrgScope,
    models::{
        _entities::{connection_credentials, connection_verifications, connections},
        audit,
        connections::{
            cas, open_creds, org_dek, seal_creds, status_of, status_str, Creds, TEMPLATE_VERSION,
        },
        find_in_org,
        ledger_storage::PgStorage,
        now,
        organisations::valid_name,
    },
    views::connections::{view, Connection},
    workers::verify::{VerifyArgs, VerifyWorker},
};

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

async fn find(
    ctx: &AppContext,
    scope: &OrgScope,
    id: &str,
) -> Result<connections::Model, ApiError> {
    find_in_org::<connections::Entity>(
        &ctx.db,
        connections::Column::OrganisationId,
        scope.organisation_id,
        id,
    )
    .await
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

#[derive(Deserialize, ToSchema)]
pub struct NewConnection {
    /// `aws`.
    pub provider: String,
    pub display_name: String,
}

#[derive(Serialize, ToSchema)]
pub struct CreatedConnection {
    pub id: Uuid,
    /// CloudFormation quick-create link for the read role; null for test providers.
    pub quick_create_url: Option<String>,
    pub template_version: String,
}

#[utoipa::path(post, path = "/orgs/{org}/connections", tag = "connections", params(OrgPath),
    request_body = NewConnection,
    responses((status = 201, body = CreatedConnection), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn create(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiJson(body): ApiJson<NewConnection>,
) -> Result<(StatusCode, Json<CreatedConnection>), ApiError> {
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
        Json(CreatedConnection {
            id,
            quick_create_url: url,
            template_version: TEMPLATE_VERSION.into(),
        }),
    ))
}

#[utoipa::path(get, path = "/orgs/{org}/connections", tag = "connections", params(OrgPath),
    responses((status = 200, body = Vec<Connection>), (status = 404, body = Problem)))]
async fn list(
    State(ctx): State<AppContext>,
    scope: OrgScope,
) -> Result<Json<Vec<Connection>>, ApiError> {
    let rows = connections::Entity::find()
        .filter(connections::Column::OrganisationId.eq(scope.organisation_id))
        .order_by_asc(connections::Column::CreatedAt)
        .all(&ctx.db)
        .await?;
    Ok(Json(rows.iter().map(|c| view(c, None)).collect()))
}

#[utoipa::path(get, path = "/orgs/{org}/connections/{id}", tag = "connections", params(OrgIdPath),
    responses((status = 200, body = Connection), (status = 404, body = Problem)))]
async fn show(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Connection>, ApiError> {
    let c = find(&ctx, &scope, &id).await?;
    let last = connection_verifications::Entity::find()
        .filter(connection_verifications::Column::ConnectionId.eq(c.id))
        .order_by_desc(connection_verifications::Column::CreatedAt)
        .one(&ctx.db)
        .await?;
    Ok(Json(view(&c, last.as_ref())))
}

#[derive(Deserialize, ToSchema)]
pub struct ConnectionPatch {
    pub display_name: Option<String>,
    /// `HH:MM`.
    pub scan_time_local: Option<String>,
    /// `HH:MM`.
    pub briefing_time_local: Option<String>,
    /// At least 1.
    pub api_rate_ceiling: Option<i32>,
}

fn valid_hhmm(field: &str, s: &str) -> Result<NaiveTime, ApiError> {
    (s.len() == 5)
        .then(|| NaiveTime::parse_from_str(s, "%H:%M").ok())
        .flatten()
        .ok_or_else(|| ApiError::invalid(format!("{field} must be HH:MM")))
}

#[utoipa::path(patch, path = "/orgs/{org}/connections/{id}", tag = "connections", params(OrgIdPath),
    request_body = ConnectionPatch,
    responses((status = 200, body = Connection), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem), (status = 422, body = Problem)))]
async fn update(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(body): ApiJson<ConnectionPatch>,
) -> Result<Json<Connection>, ApiError> {
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

#[derive(Deserialize, ToSchema)]
pub struct VerifyBody {
    /// The read role's ARN from the stack outputs (required for `aws`).
    #[serde(default)]
    pub role_arn: String,
}

#[utoipa::path(post, path = "/orgs/{org}/connections/{id}/verify", tag = "connections", params(OrgIdPath),
    request_body = VerifyBody,
    responses((status = 202, body = RunAccepted), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem), (status = 422, body = Problem)))]
async fn verify(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(body): ApiJson<VerifyBody>,
) -> Result<(StatusCode, Json<RunAccepted>), ApiError> {
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
        .map_err(ApiError::internal)?
        .run;
    VerifyWorker::perform_later(&ctx, VerifyArgs { run_id: run.id }).await?;
    Ok((StatusCode::ACCEPTED, Json(RunAccepted { run_id: run.id })))
}

#[derive(Serialize, ToSchema)]
pub struct Disconnected {
    /// Always `disconnected`.
    pub status: String,
    pub next_step: String,
}

#[utoipa::path(delete, path = "/orgs/{org}/connections/{id}", tag = "connections", params(OrgIdPath),
    responses((status = 200, body = Disconnected), (status = 403, body = Problem), (status = 404, body = Problem)))]
async fn disconnect(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Disconnected>, ApiError> {
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
    Ok(Json(Disconnected {
        status: "disconnected".into(),
        next_step: format!(
            "Delete the CloudFormation stack {} in your account to revoke access.",
            stack_name(org_id)
        ),
    }))
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(create, list))
        .routes(routes!(show, update, disconnect))
        .routes(routes!(verify))
}
