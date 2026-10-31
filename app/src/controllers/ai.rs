//! Dashboard AI settings: the switch and ceiling, usage, the organisation's own connections
//! (one per slot) and top-ups.
//! Owner only, except reading the status.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, FixedOffset};
use opsagent_core::ai::{ModelKey, RoleModels, Slot};
use sea_orm::prelude::Decimal;
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::OrgPath;
use crate::{
    actions::ai::{host_of, AiStatus, KeyInput, KeyModel},
    api_error::{ApiError, ApiJson, Problem},
    error::AppError,
    middleware::org_scope::OrgScope,
    state::AppState,
};

/// Credits as a string with 2 decimals.
fn credits(d: Decimal) -> String {
    format!("{:.2}", d)
}

#[derive(Serialize, ToSchema)]
pub struct AiUsageOut {
    /// Credits used on OpsAgent's key this period.
    pub used: String,
    pub quota: String,
    pub topup_balance: String,
    pub period_start: DateTime<FixedOffset>,
    pub period_end: DateTime<FixedOffset>,
    /// Credits on the organisation's own key this calendar month (UTC).
    pub byok_used_this_month: String,
    /// The own key's models have no list price: its credits are estimates.
    pub estimated: bool,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RoleModelsOut {
    pub routine: String,
    pub chat: String,
}

#[derive(Serialize, ToSchema)]
pub struct AiKeyOut {
    /// The API style: `anthropic` or `openai`.
    pub style: String,
    /// The custom endpoint's host; null on the style's official URL.
    pub base_host: Option<String>,
    pub last4: String,
    /// `ok`, `failing` or `provider_outage`.
    pub status: String,
    pub models: RoleModelsOut,
}

#[derive(Serialize, ToSchema)]
pub struct AiKeysOut {
    pub primary: Option<AiKeyOut>,
    /// Tried when the primary fails in a way another endpoint could fix.
    pub backup: Option<AiKeyOut>,
}

#[derive(Serialize, ToSchema)]
pub struct AiStatusOut {
    pub enabled: bool,
    /// `ready`, `ai_disabled`, `ai_unavailable`, `ai_key_failing` or `ai_quota_reached`.
    pub state: String,
    /// `opsagent`, `byok`, or null when neither key is there.
    pub source: Option<String>,
    pub usage: AiUsageOut,
    pub keys: AiKeysOut,
    /// Credits per calendar month (UTC) across both own keys; null is no ceiling.
    pub monthly_credit_ceiling: Option<String>,
    /// Stripe and OpsAgent's key are configured, so top-ups can be bought.
    pub topup_available: bool,
}

fn key_view(k: ModelKey) -> AiKeyOut {
    AiKeyOut {
        style: k.provider.as_str().into(),
        base_host: k.base_url.as_deref().and_then(host_of),
        last4: k.last4,
        status: k.status.as_str().into(),
        models: RoleModelsOut {
            routine: k.models.routine,
            chat: k.models.chat,
        },
    }
}

fn view(s: AiStatus) -> AiStatusOut {
    AiStatusOut {
        enabled: s.enabled,
        state: s.state.into(),
        source: s.source.map(|k| k.as_str().into()),
        usage: AiUsageOut {
            used: credits(s.used),
            quota: credits(s.quota),
            topup_balance: credits(s.topup_balance),
            period_start: s.period.0.fixed_offset(),
            period_end: s.period.1.fixed_offset(),
            byok_used_this_month: credits(s.byok_used_this_month),
            estimated: s.estimated,
        },
        keys: AiKeysOut {
            primary: s.keys.primary.map(key_view),
            backup: s.keys.backup.map(key_view),
        },
        monthly_credit_ceiling: s.ceiling.map(credits),
        topup_available: s.topup_available,
    }
}

#[utoipa::path(get, path = "/orgs/{org}/ai", tag = "ai", params(OrgPath),
    responses((status = 200, body = AiStatusOut), (status = 404, body = Problem)))]
async fn show(State(app): State<AppState>, scope: OrgScope) -> Result<Json<AiStatusOut>, ApiError> {
    Ok(Json(view(app.actions.ai.access.status(&scope).await?)))
}

/// Present (even as null) is `Some`; absent is `None`.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<Decimal>>, D::Error> {
    Option::<Decimal>::deserialize(d).map(Some)
}

/// At least one field.
#[derive(Deserialize, ToSchema)]
pub struct AiPatchIn {
    pub enabled: Option<bool>,
    /// Credits per calendar month (UTC) across both own keys; null removes it.
    #[serde(default, deserialize_with = "present")]
    #[schema(value_type = Option<f64>)]
    pub monthly_credit_ceiling: Option<Option<Decimal>>,
}

#[utoipa::path(patch, path = "/orgs/{org}/ai", tag = "ai", params(OrgPath), request_body = AiPatchIn,
    responses((status = 200, body = AiStatusOut), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 422, body = Problem, description = "`invalid`: no field, or a negative ceiling")))]
async fn patch_ai(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiJson(body): ApiJson<AiPatchIn>,
) -> Result<Json<AiStatusOut>, ApiError> {
    scope.require_owner()?;
    let set = &app.actions.ai.set_ceiling;
    let s = set
        .patch(&scope, body.enabled, body.monthly_credit_ceiling)
        .await?;
    Ok(Json(view(s)))
}

/// `{org}` and `{slot}` path segments, for the OpenAPI document.
#[derive(IntoParams)]
#[into_params(parameter_in = Path)]
pub struct OrgSlotPath {
    /// Organisation slug.
    pub org: String,
    /// `primary` or `backup`; anything else is 404.
    pub slot: String,
}

fn slot(s: &str) -> Result<Slot, ApiError> {
    Slot::parse(s).ok_or_else(|| AppError::NotFound.into())
}

fn role_models(m: RoleModelsOut) -> RoleModels {
    RoleModels {
        routine: m.routine,
        chat: m.chat,
    }
}

#[derive(Deserialize, ToSchema)]
pub struct KeyIn {
    /// The API style: `anthropic` or `openai`.
    pub style: String,
    /// A compatible endpoint's base URL; empty or absent is the style's official URL.
    pub base_url: Option<String>,
    /// Sent once; only its last 4 characters are ever shown again.
    pub api_key: String,
    /// Required (`models_required`) when the endpoint has no models list; else the
    /// defaults from the list.
    pub models: Option<RoleModelsOut>,
}

#[derive(Serialize, ToSchema)]
pub struct KeyModelOut {
    pub id: String,
    /// It can call tools (required for chat).
    pub tools: bool,
    /// `routine`, `chat`, or null: the role the picker preselects it for.
    pub default_for: Option<String>,
}

fn models_view(list: Vec<KeyModel>) -> Vec<KeyModelOut> {
    let out = |m: KeyModel| KeyModelOut {
        id: m.id,
        tools: m.tools,
        default_for: m.default_for.map(|r| r.as_str().into()),
    };
    list.into_iter().map(out).collect()
}

#[derive(Serialize, ToSchema)]
pub struct KeyPutOut {
    pub status: AiStatusOut,
    /// The endpoint's live models list; empty when the model ids were typed.
    pub models: Vec<KeyModelOut>,
}

#[utoipa::path(put, path = "/orgs/{org}/ai/keys/{slot}", tag = "ai", params(OrgSlotPath), request_body = KeyIn,
    responses((status = 200, body = KeyPutOut), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem, description = "`ai_primary_required`"),
        (status = 422, body = Problem, description = "`invalid`, `ai_endpoint_invalid`, `ai_key_invalid`, `models_required` or `ai_model_invalid`"),
        (status = 502, body = Problem, description = "`ai_provider_outage`")))]
async fn put_key(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, s)): Path<(String, String)>,
    ApiJson(body): ApiJson<KeyIn>,
) -> Result<Json<KeyPutOut>, ApiError> {
    scope.require_owner()?;
    let input = KeyInput {
        style: body.style,
        base_url: body.base_url,
        api_key: body.api_key,
        models: body.models.map(role_models),
    };
    let out = app.actions.ai.put_key.run(&scope, slot(&s)?, input).await?;
    Ok(Json(KeyPutOut {
        status: view(out.status),
        models: models_view(out.models),
    }))
}

#[utoipa::path(get, path = "/orgs/{org}/ai/keys/{slot}/models", tag = "ai", params(OrgSlotPath),
    responses((status = 200, body = Vec<KeyModelOut>, description = "Empty on an endpoint with no models list"),
        (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 502, body = Problem, description = "`ai_key_failing` or `ai_provider_outage`")))]
async fn key_models(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, s)): Path<(String, String)>,
) -> Result<Json<Vec<KeyModelOut>>, ApiError> {
    scope.require_owner()?;
    let list = app
        .actions
        .ai
        .list_key_models
        .run(&scope, slot(&s)?)
        .await?;
    Ok(Json(models_view(list)))
}

#[derive(Deserialize, ToSchema)]
pub struct KeyPatchIn {
    pub models: RoleModelsOut,
}

#[utoipa::path(patch, path = "/orgs/{org}/ai/keys/{slot}", tag = "ai", params(OrgSlotPath), request_body = KeyPatchIn,
    responses((status = 200, body = AiStatusOut), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 422, body = Problem, description = "`invalid` (unknown model, a chat model without tools, a bad typed id), `ai_key_invalid` or `ai_model_invalid`"),
        (status = 502, body = Problem, description = "`ai_key_failing` or `ai_provider_outage`")))]
async fn patch_key(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, s)): Path<(String, String)>,
    ApiJson(body): ApiJson<KeyPatchIn>,
) -> Result<Json<AiStatusOut>, ApiError> {
    scope.require_owner()?;
    let patch = &app.actions.ai.patch_key;
    let st = patch
        .run(&scope, slot(&s)?, role_models(body.models))
        .await?;
    Ok(Json(view(st)))
}

#[utoipa::path(delete, path = "/orgs/{org}/ai/keys/{slot}", tag = "ai", params(OrgSlotPath),
    responses((status = 204, description = "Removing the primary promotes the backup"),
        (status = 403, body = Problem), (status = 404, body = Problem)))]
async fn delete_key(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, s)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    scope.require_owner()?;
    app.actions.ai.delete_key.run(&scope, slot(&s)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct TopupUrl {
    /// The hosted Stripe page; it returns to `WEB_BASE_URL/settings/ai?topup=…`.
    pub url: String,
}

#[utoipa::path(post, path = "/orgs/{org}/ai/topup", tag = "ai", params(OrgPath),
    responses((status = 200, body = TopupUrl), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 502, body = Problem), (status = 503, body = Problem, description = "`billing_unavailable`")))]
async fn topup(State(app): State<AppState>, scope: OrgScope) -> Result<Json<TopupUrl>, ApiError> {
    scope.require_owner()?;
    let url = app.actions.ai.topup.run(&scope).await?;
    Ok(Json(TopupUrl { url }))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(show, patch_ai))
        .routes(routes!(put_key, patch_key, delete_key))
        .routes(routes!(key_models))
        .routes(routes!(topup))
}
