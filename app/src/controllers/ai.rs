//! Dashboard AI settings: the switch, usage, the organisation's own key and top-ups.
//! Owner only, except reading the status.
use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, FixedOffset};
use opsagent_core::ai::RoleModels;
use sea_orm::prelude::Decimal;
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::OrgPath;
use crate::{
    actions::ai::{AiStatus, KeyModel, KeyPatch},
    api_error::{ApiError, ApiJson, Problem},
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
    /// `anthropic` or `openai`.
    pub provider: String,
    pub last4: String,
    /// `ok`, `failing` or `provider_outage`.
    pub status: String,
    pub models: RoleModelsOut,
    pub monthly_credit_ceiling: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AiStatusOut {
    pub enabled: bool,
    /// `ready`, `ai_disabled`, `ai_unavailable`, `ai_key_failing` or `ai_quota_reached`.
    pub state: String,
    /// `opsagent`, `byok`, or null when neither key is there.
    pub source: Option<String>,
    pub usage: AiUsageOut,
    pub key: Option<AiKeyOut>,
    /// Stripe and OpsAgent's key are configured, so top-ups can be bought.
    pub topup_available: bool,
}

fn view(s: AiStatus) -> AiStatusOut {
    let ceiling = s.ceiling;
    let key = s.keys.primary.map(|k| AiKeyOut {
        provider: k.provider.as_str().into(),
        last4: k.last4,
        status: k.status.as_str().into(),
        models: RoleModelsOut {
            routine: k.models.routine,
            chat: k.models.chat,
        },
        monthly_credit_ceiling: ceiling.map(credits),
    });
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
        key,
        topup_available: s.topup_available,
    }
}

#[utoipa::path(get, path = "/orgs/{org}/ai", tag = "ai", params(OrgPath),
    responses((status = 200, body = AiStatusOut), (status = 404, body = Problem)))]
async fn show(State(app): State<AppState>, scope: OrgScope) -> Result<Json<AiStatusOut>, ApiError> {
    Ok(Json(view(app.actions.ai.access.status(&scope).await?)))
}

#[derive(Deserialize, ToSchema)]
pub struct EnableIn {
    pub enabled: bool,
}

#[utoipa::path(patch, path = "/orgs/{org}/ai", tag = "ai", params(OrgPath), request_body = EnableIn,
    responses((status = 200, body = AiStatusOut), (status = 403, body = Problem), (status = 404, body = Problem)))]
async fn set_enabled(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiJson(body): ApiJson<EnableIn>,
) -> Result<Json<AiStatusOut>, ApiError> {
    scope.require_owner()?;
    let s = app.actions.ai.set_enabled.run(&scope, body.enabled).await?;
    Ok(Json(view(s)))
}

#[derive(Deserialize, ToSchema)]
pub struct KeyIn {
    /// `anthropic` or `openai`.
    pub provider: String,
    /// Sent once; only its last 4 characters are ever shown again.
    pub api_key: String,
}

#[utoipa::path(put, path = "/orgs/{org}/ai/key", tag = "ai", params(OrgPath), request_body = KeyIn,
    responses((status = 200, body = AiStatusOut), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 422, body = Problem, description = "`ai_key_invalid` or `invalid`"),
        (status = 502, body = Problem, description = "`ai_provider_outage`")))]
async fn put_key(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiJson(body): ApiJson<KeyIn>,
) -> Result<Json<AiStatusOut>, ApiError> {
    scope.require_owner()?;
    let put = &app.actions.ai.put_key;
    Ok(Json(view(
        put.run(&scope, &body.provider, &body.api_key).await?,
    )))
}

#[derive(Serialize, ToSchema)]
pub struct KeyModelOut {
    pub id: String,
    /// It can call tools (required for chat).
    pub tools: bool,
    /// `routine`, `chat`, or null: the role the picker preselects it for.
    pub default_for: Option<String>,
}

#[utoipa::path(get, path = "/orgs/{org}/ai/key/models", tag = "ai", params(OrgPath),
    responses((status = 200, body = Vec<KeyModelOut>), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 502, body = Problem, description = "`ai_key_failing` or `ai_provider_outage`")))]
async fn key_models(
    State(app): State<AppState>,
    scope: OrgScope,
) -> Result<Json<Vec<KeyModelOut>>, ApiError> {
    scope.require_owner()?;
    let list = app.actions.ai.list_key_models.run(&scope).await?;
    let out = |m: KeyModel| KeyModelOut {
        id: m.id,
        tools: m.tools,
        default_for: m.default_for.map(|r| r.as_str().into()),
    };
    Ok(Json(list.into_iter().map(out).collect()))
}

/// Present (even as null) is `Some`; absent is `None`.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<Decimal>>, D::Error> {
    Option::<Decimal>::deserialize(d).map(Some)
}

#[derive(Deserialize, ToSchema)]
pub struct KeyPatchIn {
    pub models: Option<RoleModelsOut>,
    /// Credits per calendar month (UTC); null removes it.
    #[serde(default, deserialize_with = "present")]
    #[schema(value_type = Option<f64>)]
    pub monthly_credit_ceiling: Option<Option<Decimal>>,
}

#[utoipa::path(patch, path = "/orgs/{org}/ai/key", tag = "ai", params(OrgPath), request_body = KeyPatchIn,
    responses((status = 200, body = AiStatusOut), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 422, body = Problem, description = "`invalid`: unknown model, a chat model without tools, or a negative ceiling"),
        (status = 502, body = Problem)))]
async fn patch_key(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiJson(body): ApiJson<KeyPatchIn>,
) -> Result<Json<AiStatusOut>, ApiError> {
    scope.require_owner()?;
    let patch = KeyPatch {
        models: body.models.map(|m| RoleModels {
            routine: m.routine,
            chat: m.chat,
        }),
        ceiling: body.monthly_credit_ceiling,
    };
    Ok(Json(view(
        app.actions.ai.patch_key.run(&scope, patch).await?,
    )))
}

#[utoipa::path(delete, path = "/orgs/{org}/ai/key", tag = "ai", params(OrgPath),
    responses((status = 204), (status = 403, body = Problem), (status = 404, body = Problem)))]
async fn delete_key(State(app): State<AppState>, scope: OrgScope) -> Result<StatusCode, ApiError> {
    scope.require_owner()?;
    app.actions.ai.delete_key.run(&scope).await?;
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
        .routes(routes!(show, set_enabled))
        .routes(routes!(put_key, patch_key, delete_key))
        .routes(routes!(key_models))
        .routes(routes!(topup))
}
