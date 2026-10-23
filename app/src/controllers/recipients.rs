use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, FixedOffset};
use loco_rs::app::AppContext;
use opsagent_deliver::repo::RecipientRow;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, OrgPath};
use crate::{
    actions::recipients as action,
    api_error::{ApiError, ApiJson, ApiQuery, Problem},
    app::actions,
    controllers::page::{page_request, Page, PageParams},
    middleware::org_scope::OrgScope,
};

#[derive(Serialize, ToSchema)]
pub struct Recipient {
    pub id: Uuid,
    pub email: String,
    /// Null: organisation-wide.
    pub connection_id: Option<Uuid>,
    /// Set when the recipient is a member (no confirmation, no unsubscribe footer).
    pub member_id: Option<Uuid>,
    /// `pending` (awaiting the confirm link) or `active`.
    pub status: String,
    pub unsubscribed_at: Option<DateTime<FixedOffset>>,
    pub created_at: DateTime<FixedOffset>,
}

fn view(r: RecipientRow) -> Recipient {
    Recipient {
        id: r.id,
        email: r.email,
        connection_id: r.connection_id,
        member_id: r.member_id,
        status: r.status,
        unsubscribed_at: r.unsubscribed_at.map(|t| t.fixed_offset()),
        created_at: r.created_at.fixed_offset(),
    }
}

#[utoipa::path(get, path = "/orgs/{org}/recipients", tag = "recipients", params(OrgPath, PageParams),
    responses((status = 200, body = Page<Recipient>), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn list(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<Recipient>>, ApiError> {
    let list = &actions(&ctx)?.recipients.list_recipients;
    let got = list.run(scope.organisation.id, page_request(&p)?).await?;
    Ok(Json(Page::of(got).map(view)))
}

#[derive(Deserialize, ToSchema)]
pub struct NewRecipient {
    /// An address to invite; it receives a confirm link and stays `pending` until used.
    pub email: Option<String>,
    /// A member of the organisation; active at once. Give exactly one of `email` or `member_id`.
    pub member_id: Option<Uuid>,
    /// Route only this connection's deliveries; null for organisation-wide.
    pub connection_id: Option<Uuid>,
}

#[utoipa::path(post, path = "/orgs/{org}/recipients", tag = "recipients", params(OrgPath),
    request_body = NewRecipient,
    responses((status = 201, body = Recipient), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem), (status = 422, body = Problem)))]
async fn create(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiJson(body): ApiJson<NewRecipient>,
) -> Result<(StatusCode, Json<Recipient>), ApiError> {
    scope.require_owner()?;
    let new = action::NewRecipient {
        email: body.email,
        member_id: body.member_id,
        connection_id: body.connection_id,
    };
    let create = &actions(&ctx)?.recipients.create_recipient;
    let row = create
        .run(scope.organisation.id, scope.member.user_id, new)
        .await?;
    Ok((StatusCode::CREATED, Json(view(row))))
}

#[utoipa::path(delete, path = "/orgs/{org}/recipients/{id}", tag = "recipients", params(OrgIdPath),
    responses((status = 204), (status = 403, body = Problem), (status = 404, body = Problem)))]
async fn remove(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    scope.require_owner()?;
    let id: Uuid = id.parse().map_err(|_| ApiError::not_found())?;
    let delete = &actions(&ctx)?.recipients.delete_recipient;
    delete
        .run(scope.organisation.id, scope.member.user_id, id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub struct ConfirmBody {
    /// The token from the confirm link.
    pub token: String,
}

/// Anonymous: the single-use token is the authorisation.
#[utoipa::path(post, path = "/recipients/confirm", tag = "recipients", request_body = ConfirmBody,
    responses((status = 204), (status = 410, body = Problem)))]
async fn confirm(
    State(ctx): State<AppContext>,
    ApiJson(body): ApiJson<ConfirmBody>,
) -> Result<StatusCode, ApiError> {
    let confirm = &actions(&ctx)?.recipients.confirm_recipient;
    confirm.run(&body.token).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(IntoParams)]
#[into_params(parameter_in = Path)]
pub struct UnsubscribePath {
    /// The token from the mail footer.
    pub token: String,
}

/// Anonymous and idempotent; the token stays valid while the recipient exists.
#[utoipa::path(post, path = "/unsubscribe/{token}", tag = "recipients", params(UnsubscribePath),
    responses((status = 204), (status = 410, body = Problem)))]
async fn unsubscribe(
    State(ctx): State<AppContext>,
    Path(token): Path<String>,
) -> Result<StatusCode, ApiError> {
    actions(&ctx)?.recipients.unsubscribe.run(&token).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(list, create))
        .routes(routes!(remove))
        .routes(routes!(confirm))
        .routes(routes!(unsubscribe))
}
