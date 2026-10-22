//! The `/v1` router and its OpenAPI 3.1 document, generated from the `utoipa` annotations.
//! `openapi.json` is served to owner sessions only; brain serves no UI.
use std::sync::Arc;

use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};
use loco_rs::app::AppContext;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use super::{auth, connections, findings, members, orgs, resources, runs};
use crate::{
    api_error::ApiError,
    middleware::org_scope::AuthUser,
    models::{
        _entities::{members as member_rows, organisations},
        members::OWNER,
    },
};

#[derive(OpenApi)]
#[openapi(
    info(title = "OpsAgent brain", version = "0.1.0"),
    servers((url = "https://brain.opsagent.dev/v1"))
)]
struct ApiDoc;

/// Every `/v1` route, with paths relative to the `/v1` server URL.
fn api() -> OpenApiRouter<AppContext> {
    let mut doc = ApiDoc::openapi();
    // utoipa fills these from Cargo metadata, which has none to give.
    doc.info.description = None;
    doc.info.license = None;
    OpenApiRouter::with_openapi(doc)
        .merge(auth::api())
        .merge(orgs::api())
        .merge(members::api())
        .merge(connections::api())
        .merge(findings::api())
        .merge(resources::api())
        .merge(runs::api())
}

/// The committed `openapi.json` contents.
pub fn document_json() -> String {
    let doc = api().into_openapi();
    let mut s = doc.to_pretty_json().expect("OpenAPI document serialises");
    s.push('\n');
    s
}

/// `/v1/*` plus `GET /openapi.json`.
pub fn routes() -> Router<AppContext> {
    let (v1, _) = api().split_for_parts();
    let doc = Arc::new(document_json());
    Router::new()
        .nest("/v1", v1)
        .route("/openapi.json", get(move |s, u| serve(s, u, doc.clone())))
}

/// 404 unless the session user owns at least one live organisation.
async fn serve(
    State(ctx): State<AppContext>,
    user: Result<AuthUser, ApiError>,
    doc: Arc<String>,
) -> Result<impl IntoResponse, ApiError> {
    let AuthUser(user_id) = user.map_err(|_| ApiError::not_found())?;
    let owned = member_rows::Entity::find()
        .filter(member_rows::Column::UserId.eq(user_id))
        .filter(member_rows::Column::Role.eq(OWNER))
        .inner_join(organisations::Entity)
        .filter(organisations::Column::DeletedAt.is_null())
        .count(&ctx.db)
        .await?;
    if owned == 0 {
        return Err(ApiError::not_found());
    }
    Ok(([(header::CONTENT_TYPE, "application/json")], (*doc).clone()))
}
