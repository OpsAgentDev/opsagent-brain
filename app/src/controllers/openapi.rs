//! The `/v1` router and its OpenAPI 3.1 document, generated from the `utoipa` annotations.
//! `openapi.json` is served to owner sessions only; brain serves no UI.
use std::sync::Arc;

use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use super::{
    agents, auth, billing, connections, contact, deliveries, findings, integrations, members,
    oauth_consent, orgs, passkeys, recipients, resources, runs, waitlist,
};
use crate::{api_error::ApiError, middleware::org_scope::AuthUser, state::AppState};

#[derive(OpenApi)]
#[openapi(
    info(title = "OpsAgent brain", version = "0.1.0"),
    servers((url = "https://brain.opsagent.dev/v1"))
)]
struct ApiDoc;

/// Every `/v1` route, with paths relative to the `/v1` server URL.
fn api() -> OpenApiRouter<AppState> {
    let mut doc = ApiDoc::openapi();
    // utoipa fills these from Cargo metadata, which has none to give.
    doc.info.description = None;
    doc.info.license = None;
    OpenApiRouter::with_openapi(doc)
        .merge(auth::api())
        .merge(passkeys::api())
        .merge(orgs::api())
        .merge(members::api())
        .merge(agents::api())
        .merge(connections::api())
        .merge(integrations::api())
        .merge(recipients::api())
        .merge(findings::api())
        .merge(deliveries::api())
        .merge(resources::api())
        .merge(runs::api())
        .merge(oauth_consent::api())
        .merge(waitlist::api())
        .merge(contact::api())
        .merge(billing::api())
}

/// utoipa names operations after handler fns (`list`, `show`), which repeat across controllers;
/// OpenAPI requires unique ids (client generators key on them), so prefix the tag: `connections_list`.
fn prefix_operation_ids(doc: &mut utoipa::openapi::OpenApi) {
    for item in doc.paths.paths.values_mut() {
        let ops = [
            &mut item.get,
            &mut item.put,
            &mut item.post,
            &mut item.delete,
            &mut item.patch,
        ];
        for op in ops.into_iter().flatten() {
            let tag = op.tags.as_ref().and_then(|t| t.first());
            if let (Some(id), Some(tag)) = (op.operation_id.as_mut(), tag) {
                *id = format!("{tag}_{id}");
            }
        }
    }
}

/// The committed `openapi.json` contents.
pub fn document_json() -> String {
    let mut doc = api().into_openapi();
    prefix_operation_ids(&mut doc);
    let mut s = doc.to_pretty_json().expect("OpenAPI document serialises");
    s.push('\n');
    s
}

/// `/v1/*` plus `GET /openapi.json`.
pub fn routes() -> Router<AppState> {
    let (v1, _) = api().split_for_parts();
    let doc = Arc::new(document_json());
    Router::new()
        .nest("/v1", v1)
        .route("/openapi.json", get(move |s, u| serve(s, u, doc.clone())))
}

/// 404 unless the session user owns at least one live organisation.
async fn serve(
    State(app): State<AppState>,
    user: Result<AuthUser, ApiError>,
    doc: Arc<String>,
) -> Result<impl IntoResponse, ApiError> {
    let AuthUser(user_id) = user.map_err(|_| ApiError::not_found())?;
    if !app.actions.orgs.is_owner_anywhere.run(user_id).await? {
        return Err(ApiError::not_found());
    }
    Ok(([(header::CONTENT_TYPE, "application/json")], (*doc).clone()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    #[test]
    fn operation_ids_are_unique() {
        let doc: serde_json::Value = serde_json::from_str(&super::document_json()).unwrap();
        let ids: Vec<&str> = doc["paths"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|item| item.as_object().unwrap().values())
            .filter_map(|op| op["operationId"].as_str())
            .collect();
        assert!(!ids.is_empty());
        assert_eq!(
            ids.len(),
            ids.iter().collect::<HashSet<_>>().len(),
            "{ids:?}"
        );
    }
}
