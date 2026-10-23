use opsagent_core::org::Organisation;

use super::OrgScope;
use crate::error::AppResult;

/// The scope's organisation, as resolved for this request.
pub struct GetOrg;

impl GetOrg {
    pub async fn run(&self, scope: &OrgScope) -> AppResult<Organisation> {
        Ok(scope.organisation.clone())
    }
}
