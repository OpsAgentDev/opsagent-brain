use std::sync::Arc;

use opsagent_core::user::User;
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// The signed-in user; `Unauthenticated` if the session's user no longer exists.
pub struct CurrentUser {
    uow: Arc<dyn UnitOfWork>,
}

impl CurrentUser {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, user_id: Uuid) -> AppResult<User> {
        self.uow
            .users()
            .get(user_id)
            .await?
            .ok_or(AppError::Unauthenticated)
    }
}
