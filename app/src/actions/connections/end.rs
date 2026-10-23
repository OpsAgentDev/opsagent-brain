use opsagent_core::connection::{transition, ConnectionEvent as E};
use uuid::Uuid;

use crate::{
    actions::uow::Repos,
    error::{AppError, AppResult},
};

/// Moves the connection to `disconnected` with `reason` through `repos` (the caller's
/// transaction); `false` if it already was. A status changed since it was read is re-read and
/// retried. `NotFound` outside the organisation.
pub async fn end_connection(
    repos: &dyn Repos,
    organisation_id: Uuid,
    connection_id: Uuid,
    reason: &str,
) -> AppResult<bool> {
    let repo = repos.connections();
    loop {
        let c = repo.get(organisation_id, connection_id).await?;
        let c = c.ok_or(AppError::NotFound)?;
        let Ok(to) = transition(c.status, E::Disconnect) else {
            return Ok(false);
        };
        let cas = repo.cas_status(organisation_id, connection_id, c.status, to, Some(reason));
        if cas.await? {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::connection::ConnectionStatus as S;

    use super::*;
    use crate::{actions::runs::test_support::connected, adapters::memory::MemStore};

    #[tokio::test]
    async fn end_connection_disconnects_once_with_reason() {
        let store = MemStore::default();
        let org = Uuid::new_v4();
        let c = connected(&store, org).await;
        let other = Uuid::new_v4();
        let err = end_connection(&store, other, c.id, "x").await.unwrap_err();
        assert!(matches!(err, AppError::NotFound), "{err:?}");
        assert!(end_connection(&store, org, c.id, "organisation_deleted")
            .await
            .unwrap());
        let now = store.connections().get(org, c.id).await.unwrap().unwrap();
        let reason = now.status_reason.as_deref();
        assert_eq!(
            (now.status, reason),
            (S::Disconnected, Some("organisation_deleted"))
        );
        // Already disconnected: a no-op that keeps the first reason.
        assert!(!end_connection(&store, org, c.id, "customer_disconnected")
            .await
            .unwrap());
        let again = store.connections().get(org, c.id).await.unwrap().unwrap();
        assert_eq!(again.status_reason.as_deref(), Some("organisation_deleted"));
    }
}
