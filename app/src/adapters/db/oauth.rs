use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    oauth::{
        AccessToken, ClientKind, ConsentRequest, Grant, OAuthClient, OAuthRepo, RefreshToken,
        DYNAMIC_CLIENT_TTL_DAYS,
    },
    repo::{RepoError, RepoResult},
};
use sea_orm::{
    prelude::DateTimeWithTimeZone, sea_query::OnConflict, ColumnTrait, Condition, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use super::{db_err, utc, Conn, Pg};
use crate::models::_entities::{
    oauth_access_tokens as access, oauth_clients as clients, oauth_consent_requests as consents,
    oauth_grants as grants, oauth_refresh_tokens as refresh,
};

type Ts = DateTimeWithTimeZone;

fn ts(t: DateTime<Utc>) -> Ts {
    t.into()
}

fn client(m: clients::Model) -> RepoResult<OAuthClient> {
    Ok(OAuthClient {
        kind: ClientKind::parse(&m.kind)
            .ok_or_else(|| RepoError::Storage(format!("unknown client kind {:?}", m.kind)))?,
        redirect_uris: serde_json::from_value(m.redirect_uris).map_err(db_err)?,
        client_id: m.client_id,
        name: m.name,
        document_fetched_at: m.document_fetched_at.map(utc),
        document_cache_until: m.document_cache_until.map(utc),
        last_used_at: m.last_used_at.map(utc),
        expires_at: m.expires_at.map(utc),
    })
}

fn consent(m: consents::Model) -> ConsentRequest {
    ConsentRequest {
        id: m.id,
        client_id: m.client_id,
        redirect_uri: m.redirect_uri,
        code_challenge: m.code_challenge,
        state: m.state,
        resource: m.resource,
        scope: m.scope,
        member_id: m.member_id,
        organisation_id: m.organisation_id,
        code_hash: m.code_hash,
        code_expires_at: m.code_expires_at.map(utc),
        code_used_at: m.code_used_at.map(utc),
        grant_id: m.grant_id,
        expires_at: utc(m.expires_at),
    }
}

fn grant(m: grants::Model) -> Grant {
    Grant {
        id: m.id,
        client_id: m.client_id,
        member_id: m.member_id,
        organisation_id: m.organisation_id,
        created_at: utc(m.created_at),
        last_used_at: m.last_used_at.map(utc),
        revoked_at: m.revoked_at.map(utc),
    }
}

fn refresh_token(m: refresh::Model) -> RefreshToken {
    RefreshToken {
        id: m.id,
        grant_id: m.grant_id,
        organisation_id: m.organisation_id,
        token_hash: m.token_hash,
        expires_at: utc(m.expires_at),
        spent_at: m.spent_at.map(utc),
        successor_id: m.successor_id,
    }
}

fn access_token(m: access::Model) -> AccessToken {
    AccessToken {
        id: m.id,
        grant_id: m.grant_id,
        organisation_id: m.organisation_id,
        token_hash: m.token_hash,
        expires_at: utc(m.expires_at),
    }
}

#[async_trait]
impl<C: Conn> OAuthRepo for Pg<C> {
    async fn upsert_client(&self, c: &OAuthClient) -> RepoResult<()> {
        use clients::Column as Col;
        let m = clients::ActiveModel {
            client_id: Set(c.client_id.clone()),
            kind: Set(c.kind.as_str().into()),
            name: Set(c.name.clone()),
            redirect_uris: Set(serde_json::json!(c.redirect_uris)),
            document_fetched_at: Set(c.document_fetched_at.map(ts)),
            document_cache_until: Set(c.document_cache_until.map(ts)),
            last_used_at: Set(c.last_used_at.map(ts)),
            expires_at: Set(c.expires_at.map(ts)),
            created_at: Set(crate::models::now()),
        };
        // `last_used_at` is left out of the update: only `touch_client` moves it.
        clients::Entity::insert(m)
            .on_conflict(
                OnConflict::column(Col::ClientId)
                    .update_columns([
                        Col::Kind,
                        Col::Name,
                        Col::RedirectUris,
                        Col::DocumentFetchedAt,
                        Col::DocumentCacheUntil,
                        Col::ExpiresAt,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn client(&self, client_id: &str) -> RepoResult<Option<OAuthClient>> {
        let m = clients::Entity::find_by_id(client_id)
            .one(self.db())
            .await
            .map_err(db_err)?;
        m.map(client).transpose()
    }

    async fn touch_client(&self, client_id: &str, now: DateTime<Utc>) -> RepoResult<()> {
        clients::Entity::update_many()
            .col_expr(clients::Column::LastUsedAt, Some(ts(now)).into())
            .filter(clients::Column::ClientId.eq(client_id))
            .exec(self.db())
            .await
            .map_err(db_err)?;
        // A dynamic client's expiry slides with use.
        clients::Entity::update_many()
            .col_expr(
                clients::Column::ExpiresAt,
                Some(ts(now + chrono::Duration::days(DYNAMIC_CLIENT_TTL_DAYS))).into(),
            )
            .filter(clients::Column::ClientId.eq(client_id))
            .filter(clients::Column::Kind.eq(ClientKind::Dynamic.as_str()))
            .exec(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn client_has_live_grant(&self, client_id: &str) -> RepoResult<bool> {
        // tenancy: clients are global; this asks whether any organisation holds a live grant.
        let n = grants::Entity::find()
            .filter(grants::Column::ClientId.eq(client_id))
            .filter(grants::Column::RevokedAt.is_null())
            .count(self.db())
            .await
            .map_err(db_err)?;
        Ok(n > 0)
    }

    async fn insert_consent(&self, r: &ConsentRequest) -> RepoResult<()> {
        let m = consents::ActiveModel {
            id: Set(r.id),
            client_id: Set(r.client_id.clone()),
            redirect_uri: Set(r.redirect_uri.clone()),
            code_challenge: Set(r.code_challenge.clone()),
            state: Set(r.state.clone()),
            resource: Set(r.resource.clone()),
            scope: Set(r.scope.clone()),
            member_id: Set(r.member_id),
            organisation_id: Set(r.organisation_id),
            code_hash: Set(r.code_hash.clone()),
            code_expires_at: Set(r.code_expires_at.map(ts)),
            code_used_at: Set(r.code_used_at.map(ts)),
            grant_id: Set(r.grant_id),
            expires_at: Set(ts(r.expires_at)),
            created_at: Set(crate::models::now()),
        };
        consents::Entity::insert(m)
            .exec_without_returning(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn consent(&self, id: Uuid) -> RepoResult<Option<ConsentRequest>> {
        let m = consents::Entity::find_by_id(id)
            .one(self.db())
            .await
            .map_err(db_err)?;
        Ok(m.map(consent))
    }

    async fn decide_consent(
        &self,
        id: Uuid,
        member_id: Uuid,
        organisation_id: Uuid,
        code_hash: &str,
        code_expires_at: DateTime<Utc>,
    ) -> RepoResult<()> {
        use consents::Column as Col;
        let done = consents::Entity::update_many()
            .col_expr(Col::MemberId, Some(member_id).into())
            .col_expr(Col::OrganisationId, Some(organisation_id).into())
            .col_expr(Col::CodeHash, Some(code_hash.to_owned()).into())
            .col_expr(Col::CodeExpiresAt, Some(ts(code_expires_at)).into())
            .filter(Col::Id.eq(id))
            .filter(Col::CodeHash.is_null())
            .exec(self.db())
            .await
            .map_err(db_err)?;
        (done.rows_affected == 1)
            .then_some(())
            .ok_or(RepoError::NotFound)
    }

    async fn consume_code(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<ConsentRequest>> {
        use consents::Column as Col;
        let done = consents::Entity::update_many()
            .col_expr(Col::CodeUsedAt, Some(ts(now)).into())
            .filter(Col::CodeHash.eq(code_hash))
            .filter(Col::CodeUsedAt.is_null())
            .filter(Col::CodeExpiresAt.gt(ts(now)))
            .exec_with_returning(self.db())
            .await
            .map_err(db_err)?;
        Ok(done.into_iter().next().map(consent))
    }

    async fn consent_by_code_hash(&self, code_hash: &str) -> RepoResult<Option<ConsentRequest>> {
        let m = consents::Entity::find()
            .filter(consents::Column::CodeHash.eq(code_hash))
            .one(self.db())
            .await
            .map_err(db_err)?;
        Ok(m.map(consent))
    }

    async fn set_consent_grant(&self, id: Uuid, grant_id: Uuid) -> RepoResult<()> {
        let done = consents::Entity::update_many()
            .col_expr(consents::Column::GrantId, Some(grant_id).into())
            .filter(consents::Column::Id.eq(id))
            .exec(self.db())
            .await
            .map_err(db_err)?;
        (done.rows_affected == 1)
            .then_some(())
            .ok_or(RepoError::NotFound)
    }

    async fn insert_grant(&self, g: &Grant) -> RepoResult<()> {
        let m = grants::ActiveModel {
            id: Set(g.id),
            client_id: Set(g.client_id.clone()),
            member_id: Set(g.member_id),
            organisation_id: Set(g.organisation_id),
            created_at: Set(ts(g.created_at)),
            last_used_at: Set(g.last_used_at.map(ts)),
            revoked_at: Set(g.revoked_at.map(ts)),
        };
        grants::Entity::insert(m)
            .exec_without_returning(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn grant(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Grant>> {
        let m = grants::Entity::find_by_id(id)
            .filter(grants::Column::OrganisationId.eq(organisation_id))
            .one(self.db())
            .await
            .map_err(db_err)?;
        Ok(m.map(grant))
    }

    async fn grants_for_org(&self, organisation_id: Uuid) -> RepoResult<Vec<Grant>> {
        let rows = grants::Entity::find()
            .filter(grants::Column::OrganisationId.eq(organisation_id))
            .filter(grants::Column::RevokedAt.is_null())
            .order_by_asc(grants::Column::CreatedAt)
            .order_by_asc(grants::Column::Id)
            .all(self.db())
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(grant).collect())
    }

    async fn insert_refresh(&self, t: &RefreshToken) -> RepoResult<()> {
        let m = refresh::ActiveModel {
            id: Set(t.id),
            grant_id: Set(t.grant_id),
            organisation_id: Set(t.organisation_id),
            token_hash: Set(t.token_hash.clone()),
            expires_at: Set(ts(t.expires_at)),
            spent_at: Set(t.spent_at.map(ts)),
            successor_id: Set(t.successor_id),
            created_at: Set(crate::models::now()),
        };
        refresh::Entity::insert(m)
            .exec_without_returning(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn refresh_by_hash(&self, token_hash: &str) -> RepoResult<Option<RefreshToken>> {
        // tenancy: the presented token is the lookup key; the row names its organisation.
        let m = refresh::Entity::find()
            .filter(refresh::Column::TokenHash.eq(token_hash))
            .one(self.db())
            .await
            .map_err(db_err)?;
        Ok(m.map(refresh_token))
    }

    async fn spend_refresh(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        successor_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        use refresh::Column as Col;
        let done = refresh::Entity::update_many()
            .col_expr(Col::SpentAt, Some(ts(now)).into())
            .col_expr(Col::SuccessorId, Some(successor_id).into())
            .filter(Col::OrganisationId.eq(organisation_id))
            .filter(Col::Id.eq(id))
            .filter(Col::SpentAt.is_null())
            .exec(self.db())
            .await
            .map_err(db_err)?;
        (done.rows_affected == 1)
            .then_some(())
            .ok_or(RepoError::NotFound)
    }

    async fn insert_access(&self, t: &AccessToken) -> RepoResult<()> {
        let m = access::ActiveModel {
            id: Set(t.id),
            grant_id: Set(t.grant_id),
            organisation_id: Set(t.organisation_id),
            token_hash: Set(t.token_hash.clone()),
            expires_at: Set(ts(t.expires_at)),
            created_at: Set(crate::models::now()),
        };
        access::Entity::insert(m)
            .exec_without_returning(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }

    async fn access_by_hash(&self, token_hash: &str) -> RepoResult<Option<(AccessToken, Grant)>> {
        // tenancy: the bearer token is the lookup key; the row names its organisation.
        let Some(t) = access::Entity::find()
            .filter(access::Column::TokenHash.eq(token_hash))
            .one(self.db())
            .await
            .map_err(db_err)?
        else {
            return Ok(None);
        };
        let g = grants::Entity::find_by_id(t.grant_id)
            .filter(grants::Column::OrganisationId.eq(t.organisation_id))
            .one(self.db())
            .await
            .map_err(db_err)?
            .ok_or_else(|| RepoError::Storage("access token without grant".into()))?;
        Ok(Some((access_token(t), grant(g))))
    }

    async fn revoke_grant(
        &self,
        organisation_id: Uuid,
        grant_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        revoke(
            self,
            Condition::all()
                .add(grants::Column::OrganisationId.eq(organisation_id))
                .add(grants::Column::Id.eq(grant_id)),
            now,
        )
        .await
    }

    async fn revoke_member_grants(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        revoke(
            self,
            Condition::all()
                .add(grants::Column::OrganisationId.eq(organisation_id))
                .add(grants::Column::MemberId.eq(member_id)),
            now,
        )
        .await
    }

    async fn revoke_org_grants(&self, organisation_id: Uuid, now: DateTime<Utc>) -> RepoResult<()> {
        revoke(
            self,
            Condition::all().add(grants::Column::OrganisationId.eq(organisation_id)),
            now,
        )
        .await
    }

    async fn touch_grant(
        &self,
        organisation_id: Uuid,
        grant_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        grants::Entity::update_many()
            .col_expr(grants::Column::LastUsedAt, Some(ts(now)).into())
            .filter(grants::Column::OrganisationId.eq(organisation_id))
            .filter(grants::Column::Id.eq(grant_id))
            .exec(self.db())
            .await
            .map(|_| ())
            .map_err(db_err)
    }
}

/// Stamps `revoked_at` on the unrevoked grants matching `scope` (which names the organisation).
async fn revoke<C: Conn>(pg: &Pg<C>, scope: Condition, now: DateTime<Utc>) -> RepoResult<()> {
    // tenancy: every caller passes a scope that names the organisation.
    grants::Entity::update_many()
        .col_expr(grants::Column::RevokedAt, Some(ts(now)).into())
        .filter(scope)
        .filter(grants::Column::RevokedAt.is_null())
        .exec(pg.db())
        .await
        .map(|_| ())
        .map_err(db_err)
}
