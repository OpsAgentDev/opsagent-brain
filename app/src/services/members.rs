//! Membership use cases: invite, accept (bound to the invited email), remove (never the last
//! owner).
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use opsagent_core::{
    audit::{AuditEntry, AuditLog},
    org::{Invite, Organisation, OrganisationsRepo, Role},
    user::{Email, UsersRepo},
};
use sea_orm::{DatabaseConnection, TransactionTrait};
use uuid::Uuid;

use crate::{
    adapters::db::Pg,
    api_error::ApiError,
    mailers::{magic_link as mail, Mailer},
    tokens::{hash_token, new_token},
};

/// Creates a 7-day invite and mails its link (`{web_base_url}/invites/{token}`).
pub async fn invite(
    db: &DatabaseConnection,
    mailer: &dyn Mailer,
    web_base_url: &str,
    organisation_id: Uuid,
    actor: Uuid,
    email: &str,
    role: String,
) -> Result<Invite, ApiError> {
    let email = Email::parse(email).ok_or_else(|| ApiError::invalid("invalid email"))?;
    let role =
        Role::parse(&role).ok_or_else(|| ApiError::invalid("role must be owner or member"))?;
    let org = OrganisationsRepo::get(&Pg::new(db), organisation_id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let token = new_token();
    let txn = db.begin().await?;
    let repo = Pg::new(&txn);
    let expires = Utc::now() + Duration::days(7);
    let row = repo
        .insert_invite(org.id, &email, role, &hash_token(&token), expires)
        .await?;
    let target = Some(("invite", row.id.to_string()));
    repo.record(AuditEntry::member(
        Some(org.id),
        actor,
        "invite.create",
        target,
    ))
    .await?;
    txn.commit().await?;
    let link = format!("{web_base_url}/invites/{token}");
    if let Err(e) = mailer
        .send(mail::invite(email.as_str(), &org.name, &link))
        .await
    {
        tracing::error!(error = %e, "invite mail failed");
    }
    Ok(row)
}

/// Accepts invite `token` for signed-in `user_id`; returns the organisation and the role held.
/// One transaction: a refused accept leaves the invite pending.
pub async fn accept(
    db: &DatabaseConnection,
    user_id: Uuid,
    token: &str,
) -> Result<(Organisation, Role), ApiError> {
    let gone = || ApiError::gone("invite_invalid");
    let txn = db.begin().await?;
    let repo = Pg::new(&txn);
    let inv = repo
        .take_invite(&hash_token(token), Utc::now())
        .await?
        .ok_or_else(gone)?;
    let user = UsersRepo::get(&repo, user_id)
        .await?
        .ok_or_else(ApiError::unauthenticated)?;
    if inv.email != user.email {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invite_email_mismatch",
            "This invite was sent to a different email address.",
        ));
    }
    let org = OrganisationsRepo::get(&repo, inv.organisation_id)
        .await?
        .filter(|o| o.deleted_at.is_none())
        .ok_or_else(gone)?;
    // An existing membership keeps its role.
    let role = match repo.membership(&org.slug, user_id).await? {
        Some((_, m)) => m.role,
        None => repo.add_member(org.id, user_id, inv.role).await?.role,
    };
    let target = Some(("invite", inv.id.to_string()));
    repo.record(AuditEntry::member(
        Some(org.id),
        user_id,
        "invite.accept",
        target,
    ))
    .await?;
    txn.commit().await?;
    Ok((org, role))
}

/// Removes member `member_id` for owner `actor`; `last_owner` if it would leave no owner.
pub async fn remove(
    db: &DatabaseConnection,
    organisation_id: Uuid,
    actor: Uuid,
    member_id: Uuid,
) -> Result<(), ApiError> {
    let txn = db.begin().await?;
    let repo = Pg::new(&txn);
    // Serialise owner removals per org so two concurrent requests cannot orphan it.
    repo.lock(organisation_id).await?;
    let target = repo
        .members(organisation_id)
        .await?
        .into_iter()
        .find(|m| m.id == member_id)
        .ok_or_else(ApiError::not_found)?;
    if target.role == Role::Owner && repo.owner_count(organisation_id).await? <= 1 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "last_owner",
            "An organisation must keep at least one owner.",
        ));
    }
    // Also cancels the user's pending invites, so they cannot rejoin through one.
    repo.remove_member(organisation_id, member_id).await?;
    let target = Some(("member", member_id.to_string()));
    repo.record(AuditEntry::member(
        Some(organisation_id),
        actor,
        "member.remove",
        target,
    ))
    .await?;
    txn.commit().await?;
    Ok(())
}
