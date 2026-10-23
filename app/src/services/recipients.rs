//! Email recipients of deliveries: owner adds (an email confirms by link, a member is active at
//! once), public confirm by single-use token (SHA-256 at rest), and unsubscribe by a stable
//! HMAC token. `mail_guard` decides whether a confirm mail may go out; a refused mail is
//! answered as if sent.
use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use chrono::{Duration, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use opsagent_core::{
    audit::{AuditEntry, AuditLog},
    repo::RepoError,
    user::Email,
};
use opsagent_deliver::repo::{self as repo, RecipientRow, RecipientsRepo, Suppression};
use opsagent_ledger::redis;
use sea_orm::{DatabaseConnection, TransactionTrait};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    actions::uow::Repos,
    adapters::db::Pg,
    api_error::ApiError,
    mailers::{magic_link as mail, Mailer},
    models::{_entities::connections, find_in_org},
    services::mail_guard,
    tokens::{hash_token, new_token},
};

const CONFIRM_DAYS: i64 = 7;
/// The HMAC key for unsubscribe tokens, derived from `Settings::unsubscribe_key`.
fn unsubscribe_mac(secret: &str, id: Uuid) -> Hmac<Sha256> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret.as_bytes())
        .expand(b"opsagent-unsubscribe", &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    let mut m = Hmac::<Sha256>::new_from_slice(&key).expect("hmac accepts any key");
    m.update(id.as_bytes());
    m
}

/// `<recipient id>.<base64url HMAC-SHA256(key, id)>`: stable for the row's lifetime, so every
/// mail carries the same working link.
pub fn unsubscribe_token(secret: &str, id: Uuid) -> String {
    let mac = unsubscribe_mac(secret, id).finalize().into_bytes();
    format!("{}.{}", id.simple(), B64.encode(mac))
}

/// The recipient id a token was issued for, if its HMAC verifies (constant-time compare).
fn verify_unsubscribe(secret: &str, token: &str) -> Option<Uuid> {
    let (id, mac) = token.split_once('.')?;
    let id = Uuid::try_parse(id).ok()?;
    let mac = B64.decode(mac).ok()?;
    unsubscribe_mac(secret, id).verify_slice(&mac).ok()?;
    Some(id)
}

/// The footer link for recipient `id`.
pub fn unsubscribe_url(web_base_url: &str, secret: &str, id: Uuid) -> String {
    format!(
        "{}/unsubscribe/{}",
        web_base_url.trim_end_matches('/'),
        unsubscribe_token(secret, id)
    )
}

/// Who to add: exactly one of `email` (confirms by mail) or `member_id`.
pub struct NewRecipient {
    pub email: Option<String>,
    pub member_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
}

/// The member's email, for a member of `organisation_id`.
async fn member_email(
    db: &DatabaseConnection,
    organisation_id: Uuid,
    member_id: Uuid,
) -> Result<String, ApiError> {
    let members = Pg::new(db).orgs().members(organisation_id).await?;
    match members.into_iter().find(|m| m.id == member_id) {
        Some(m) => Ok(m.email.as_str().to_lowercase()),
        None => Err(ApiError::invalid(
            "member_id is not a member of this organisation",
        )),
    }
}

// shortcut: ~55 lines, one use case in one transaction plus its mail; split if it gains steps.
/// Adds a recipient for owner `actor`; mails the confirm link (`{web}/recipients/confirm?token=`)
/// to an email recipient. 409 `recipient_exists` for the same email and connection.
pub async fn create(
    db: &DatabaseConnection,
    redis: &redis::Client,
    mailer: &dyn Mailer,
    web_base_url: &str,
    organisation_id: Uuid,
    actor: Uuid,
    new: NewRecipient,
) -> Result<RecipientRow, ApiError> {
    let (email, member_id) = match (new.email.as_deref(), new.member_id) {
        (Some(e), None) => (
            Email::parse(e)
                .ok_or_else(|| ApiError::invalid("invalid email"))?
                .as_str()
                .to_owned(),
            None,
        ),
        (None, Some(m)) => (member_email(db, organisation_id, m).await?, Some(m)),
        _ => return Err(ApiError::invalid("give exactly one of email or member_id")),
    };
    if let Some(c) = new.connection_id {
        find_in_org::<connections::Entity>(
            db,
            connections::Column::OrganisationId,
            organisation_id,
            &c.to_string(),
        )
        .await?;
    }
    let token = member_id.is_none().then(new_token);
    let new = repo::NewRecipient {
        connection_id: new.connection_id,
        email: email.clone(),
        member_id,
        confirm: token
            .as_deref()
            .map(|t| (hash_token(t), Utc::now() + Duration::days(CONFIRM_DAYS))),
    };
    let txn = db.begin().await?;
    let row = Pg::new(&txn)
        .recipients()
        .insert(organisation_id, new)
        .await
        .map_err(|e| match e {
            RepoError::Conflict(_) => ApiError::new(
                StatusCode::CONFLICT,
                "recipient_exists",
                "This recipient is already added.",
            ),
            e => e.into(),
        })?;
    Pg::new(&txn)
        .record(AuditEntry::member(
            Some(organisation_id),
            actor,
            "recipient.create",
            Some(("recipient", row.id.to_string())),
        ))
        .await?;
    txn.commit().await?;
    if let Some(token) = token {
        let to = Confirm {
            organisation_id,
            email: &email,
            token: &token,
        };
        send_confirm(db, redis, mailer, web_base_url, to).await?;
    }
    Ok(row)
}

struct Confirm<'a> {
    organisation_id: Uuid,
    email: &'a str,
    token: &'a str,
}

/// Mails the confirm link unless `mail_guard` refuses (answered as if sent either way).
async fn send_confirm(
    db: &DatabaseConnection,
    redis: &redis::Client,
    mailer: &dyn Mailer,
    web_base_url: &str,
    c: Confirm<'_>,
) -> Result<(), ApiError> {
    if !mail_guard::may_send_confirm(db, redis, c.organisation_id, c.email).await? {
        return Ok(());
    }
    let org = Pg::new(db).orgs().get(c.organisation_id).await?;
    let name = org.map(|o| o.name).unwrap_or_default();
    let link = format!("{web_base_url}/recipients/confirm?token={}", c.token);
    if mailer
        .send(mail::recipient_confirm(c.email, &name, &link))
        .await
        .is_err()
    {
        tracing::error!(error_code = "mail_failed", "recipient confirm mail failed");
    }
    Ok(())
}

/// Activates the pending recipient holding confirm `token`; 410 if unknown, used or expired.
pub async fn confirm(
    db: &DatabaseConnection,
    redis: &redis::Client,
    token: &str,
) -> Result<(), ApiError> {
    let txn = db.begin().await?;
    let row = Pg::new(&txn)
        .confirm(&hash_token(token), Utc::now())
        .await?
        .ok_or_else(|| ApiError::gone("recipient_token_invalid"))?;
    Pg::new(&txn)
        .record(
            AuditEntry::system(
                row.organisation_id,
                "recipient.confirm",
                ("recipient", row.id.to_string()),
                "success",
            )
            .with_meta(serde_json::json!({})),
        )
        .await?;
    txn.commit().await?;
    mail_guard::confirmed(db, redis, row.organisation_id, &row.email).await?;
    Ok(())
}

/// Unsubscribes the recipient a valid token names and suppresses its address everywhere.
/// Idempotent; 410 for a forged token or a deleted recipient.
pub async fn unsubscribe(
    db: &DatabaseConnection,
    secret: &str,
    token: &str,
) -> Result<(), ApiError> {
    let gone = || ApiError::gone("unsubscribe_token_invalid");
    let id = verify_unsubscribe(secret, token).ok_or_else(gone)?;
    let row = Pg::new(db).by_id_unscoped(id).await?.ok_or_else(gone)?;
    let txn = db.begin().await?;
    let repo = Pg::new(&txn);
    if repo
        .unsubscribe(row.organisation_id, row.id, Utc::now())
        .await?
    {
        Pg::new(&txn)
            .record(
                AuditEntry::system(
                    row.organisation_id,
                    "recipient.unsubscribe",
                    ("recipient", row.id.to_string()),
                    "success",
                )
                .with_meta(serde_json::json!({})),
            )
            .await?;
    }
    let hash = mail_guard::email_hash(&row.email);
    repo.suppress(None, &hash, Suppression::Unsubscribed)
        .await?;
    txn.commit().await?;
    Ok(())
}

/// Removes recipient `id` for owner `actor`.
pub async fn delete(
    db: &DatabaseConnection,
    organisation_id: Uuid,
    actor: Uuid,
    id: Uuid,
) -> Result<(), ApiError> {
    let txn = db.begin().await?;
    let repo = Pg::new(&txn);
    if !repo.recipients().delete(organisation_id, id).await? {
        return Err(ApiError::not_found());
    }
    repo.record(AuditEntry::member(
        Some(organisation_id),
        actor,
        "recipient.delete",
        Some(("recipient", id.to_string())),
    ))
    .await?;
    txn.commit().await?;
    Ok(())
}
