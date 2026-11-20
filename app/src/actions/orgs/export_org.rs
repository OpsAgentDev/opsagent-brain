use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{
    audit::AuditEntry,
    repo::{Clock, PageRequest},
};
use serde::Serialize;
use uuid::Uuid;

use super::{
    audit_view::{AuditItem, Describe},
    export_doc::{DeliveryOut, DeliverySettingsOut, ExportDoc, FindingOut, OrgOut, RecipientOut},
    OrgScope,
};
use crate::{
    actions::{uow::UnitOfWork, RateLimiter},
    error::{AppError, AppResult},
};

/// The largest export served, in bytes of JSON (20 MB). A larger organisation is told to ask
/// support.
pub const EXPORT_MAX_BYTES: usize = 20 * 1024 * 1024;
const HOUR_SECS: i64 = 3600;
const PAGE: u64 = 200;

/// The organisation's own data as one JSON document (`ExportDoc`). Owners only, once per
/// organisation per hour, audited as `org.exported`.
pub struct ExportOrg {
    uow: Arc<dyn UnitOfWork>,
    limiter: Arc<dyn RateLimiter>,
    clock: Arc<dyn Clock>,
    max_bytes: usize,
    /// Rows read per query.
    page: u64,
}

/// What is left of the size cap while the document is gathered, so an oversized organisation
/// is refused before all of it is in memory.
struct Budget(usize);

impl Budget {
    fn take<T: Serialize>(&mut self, rows: &[T]) -> AppResult<()> {
        let n = serde_json::to_vec(rows).map_err(internal)?.len();
        self.0 = self.0.checked_sub(n).ok_or_else(too_large)?;
        Ok(())
    }
}

fn internal(e: serde_json::Error) -> AppError {
    AppError::Internal(format!("export: {e}"))
}

fn too_large() -> AppError {
    AppError::Refused {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        code: "export_too_large",
        detail: "This organisation's data is larger than the 20 MB an export can hold. \
                 Contact support and we will prepare it for you."
            .into(),
    }
}

impl ExportOrg {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        limiter: Arc<dyn RateLimiter>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            uow,
            limiter,
            clock,
            max_bytes: EXPORT_MAX_BYTES,
            page: PAGE,
        }
    }

    /// The document's bytes. An export that fails or is refused as too large does not count
    /// against the hour: the owner may try again.
    pub async fn run(&self, scope: &OrgScope) -> AppResult<Vec<u8>> {
        scope.require_owner()?;
        let key = format!("ratelimit:org_export:org:{}", scope.organisation.id);
        if !self.limiter.hit(&key, 1, HOUR_SECS).await? {
            // shortcut: Retry-After is the window length, an upper bound; read the key TTL if exactness matters.
            return Err(AppError::RateLimited {
                detail: "An organisation's data can be exported once per hour.".into(),
                retry_after_secs: HOUR_SECS.unsigned_abs(),
            });
        }
        let built = self.build(scope).await;
        if built.is_err() {
            // The export's own error is the one to report, whatever the limiter says.
            if let Err(e) = self.limiter.clear(&key).await {
                tracing::warn!(error = %e, "export rate limit not released");
            }
        }
        built
    }

    async fn build(&self, scope: &OrgScope) -> AppResult<Vec<u8>> {
        let org = scope.organisation.id;
        let doc = self.gather(scope).await?;
        let bytes = serde_json::to_vec(&doc).map_err(internal)?;
        if bytes.len() > self.max_bytes {
            return Err(too_large());
        }
        let target = Some(("organisation", org.to_string()));
        let entry = AuditEntry::member(Some(org), scope.member.user_id, "org.exported", target);
        self.uow.audit().record(entry).await?;
        Ok(bytes)
    }

    fn page_after<K>(&self, after: Option<K>) -> PageRequest<K> {
        PageRequest {
            after,
            limit: self.page,
        }
    }

    async fn gather(&self, scope: &OrgScope) -> AppResult<ExportDoc> {
        let (o, org) = (&scope.organisation, scope.organisation.id);
        let mut budget = Budget(self.max_bytes);
        let billing = self.uow.billing().billing(org).await?;
        let connections = self.uow.connections().list(org).await?;
        let members = self.uow.orgs().members(org).await?;
        let integrations = self.uow.integrations().list(org).await?;
        Ok(ExportDoc {
            exported_at: self.clock.now(),
            organisation: OrgOut {
                name: o.name.clone(),
                slug: o.slug.clone(),
                timezone: o.timezone.clone(),
                created_at: o.created_at,
                plan: billing
                    .subscription
                    .and_then(|s| s.tier)
                    .map(|t| t.as_str()),
                billing_status: billing.status.as_str(),
            },
            members: members.into_iter().map(Into::into).collect(),
            connections: connections.iter().map(Into::into).collect(),
            findings: self.findings(org, &mut budget).await?,
            delivery_settings: DeliverySettingsOut {
                connections: connections.iter().map(Into::into).collect(),
                integrations: integrations.into_iter().map(Into::into).collect(),
            },
            recipients: self.recipients(org, &mut budget).await?,
            deliveries: self.deliveries(org, &mut budget).await?,
            audit_log: self.audit_log(org, &mut budget).await?,
        })
    }

    /// Every finding the findings list shows, each with its stored evidence: two queries per
    /// page, whatever the number of findings.
    async fn findings(&self, org: Uuid, budget: &mut Budget) -> AppResult<Vec<FindingOut>> {
        let repo = self.uow.findings();
        let (mut out, mut after) = (Vec::new(), None);
        loop {
            let page = self.page_after(after);
            let got = repo.list(org, Default::default(), page).await?;
            let from = out.len();
            let ids: Vec<Uuid> = got.items.iter().map(|f| f.id).collect();
            let mut evidence = repo.evidence_of(org, &ids).await?;
            for f in got.items {
                let own = evidence.remove(&f.id).unwrap_or_default();
                out.push(FindingOut::new(f, own));
            }
            budget.take(&out[from..])?;
            after = got.next;
            if after.is_none() {
                return Ok(out);
            }
        }
    }

    async fn recipients(&self, org: Uuid, budget: &mut Budget) -> AppResult<Vec<RecipientOut>> {
        let (mut out, mut after) = (Vec::new(), None);
        loop {
            let page = self.page_after(after);
            let got = self.uow.recipients().list(org, page).await?;
            let from = out.len();
            out.extend(got.items.into_iter().map(RecipientOut::from));
            budget.take(&out[from..])?;
            after = got.next;
            if after.is_none() {
                return Ok(out);
            }
        }
    }

    async fn deliveries(&self, org: Uuid, budget: &mut Budget) -> AppResult<Vec<DeliveryOut>> {
        let (mut out, mut after) = (Vec::new(), None);
        loop {
            let page = self.page_after(after);
            let repo = self.uow.deliveries();
            let got = repo.list(org, Default::default(), page).await?;
            let from = out.len();
            out.extend(got.items.into_iter().map(DeliveryOut::from));
            budget.take(&out[from..])?;
            after = got.next;
            if after.is_none() {
                return Ok(out);
            }
        }
    }

    async fn audit_log(&self, org: Uuid, budget: &mut Budget) -> AppResult<Vec<AuditItem>> {
        let mut describe = Describe::new(&*self.uow, org).await?;
        let (mut out, mut after) = (Vec::new(), None);
        loop {
            let page = self.page_after(after);
            let got = self.uow.audit().list(org, page).await?;
            let from = out.len();
            out.extend(describe.page(got.items).await?);
            budget.take(&out[from..])?;
            after = got.next;
            if after.is_none() {
                return Ok(out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use opsagent_core::{
        audit::AuditLog,
        billing::{BillingRepo, BillingStatus, SubscriptionState, Tier},
        connection::{ConnectionsRepo, NewConnection, SealedCreds},
        org::{OrganisationsRepo, Role},
        repo::SystemClock,
    };
    use opsagent_deliver::repo::{
        DeliveriesRepo, IntegrationsRepo, NewDelivery, NewRecipient, RecipientsRepo, SealedToken,
    };
    use serde_json::Value;

    use super::*;
    use crate::{
        actions::{findings::test_support::seeded, orgs::test_support::*},
        adapters::memory::{MemRateLimiter, MemStore},
    };

    fn action(store: &MemStore) -> ExportOrg {
        ExportOrg::new(
            Arc::new(store.clone()),
            Arc::new(MemRateLimiter::default()),
            Arc::new(SystemClock),
        )
    }

    /// Every kind of row the export reads, each carrying `mark` where a secret or another
    /// organisation's text would show.
    async fn fill(store: &MemStore, org: Uuid, mark: &str) {
        let new = NewConnection {
            organisation_id: org,
            provider: "aws".into(),
            display_name: format!("{mark}-conn"),
            template_version: None,
            credential_kind: "role_arn".into(),
        };
        let sealed = || {
            (
                format!("{mark}-SEALED").into_bytes(),
                b"nonce-bytes".to_vec(),
            )
        };
        let (ciphertext, nonce) = sealed();
        let creds = SealedCreds {
            ciphertext,
            nonce,
            kek_version: 1,
        };
        let conn = ConnectionsRepo::insert(store, new, creds).await.unwrap().id;
        seeded(store, org, &format!("{mark}-evidence")).await;
        let new = NewRecipient {
            connection_id: None,
            email: format!("{mark}@example.com").to_lowercase(),
            member_id: None,
            confirm: Some((format!("{mark}-CONFIRMHASH"), chrono::Utc::now())),
        };
        RecipientsRepo::insert(store, org, new).await.unwrap();
        let config = serde_json::json!({
            "team_id": format!("{mark}-TEAMID"), "team_name": format!("{mark}-team"),
            "bot_user_id": format!("{mark}-BOT"), "scope": "chat:write",
        });
        let (ciphertext, nonce) = sealed();
        let token = SealedToken {
            ciphertext,
            nonce,
            kek_version: 1,
        };
        store.upsert_slack(org, config, token).await.unwrap();
        let target = format!("{mark}-TARGET");
        let row = NewDelivery {
            connection_id: Some(conn),
            run_id: Uuid::new_v4(),
            key: "k",
            kind: "briefing",
            channel: "slack",
            target: &target,
            status: "sent",
            external_ref: Some(format!("{mark}-EXTREF")),
            fallback_reason: None,
        };
        DeliveriesRepo::record(store, org, row).await.unwrap();
        store
            .set_customer(org, &format!("cus_{mark}"))
            .await
            .unwrap();
        let s = SubscriptionState {
            subscription_id: format!("sub_{mark}"),
            status: BillingStatus::Active,
            tier: Some(Tier::Team),
            quantity: 1,
            trial_ends_at: None,
            current_period_start: None,
            current_period_end: None,
            cancel_at_period_end: false,
        };
        store
            .apply_subscription(org, &s, chrono::Utc::now())
            .await
            .unwrap();
        let meta = serde_json::json!({ "refresh_token": format!("{mark}-TOKEN"), "scope": "x" });
        let e = AuditEntry::system(
            org,
            "seed.entry",
            ("connection", conn.to_string()),
            "success",
        );
        AuditLog::record(store, e.with_meta(meta)).await.unwrap();
    }

    /// Every object key in `v`, except inside audit `metadata` (free-form, redacted).
    fn keys(v: &Value, into: &mut BTreeSet<String>) {
        match v {
            Value::Object(o) => {
                for (k, v) in o {
                    into.insert(k.clone());
                    if k != "metadata" {
                        keys(v, into);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|v| keys(v, into)),
            _ => {}
        }
    }

    #[tokio::test]
    async fn export_holds_only_named_fields_of_this_organisation() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "o@example.com", "Mine").await;
        let (_, other) = owned_org(&store, "x@example.com", "Theirs").await;
        fill(&store, org.id, "MINE").await;
        fill(&store, other.id, "THEIRS").await;

        let scope = scope(&store, &org, &owner).await;
        let bytes = action(&store).run(&scope).await.unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();

        // The exact field names: a new field must be added here on purpose.
        let mut got = BTreeSet::new();
        keys(&doc, &mut got);
        let want = "exported_at organisation members connections findings delivery_settings \
            recipients deliveries audit_log name slug timezone created_at plan billing_status \
            email role joined_at id display_name provider account_id status connection_id \
            check_id resource severity title summary next_step resolved_at evidence source \
            excerpt redacted integrations scan_time_local briefing_time_local slack_channel_id \
            urgent_alerts kind workspace unsubscribed_at at channel actor_type actor action \
            target_type target outcome metadata";
        let want: BTreeSet<String> = want.split_whitespace().map(str::to_owned).collect();
        assert_eq!(got, want);
        for word in [
            "ciphertext",
            "nonce",
            "kek",
            "dek",
            "external_id",
            "token",
            "secret",
            "customer",
            "subscription_id",
            "hash",
            "password",
            "config",
        ] {
            assert!(got.iter().all(|k| !k.contains(word)), "{word}");
        }

        // No sealed value, Stripe id, token, delivery address or Slack id, and nothing of the
        // other organisation.
        for absent in [
            "SEALED",
            "nonce-bytes",
            "cus_",
            "sub_",
            "TOKEN",
            "CONFIRMHASH",
            "TEAMID",
            "BOT",
            "TARGET",
            "EXTREF",
            "THEIRS",
            "Theirs",
            "x@example.com",
        ] {
            assert!(!text.contains(absent), "{absent}");
        }
        // Its own rows are there.
        assert_eq!(doc["organisation"]["plan"], "team");
        assert_eq!(doc["organisation"]["billing_status"], "active");
        assert_eq!(doc["members"][0]["email"], "o@example.com");
        assert_eq!(doc["connections"][0]["display_name"], "MINE-conn");
        assert_eq!(
            doc["findings"][0]["evidence"][0]["excerpt"],
            "MINE-evidence"
        );
        assert_eq!(doc["recipients"][0]["email"], "mine@example.com");
        assert_eq!(
            doc["delivery_settings"]["integrations"][0]["workspace"],
            "MINE-team"
        );
        assert_eq!(doc["deliveries"][0]["channel"], "slack");
        let seeded = &doc["audit_log"][0];
        assert_eq!(seeded["metadata"], serde_json::json!({ "scope": "x" }));
        assert_eq!(seeded["target"], "MINE-conn");
    }

    #[tokio::test]
    async fn export_is_owner_only_hourly_and_audited_and_a_refused_one_can_be_retried() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "o@example.com", "Mine").await;
        let mate = user(&store, "m@example.com").await;
        store
            .add_member(org.id, mate.id, Role::Member)
            .await
            .unwrap();
        let export = action(&store);
        let as_member = scope(&store, &org, &mate).await;
        let err = export.run(&as_member).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden), "{err:?}");
        let exported = |s: &MemStore| {
            let all = s.audit_entries();
            all.iter().filter(|e| e.action == "org.exported").count()
        };

        // Too large: refused with the 413 each time, never the hourly refusal, and not audited.
        let as_owner = scope(&store, &org, &owner).await;
        let small = ExportOrg {
            max_bytes: 64,
            limiter: export.limiter.clone(),
            ..action(&store)
        };
        for _ in 0..2 {
            let err = small.run(&as_owner).await.unwrap_err();
            assert!(
                matches!(&err, AppError::Refused { status, code, .. }
                    if status.as_u16() == 413 && *code == "export_too_large"),
                "{err:?}"
            );
        }
        assert_eq!(exported(&store), 0);

        // Neither the member nor the refusals used up the hour; a served export does.
        export.run(&as_owner).await.unwrap();
        assert_eq!(exported(&store), 1);
        for _ in 0..2 {
            let err = export.run(&as_owner).await.unwrap_err();
            assert!(
                matches!(
                    &err,
                    AppError::RateLimited {
                        retry_after_secs: 3600,
                        ..
                    }
                ),
                "{err:?}"
            );
        }
        assert_eq!(exported(&store), 1);
    }

    #[tokio::test]
    async fn every_finding_and_audit_entry_is_matched_across_pages() {
        use crate::actions::uow::Repos;
        use opsagent_core::oauth::{ClientKind, Grant, OAuthClient, OAuthRepo};
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "o@example.com", "Mine").await;
        let (_, other) = owned_org(&store, "x@example.com", "Theirs").await;
        let client = OAuthClient {
            client_id: "c-1".into(),
            kind: ClientKind::Dynamic,
            name: "Example".into(),
            redirect_uris: vec![],
            document_fetched_at: None,
            document_cache_until: None,
            last_used_at: None,
            expires_at: None,
        };
        store.upsert_client(&client).await.unwrap();
        let grant = Grant {
            id: Uuid::new_v4(),
            client_id: "c-1".into(),
            member_id: Uuid::new_v4(),
            organisation_id: org.id,
            scope: "opsagent.read".into(),
            created_at: chrono::Utc::now(),
            last_used_at: None,
            revoked_at: None,
        };
        store.insert_grant(&grant).await.unwrap();
        // Five findings of this organisation, each triaged by the agent; one elsewhere.
        seeded(&store, other.id, "theirs").await;
        let all = crate::actions::findings::test_support::page();
        for i in 0..5 {
            seeded(&store, org.id, &format!("ev-{i}")).await;
        }
        let mine = store.findings().list(org.id, Default::default(), all);
        let theirs = store.findings().list(other.id, Default::default(), all);
        let (mine, theirs) = (mine.await.unwrap().items, theirs.await.unwrap().items);
        for id in mine.iter().chain(&theirs).map(|f| f.id) {
            let e = AuditEntry {
                target: Some(("finding", id.to_string())),
                ..AuditEntry::mcp_client(org.id, grant.id, "finding.snoozed", "success")
            };
            AuditLog::record(&store, e).await.unwrap();
        }

        // Two rows per query: three pages of findings, four of audit entries.
        let export = ExportOrg {
            page: 2,
            ..action(&store)
        };
        let scope = scope(&store, &org, &owner).await;
        let doc: Value = serde_json::from_slice(&export.run(&scope).await.unwrap()).unwrap();

        let findings = doc["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 5);
        let mut excerpts = Vec::new();
        for f in findings {
            let own = store
                .findings()
                .evidence(org.id, f["id"].as_str().unwrap().parse().unwrap());
            let own = own.await.unwrap();
            let got = f["evidence"].as_array().unwrap();
            assert_eq!(got.len(), 1);
            assert_eq!(got[0]["excerpt"], own[0].excerpt.as_str());
            excerpts.push(got[0]["excerpt"].as_str().unwrap().to_owned());
        }
        excerpts.sort();
        assert_eq!(excerpts, ["ev-0", "ev-1", "ev-2", "ev-3", "ev-4"]);

        let audit = doc["audit_log"].as_array().unwrap();
        let snoozed: Vec<_> = audit
            .iter()
            .filter(|e| e["action"] == "finding.snoozed")
            .collect();
        assert_eq!(snoozed.len(), 6);
        assert!(snoozed.iter().all(|e| e["actor"] == "agent Example"));
        // Its own findings are named on every page; the other organisation's is not.
        let named = snoozed.iter().filter(|e| e["target"] == "t").count();
        let unnamed = snoozed.iter().filter(|e| e["target"].is_null()).count();
        assert_eq!((named, unnamed), (5, 1));
        assert_eq!(audit.len(), 7);
    }
}
