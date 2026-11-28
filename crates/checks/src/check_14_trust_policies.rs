use crate::ctx::{draft, short, Check, CheckCtx};
use opsagent_connectors::Capability;
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::{Provider, Resource};
use serde_json::Value;
use std::collections::BTreeSet;

/// Who may assume each IAM role. The browser twin is opsagent-web's `lib/tools/trust-policy.ts`;
/// `tests/fixtures/trust-policy-cases.json` pins the cases both must agree on.
pub struct TrustPolicies;

// shortcut: federated principals (GitHub OIDC without a `sub` condition), `NotPrincipal` and
// the customer's other connected accounts are not judged (spec trust-policy-check.md section 5).
// shortcut: one finding per variant per role, not per statement: the finding key has no
// statement index, so two statements of one kind would share it. Accounts merge into one.
impl Check for TrustPolicies {
    fn id(&self) -> &'static str {
        "14"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Aws, Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[Capability::Inventory]
    }

    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        // A denied or missing roles read leaves nothing to judge.
        if ctx.unavailable.contains("iam_role") {
            return out;
        }
        for r in ctx.resources.iter().filter(|r| r.service() == "iam_role") {
            let t = Trust::of(r);
            let (name, id) = (short(r), &r.identity);
            let mut add = |variant, sev, (title, summary, step): (String, String, &str), ex| {
                out.push(draft(
                    ctx,
                    "14",
                    r,
                    variant,
                    sev,
                    (title, summary, step),
                    ex,
                ));
            };
            if t.any {
                add(
                    "any_principal",
                    Severity::Critical,
                    (format!("{name} can be assumed by anyone in any AWS account"),
                    format!("Role {id} trusts every AWS principal and has no condition on who may assume it."),
                    "Anyone with an AWS account can ask to become this role. Replace the principal with the exact accounts or roles that need it, or add a condition that limits who may assume it: IAM console > Roles > the role > Trust relationships > Edit trust policy."),
                    "principal=*".into(),
                );
            }
            if t.any_conditional {
                add(
                    "any_principal_conditional",
                    Severity::Medium,
                    (format!("{name} can be assumed by any AWS principal, limited only by a condition"),
                    format!("Role {id} trusts * and relies on a condition to decide who may assume it."),
                    "Only the condition decides who gets in, so a wrong key or value opens the role to everyone. Check that it names your own accounts or organisation (for example aws:PrincipalOrgID): IAM console > Roles > the role > Trust relationships > Edit trust policy."),
                    "principal=* condition=present".into(),
                );
            }
            if !t.foreign.is_empty() {
                let accounts = t.foreign.iter().cloned().collect::<Vec<_>>().join(", ");
                let noun = if t.foreign.len() == 1 {
                    "account"
                } else {
                    "accounts"
                };
                add(
                    "foreign_account_no_external_id",
                    Severity::Medium,
                    (format!("{name} trusts {noun} {accounts} with no sts:ExternalId condition"),
                    format!("Role {id} can be assumed from {noun} {accounts}, and its trust policy does not require an external ID."),
                    "If that account belongs to a vendor or another third party, any other customer of the same vendor can point their service at your role (the confused deputy problem). Add a condition on sts:ExternalId, using the ID the vendor gave you: IAM console > Roles > the role > Trust relationships > Edit trust policy. If the account is your own, you can leave it."),
                    format!("principal_accounts={accounts}"),
                );
            }
        }
        out
    }
}

/// What a role's trust policy allows, summed over its statements.
#[derive(Default)]
struct Trust {
    any: bool,
    any_conditional: bool,
    foreign: BTreeSet<String>,
}

impl Trust {
    fn of(r: &Resource) -> Self {
        let own = account_of(&r.identity);
        let mut t = Self::default();
        for st in list(&r.attributes["trust_policy"]["Statement"]) {
            if st["Effect"] != "Allow" || !list(&st["Action"]).iter().any(|a| assumes(a)) {
                continue;
            }
            let principals = match &st["Principal"] {
                Value::Object(p) => list(p.get("AWS").unwrap_or(&Value::Null)),
                other => list(other),
            };
            let has_condition = st["Condition"].as_object().is_some_and(|c| !c.is_empty());
            if principals.iter().any(|p| *p == "*") {
                if has_condition {
                    t.any_conditional = true;
                } else {
                    t.any = true;
                }
            } else if !has_external_id(&st["Condition"]) {
                let accounts = principals
                    .iter()
                    .filter_map(|p| p.as_str().and_then(account));
                t.foreign
                    .extend(accounts.filter(|a| Some(a.as_str()) != own.as_deref()));
            }
        }
        t
    }
}

/// A missing or null value is empty, an array is its items, anything else is one item.
fn list(v: &Value) -> Vec<&Value> {
    match v {
        Value::Null => vec![],
        Value::Array(xs) => xs.iter().collect(),
        one => vec![one],
    }
}

fn assumes(action: &Value) -> bool {
    action.as_str().is_some_and(|a| {
        ["*", "sts:*", "sts:assumerole"]
            .iter()
            .any(|x| a.eq_ignore_ascii_case(x))
    })
}

/// Any condition operator on the `sts:ExternalId` key, in any case.
fn has_external_id(cond: &Value) -> bool {
    cond.as_object().is_some_and(|ops| {
        ops.values().any(|op| {
            op.as_object().is_some_and(|keys| {
                keys.keys()
                    .any(|k| k.eq_ignore_ascii_case("sts:externalid"))
            })
        })
    })
}

/// A bare 12-digit account id, or the account of an `arn:aws:iam::<id>:...` ARN.
fn account(principal: &str) -> Option<String> {
    let id =
        |s: &str| (s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.to_owned());
    id(principal).or_else(|| account_of(principal))
}

fn account_of(arn: &str) -> Option<String> {
    let p: Vec<&str> = arn.splitn(6, ':').collect();
    let partition = p.get(1)?.strip_prefix("aws")?;
    let ok = p[0] == "arn"
        && partition
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && p.get(2) == Some(&"iam")
        && p.get(3) == Some(&"")
        && p.len() == 6;
    ok.then(|| p[4])
        .filter(|a| a.len() == 12 && a.bytes().all(|b| b.is_ascii_digit()))
        .map(str::to_owned)
}
