//! Template v1 as data, and the statement-level diff `verify` runs against the deployed role.
//!
//! The expected policy is rendered from the embedded template itself (`TEMPLATE_V1_YAML`), so
//! the Rust side cannot drift from the YAML; `tests/aws_template.rs` checks the rendering.

use serde_json::Value;
use serde_yaml::Value as Yaml;
use std::collections::{BTreeMap, BTreeSet};

pub const TEMPLATE_V1_YAML: &str =
    include_str!("../../../../templates/aws/opsagent-read-role-v1.yaml");

/// Parameter values the stack was launched with (`terraform`: bucket and prefix, both set).
#[derive(Debug, Clone, Copy)]
pub struct TemplateParams<'a> {
    pub partition: &'a str,
    pub account: &'a str,
    pub external_id: &'a str,
    pub principal: &'a str,
    pub terraform: Option<(&'a str, &'a str)>,
}

impl TemplateParams<'_> {
    fn reference(&self, name: &str) -> Option<String> {
        let (bucket, prefix) = self.terraform.unwrap_or_default();
        Some(match name {
            "AWS::NoValue" => return None,
            "AWS::Partition" => self.partition.into(),
            "AWS::AccountId" => self.account.into(),
            "ExternalId" => self.external_id.into(),
            "OpsAgentPrincipal" => self.principal.into(),
            "TerraformStateBucket" => bucket.into(),
            "TerraformStatePrefix" => prefix.into(),
            "TemplateVersion" => "1".into(),
            other => other.into(),
        })
    }

    fn condition(&self, name: &str) -> bool {
        match name {
            "HasTerraformState" => self.terraform.is_some(),
            other => panic!("unknown template condition {other}"),
        }
    }
}

/// The role as CloudFormation would create it: trust document and inline policy documents.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderedRole {
    pub trust: Value,
    pub policies: Vec<Value>,
}

/// Resolves `!Ref`, `!Sub`, `!If` and `AWS::NoValue` (returned as `None`).
fn resolve(v: &Yaml, p: &TemplateParams) -> Option<Value> {
    Some(match v {
        Yaml::Null => Value::Null,
        Yaml::Bool(b) => Value::Bool(*b),
        Yaml::Number(n) => serde_json::to_value(n).ok()?,
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Sequence(xs) => Value::Array(xs.iter().filter_map(|x| resolve(x, p)).collect()),
        Yaml::Mapping(m) => Value::Object(
            m.iter()
                .filter_map(|(k, v)| Some((k.as_str()?.to_owned(), resolve(v, p)?)))
                .collect(),
        ),
        Yaml::Tagged(t) => match (t.tag.to_string().as_str(), &t.value) {
            ("!Ref", Yaml::String(name)) => Value::String(p.reference(name)?),
            ("!Sub", Yaml::String(s)) => {
                let mut out = s.clone();
                while let Some(i) = out.find("${") {
                    let j = i + out[i..].find('}').expect("closed ${");
                    let val = p.reference(&out[i + 2..j]).unwrap_or_default();
                    out.replace_range(i..=j, &val);
                }
                Value::String(out)
            }
            ("!If", Yaml::Sequence(xs)) => {
                let cond = xs[0].as_str().expect("!If condition name");
                return resolve(&xs[if p.condition(cond) { 1 } else { 2 }], p);
            }
            _ => resolve(&t.value, p)?,
        },
    })
}

pub fn render_template_v1(p: &TemplateParams) -> RenderedRole {
    let y: Yaml = serde_yaml::from_str(TEMPLATE_V1_YAML).expect("embedded template parses");
    let props = &y["Resources"]["OpsAgentReadRole"]["Properties"];
    let trust = resolve(&props["AssumeRolePolicyDocument"], p).expect("trust policy");
    let policies = resolve(&props["Policies"], p)
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .map(|pol| pol["PolicyDocument"].clone())
        .collect();
    RenderedRole { trust, policies }
}

/// Order- and shape-insensitive rendering: object keys sorted, arrays sorted, one-element
/// arrays collapsed to the element (IAM accepts both forms).
fn canon(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut kv: Vec<String> = m
                .iter()
                .map(|(k, v)| format!("{}:{}", Value::from(k.as_str()), canon(v)))
                .collect();
            kv.sort();
            format!("{{{}}}", kv.join(","))
        }
        Value::Array(xs) if xs.len() == 1 => canon(&xs[0]),
        Value::Array(xs) => {
            let mut s: Vec<String> = xs.iter().map(canon).collect();
            s.sort();
            format!("[{}]", s.join(","))
        }
        other => other.to_string(),
    }
}

fn as_strs(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(xs) => xs
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect(),
        _ => vec![],
    }
}

fn statements(doc: &Value) -> Vec<&Value> {
    match &doc["Statement"] {
        Value::Array(xs) => xs.iter().collect(),
        v @ Value::Object(_) => vec![v],
        _ => vec![],
    }
}

/// Everything about a statement except its action list.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StatementScope {
    pub effect: String,
    pub not_action: bool,
    pub not_resource: bool,
    pub resources: Vec<String>,
    /// Canonical JSON of `Condition`; empty when absent.
    pub condition: String,
}

/// Statements grouped by scope; actions keyed lowercase (IAM actions are case-insensitive),
/// values keep the original spelling for reporting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyStatements(pub BTreeMap<StatementScope, BTreeMap<String, String>>);

impl PolicyStatements {
    pub fn from_documents<'a>(docs: impl IntoIterator<Item = &'a Value>) -> Self {
        let mut p = Self::default();
        docs.into_iter().for_each(|d| p.add_document(d));
        p
    }

    pub fn add_document(&mut self, doc: &Value) {
        for s in statements(doc) {
            let not_action = s.get("Action").is_none();
            let not_resource = s.get("Resource").is_none() && s.get("NotResource").is_some();
            let mut resources = as_strs(
                &s[if not_resource {
                    "NotResource"
                } else {
                    "Resource"
                }],
            );
            resources.sort();
            let scope = StatementScope {
                effect: s["Effect"].as_str().unwrap_or_default().to_owned(),
                not_action,
                not_resource,
                resources,
                condition: s.get("Condition").map(canon).unwrap_or_default(),
            };
            let actions = as_strs(&s[if not_action { "NotAction" } else { "Action" }]);
            let set = self.0.entry(scope).or_default();
            for a in actions {
                set.insert(a.trim().to_lowercase(), a.trim().to_owned());
            }
        }
    }
}

fn label(scope: &StatementScope, action: &str, scope_known: bool) -> String {
    let a = if scope.not_action {
        format!("notaction:{action}")
    } else {
        action.to_owned()
    };
    if scope_known {
        return a;
    }
    let not = if scope.not_resource { "not " } else { "" };
    let when = if scope.condition.is_empty() {
        String::new()
    } else {
        format!(" when {}", scope.condition)
    };
    format!("{a} on {not}{}{when}", scope.resources.join(","))
}

/// `(extra, missing)`, both sorted.
/// - extra: every deployed Allow action not granted by a template statement of the same scope
///   (bare action name when the scope exists in the template, else with its scope), and every
///   template Deny action not denied by a deployed statement of identical scope
///   (`deny-missing:<action>`; an altered Resource or Condition counts as missing).
/// - missing: template Allow actions absent from the deployed statement of the same scope.
pub fn policy_diff(
    deployed: &PolicyStatements,
    expected: &PolicyStatements,
) -> (Vec<String>, Vec<String>) {
    let none = BTreeMap::new();
    let (mut extra, mut missing) = (vec![], vec![]);
    for (scope, acts) in deployed.0.iter().filter(|(s, _)| s.effect == "Allow") {
        let exp = expected.0.get(scope);
        for (k, a) in acts {
            if !exp.unwrap_or(&none).contains_key(k) {
                extra.push(label(scope, a, exp.is_some()));
            }
        }
    }
    for (scope, acts) in &expected.0 {
        let dep = deployed.0.get(scope).unwrap_or(&none);
        for (_, a) in acts.iter().filter(|(k, _)| !dep.contains_key(*k)) {
            if scope.effect == "Deny" {
                extra.push(format!("deny-missing:{}", label(scope, a, true)));
            } else {
                missing.push(label(scope, a, true));
            }
        }
    }
    extra.sort();
    extra.dedup();
    missing.sort();
    (extra, missing)
}

/// Every deployed Allow trust statement must equal a template statement (principal is the
/// outbound role, `sts:ExternalId` StringEquals present). Deviations are named by field so the
/// ExternalId value never lands in the report.
pub fn trust_diff(deployed: &Value, expected: &Value) -> Vec<String> {
    let strip = |s: &Value| {
        let mut s = s.clone();
        if let Some(m) = s.as_object_mut() {
            m.remove("Sid");
        }
        s
    };
    let exp: Vec<Value> = statements(expected).into_iter().map(strip).collect();
    let exp_set: BTreeSet<String> = exp.iter().map(canon).collect();
    let mut out = BTreeSet::new();
    let mut matched = false;
    for s in statements(deployed).into_iter().map(strip) {
        if exp_set.contains(&canon(&s)) {
            matched = true;
            continue;
        }
        if s["Effect"] == "Deny" {
            continue; // A deny can only narrow who may assume the role.
        }
        for field in [
            "Principal",
            "NotPrincipal",
            "Action",
            "NotAction",
            "Condition",
        ] {
            if canon(&s[field]) != canon(&exp[0][field]) {
                out.insert(format!("trust-policy:{field} differs"));
            }
        }
    }
    if !matched && out.is_empty() {
        out.insert("trust-policy:statement missing".into());
    }
    out.into_iter().collect()
}

/// What `verify` reads from the deployed role.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DeployedRole {
    pub trust: Value,
    pub max_session_duration: i32,
    pub policies: Vec<Value>,
    pub attached_policy_arns: Vec<String>,
}

/// Full role diff: inline statements, trust policy, attached managed policies (never part of
/// the template, so each is extra) and `MaxSessionDuration`.
pub fn diff_role(deployed: &DeployedRole, params: &TemplateParams) -> (Vec<String>, Vec<String>) {
    let t = render_template_v1(params);
    let (mut extra, missing) = policy_diff(
        &PolicyStatements::from_documents(&deployed.policies),
        &PolicyStatements::from_documents(&t.policies),
    );
    extra.extend(trust_diff(&deployed.trust, &t.trust));
    extra.extend(
        deployed
            .attached_policy_arns
            .iter()
            .map(|a| format!("attached-policy:{a}")),
    );
    if deployed.max_session_duration > 3600 {
        extra.push("role:MaxSessionDuration>3600".into());
    }
    extra.sort();
    (extra, missing)
}
