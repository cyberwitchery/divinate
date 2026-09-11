//! built-in normalizers for retained tool output.
//!
//! a normalizer returns typed observation fields. core assigns identity,
//! provenance, and state. [`crate::pack::normalize`] provides the external pack
//! path.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::model::{EvidenceClass, ObservationKind, Severity, Status, Subject};

#[derive(Debug)]
pub(crate) struct Adapted {
    pub claim_key: String,
    pub data: Value,
    pub evidence_class: EvidenceClass,
    pub kind: ObservationKind,
    pub severity: Option<Severity>,
    pub status: Option<Status>,
}

pub(crate) fn adapt(adapter: &str, payload: &Value, subject: &Subject) -> Result<Adapted> {
    match adapter {
        "sbom-diff" => adapt_sbom_diff(payload),
        "unsafe-budget" => adapt_unsafe_budget(payload),
        "github-branch-protection" => adapt_github_branch_protection(payload, subject),
        "github-branch-policy-history" => adapt_branch_policy_history(payload, subject),
        "github-release-membership" => adapt_release_membership(payload),
        "github-pull-request-reviews" => adapt_pull_request_reviews(payload),
        "github-repository-mutations" => adapt_repository_mutations(payload),
        "supply-chain-gate" => adapt_supply_chain_gate(payload),
        _ => Err(Error::Invalid(format!("unknown adapter: {adapter:?}"))),
    }
}

#[derive(Deserialize)]
struct RepositoryMutations {
    branch: String,
    events: Vec<RepositoryMutation>,
}

#[derive(Deserialize, serde::Serialize)]
struct RepositoryMutation {
    event_id: String,
    kind: String,
    occurred_at: String,
    commit: String,
    #[serde(default)]
    pull_request: Option<u64>,
}

fn adapt_repository_mutations(payload: &Value) -> Result<Adapted> {
    let source: RepositoryMutations = serde_json::from_value(payload.clone())
        .map_err(|error| Error::Invalid(format!("invalid repository-mutations output: {error}")))?;
    Ok(Adapted {
        claim_key: format!("github:repository-mutations:{}", source.branch),
        data: json!({
            "branch": source.branch,
            "events": source.events,
        }),
        evidence_class: EvidenceClass::ObservedOperation,
        kind: ObservationKind::MutationHistory,
        severity: None,
        status: None,
    })
}

#[derive(Deserialize)]
struct SbomDiff {
    added: ItemsOrCount<Component>,
    removed: ItemsOrCount<Component>,
    changed: ItemsOrCount<ComponentChange>,
    #[serde(alias = "edge_changes")]
    edge_diffs: ItemsOrCount<Value>,
    metadata_changed: Option<Value>,
    old_total: u64,
    new_total: u64,
    unchanged: Option<u64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ItemsOrCount<T> {
    Items(Vec<T>),
    Count(u64),
}

impl<T> ItemsOrCount<T> {
    fn count(&self) -> u64 {
        match self {
            Self::Items(items) => u64::try_from(items.len()).unwrap_or(u64::MAX),
            Self::Count(count) => *count,
        }
    }

    fn items(&self) -> &[T] {
        match self {
            Self::Items(items) => items,
            Self::Count(_) => &[],
        }
    }
}

#[derive(Deserialize)]
struct Component {
    id: String,
}

#[derive(Deserialize)]
struct ComponentChange {
    id: String,
}

fn adapt_sbom_diff(payload: &Value) -> Result<Adapted> {
    let source: SbomDiff = serde_json::from_value(payload.clone())
        .map_err(|error| Error::Invalid(format!("invalid sbom-diff output: {error}")))?;
    Ok(Adapted {
        claim_key: "sbom-diff:dependency-change".into(),
        data: json!({
            "counts": {
                "added": source.added.count(),
                "changed": source.changed.count(),
                "dependency_edges_changed": source.edge_diffs.count(),
                "new_total": source.new_total,
                "old_total": source.old_total,
                "removed": source.removed.count(),
                "unchanged": source.unchanged,
            },
            "components": {
                "added": source.added.items().iter().map(|item| item.id.as_str()).collect::<Vec<_>>(),
                "changed": source.changed.items().iter().map(|item| item.id.as_str()).collect::<Vec<_>>(),
                "removed": source.removed.items().iter().map(|item| item.id.as_str()).collect::<Vec<_>>(),
            },
            "metadata_changed": source.metadata_changed,
        }),
        evidence_class: EvidenceClass::ObservedState,
        kind: ObservationKind::ChangeSet,
        severity: None,
        status: None,
    })
}

#[derive(Deserialize)]
struct UnsafeBudget {
    scan: UnsafeScan,
    violations: Vec<Value>,
    #[serde(default)]
    warnings: Vec<Value>,
    passed: bool,
}

#[derive(Deserialize)]
struct UnsafeScan {
    analyzer_id: String,
    language: String,
    scope: Value,
    totals: Value,
    units: Vec<Value>,
}

fn adapt_unsafe_budget(payload: &Value) -> Result<Adapted> {
    let source: UnsafeBudget = serde_json::from_value(payload.clone())
        .map_err(|error| Error::Invalid(format!("invalid unsafe-budget output: {error}")))?;
    Ok(Adapted {
        claim_key: "unsafe-budget:default".into(),
        data: json!({
            "analyzer_id": source.scan.analyzer_id,
            "language": source.scan.language,
            "scope": source.scan.scope,
            "totals": source.scan.totals,
            "units": source.scan.units,
            "violations": source.violations,
            "warnings": source.warnings,
        }),
        evidence_class: EvidenceClass::ObservedOperation,
        kind: ObservationKind::PolicyCheck,
        severity: (!source.passed).then_some(Severity::High),
        status: Some(if source.passed {
            Status::Pass
        } else {
            Status::Fail
        }),
    })
}

#[derive(Deserialize)]
struct BranchProtection {
    #[serde(default)]
    required_status_checks: RequiredStatusChecks,
    required_pull_request_reviews: RequiredReviews,
    enforce_admins: Enabled,
    #[serde(default)]
    allow_force_pushes: Enabled,
    #[serde(default)]
    allow_deletions: Enabled,
}

#[derive(Default, Deserialize)]
struct Enabled {
    #[serde(default)]
    enabled: bool,
}

#[derive(Default, Deserialize)]
struct RequiredStatusChecks {
    #[serde(default)]
    strict: bool,
    #[serde(default)]
    contexts: Vec<String>,
    #[serde(default)]
    checks: Vec<NamedCheck>,
}

#[derive(Deserialize)]
struct NamedCheck {
    context: String,
}

#[derive(Deserialize)]
struct RequiredReviews {
    required_approving_review_count: u64,
    #[serde(default)]
    dismiss_stale_reviews: bool,
    #[serde(default)]
    require_code_owner_reviews: bool,
    #[serde(default)]
    require_last_push_approval: bool,
}

fn adapt_github_branch_protection(payload: &Value, subject: &Subject) -> Result<Adapted> {
    let source: BranchProtection = serde_json::from_value(payload.clone()).map_err(|error| {
        Error::Invalid(format!("invalid github branch-protection output: {error}"))
    })?;
    let mut checks = source.required_status_checks.contexts;
    checks.extend(
        source
            .required_status_checks
            .checks
            .into_iter()
            .map(|item| item.context),
    );
    checks.sort();
    checks.dedup();
    let branch = subject.qualifier("branch").unwrap_or("unknown");
    Ok(Adapted {
        claim_key: format!("github:branch-protection:{branch}"),
        data: json!({
            "allows_deletions": source.allow_deletions.enabled,
            "allows_force_pushes": source.allow_force_pushes.enabled,
            "dismisses_stale_reviews": source.required_pull_request_reviews.dismiss_stale_reviews,
            "enforces_admins": source.enforce_admins.enabled,
            "requires_code_owner_reviews": source.required_pull_request_reviews.require_code_owner_reviews,
            "requires_last_push_approval": source.required_pull_request_reviews.require_last_push_approval,
            "required_approving_review_count": source.required_pull_request_reviews.required_approving_review_count,
            "required_status_checks": checks,
            "requires_strict_status_checks": source.required_status_checks.strict,
        }),
        evidence_class: EvidenceClass::ConfiguredIntent,
        kind: ObservationKind::ConfigurationSnapshot,
        severity: None,
        status: None,
    })
}

#[derive(Deserialize)]
struct BranchPolicyHistory {
    branch: String,
    complete_from: String,
    complete_through: String,
    events: Vec<BranchPolicyEvent>,
}

#[derive(Deserialize, serde::Serialize)]
struct BranchPolicyEvent {
    event_id: String,
    effective_at: String,
    required_approving_review_count: u64,
    requires_last_push_approval: bool,
}

fn adapt_branch_policy_history(payload: &Value, subject: &Subject) -> Result<Adapted> {
    let source: BranchPolicyHistory = serde_json::from_value(payload.clone())
        .map_err(|error| Error::Invalid(format!("invalid branch-policy history: {error}")))?;
    let branch = subject.qualifier("branch").unwrap_or(&source.branch);
    Ok(Adapted {
        claim_key: format!("github:branch-policy-history:{branch}"),
        data: json!({
            "branch": source.branch,
            "complete_from": source.complete_from,
            "complete_through": source.complete_through,
            "events": source.events,
        }),
        evidence_class: EvidenceClass::ConfiguredIntent,
        kind: ObservationKind::ConfigurationHistory,
        severity: None,
        status: None,
    })
}

#[derive(Deserialize)]
struct ReleaseMembership {
    release: Release,
    base_revision: String,
    target_revision: String,
    pull_requests: Vec<u64>,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    published_at: String,
}

fn adapt_release_membership(payload: &Value) -> Result<Adapted> {
    let source: ReleaseMembership = serde_json::from_value(payload.clone())
        .map_err(|error| Error::Invalid(format!("invalid release-membership output: {error}")))?;
    Ok(Adapted {
        claim_key: format!("github:release-membership:{}", source.release.tag_name),
        data: json!({
            "base_revision": source.base_revision,
            "published_at": source.release.published_at,
            "pull_requests": source.pull_requests,
            "release": source.release.tag_name,
            "target_revision": source.target_revision,
        }),
        evidence_class: EvidenceClass::ObservedState,
        kind: ObservationKind::ReleaseMembership,
        severity: None,
        status: None,
    })
}

#[derive(Deserialize)]
struct PullRequestReviews {
    release: String,
    base_branch: String,
    target_revision: String,
    pull_requests: Vec<PullRequest>,
}

#[derive(Deserialize, serde::Serialize)]
struct PullRequest {
    number: u64,
    author: String,
    merge_commit_sha: String,
    merged_at: String,
    approvals: Vec<Approval>,
}

#[derive(Deserialize, serde::Serialize)]
struct Approval {
    actor: String,
    submitted_at: String,
    state: String,
}

fn adapt_pull_request_reviews(payload: &Value) -> Result<Adapted> {
    let source: PullRequestReviews = serde_json::from_value(payload.clone())
        .map_err(|error| Error::Invalid(format!("invalid pull-request review output: {error}")))?;
    Ok(Adapted {
        claim_key: format!("github:pull-request-reviews:{}", source.release),
        data: json!({
            "base_branch": source.base_branch,
            "pull_requests": source.pull_requests,
            "release": source.release,
            "target_revision": source.target_revision,
        }),
        evidence_class: EvidenceClass::ObservedOperation,
        kind: ObservationKind::ReviewRecord,
        severity: None,
        status: None,
    })
}

#[derive(Deserialize)]
struct SupplyChainGate {
    policy: GatePolicy,
    input: GateInput,
    passed: bool,
    #[serde(default)]
    violations: Vec<Value>,
}

#[derive(Deserialize)]
struct GatePolicy {
    id: String,
}

#[derive(Deserialize)]
struct GateInput {
    sbom_diff_sha256: String,
    base_revision: String,
    target_revision: String,
}

fn adapt_supply_chain_gate(payload: &Value) -> Result<Adapted> {
    let source: SupplyChainGate = serde_json::from_value(payload.clone())
        .map_err(|error| Error::Invalid(format!("invalid supply-chain gate output: {error}")))?;
    Ok(Adapted {
        claim_key: format!("supply-chain-gate:{}", source.policy.id),
        data: json!({
            "base_revision": source.input.base_revision,
            "evaluated_sbom_diff_sha256": source.input.sbom_diff_sha256,
            "policy_id": source.policy.id,
            "target_revision": source.input.target_revision,
            "violations": source.violations,
        }),
        evidence_class: EvidenceClass::ObservedOperation,
        kind: ObservationKind::PolicyCheck,
        severity: (!source.passed).then_some(Severity::High),
        status: Some(if source.passed {
            Status::Pass
        } else {
            Status::Fail
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn subject() -> Subject {
        Subject {
            kind: "repository".into(),
            id: "example".into(),
            qualifiers: BTreeMap::from([("branch".into(), json!("main"))]),
        }
    }

    #[test]
    fn malformed_gate_output_is_rejected() {
        let error = adapt("unsafe-budget", &json!({"passed": true}), &subject()).unwrap_err();
        assert!(error.to_string().contains("missing field `scan`"));
    }

    #[test]
    fn branch_checks_are_deduplicated() {
        let output = adapt(
            "github-branch-protection",
            &json!({
                "required_status_checks": {"strict": true, "contexts": ["ci"], "checks": [{"context": "ci"}]},
                "required_pull_request_reviews": {"required_approving_review_count": 2},
                "enforce_admins": {"enabled": true}
            }),
            &subject(),
        )
        .unwrap();
        assert_eq!(output.data["required_status_checks"], json!(["ci"]));
    }

    #[test]
    fn branch_protection_without_status_checks_is_valid() {
        let output = adapt(
            "github-branch-protection",
            &json!({
                "required_pull_request_reviews": {"required_approving_review_count": 1},
                "enforce_admins": {"enabled": false}
            }),
            &subject(),
        )
        .unwrap();
        assert_eq!(output.data["required_status_checks"], json!([]));
        assert_eq!(output.data["required_approving_review_count"], 1);
    }
}
