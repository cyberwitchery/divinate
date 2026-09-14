//! typed assertion evaluators.
//!
//! [`DerivedAssertion`] stores support, contradictions, rejected evidence,
//! coverage, limitations, missing requirements, and evaluator identity. its id is
//! derived from assertion type and subject.
//!
//! universal claims require complete authoritative coverage. one intact
//! counterexample can contradict them with incomplete coverage. [`Outcome`] keeps
//! insufficient evidence and non-automatable claims separate from failures.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::coverage::{
    self, CoverageDecision, CoverageOutcome, CoverageRequirement, RunDisposition,
};
use crate::error::{Error, Result};
use crate::model::{
    Corpus, EvidenceClass, Observation, ObservationKind, Proposition, Status, TimeRange,
};
use crate::{hex_digest, parse_timestamp};

const CONFIGURED_REVIEWS_VERSION: &str = "configured-reviews/v1";
const RELEASE_REVIEWS_VERSION: &str = "release-reviews/v1";
const SUPPLY_CHAIN_VERSION: &str = "release-supply-chain/v1";
const SECURITY_REVIEW_VERSION: &str = "adequate-security-review/v1";
const MAIN_CHANGES_REVIEWED_VERSION: &str = "main-changes-reviewed/v1";
const INDEPENDENT_REVIEW_VERSION: &str = "configured-independent-review/v1";
const DEPENDENCY_VISIBILITY_VERSION: &str = "dependency-change-visibility/v1";
const CONFIG_FRESHNESS_DAYS: i64 = 7;

#[derive(Debug, Clone)]
/// what to evaluate: a repository, branch, release, and interval.
pub struct EvaluationTarget {
    pub repository: String,
    pub branch: String,
    pub release: Option<String>,
    pub from: String,
    pub until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// a deterministic claim with evidence, coverage, limitations, and derivation.
pub struct DerivedAssertion {
    pub id: String,
    pub assertion_type: AssertionType,
    pub claim: String,
    pub subject: AssertionSubject,
    pub outcome: Outcome,
    pub evaluated_at: String,
    pub validity: Validity,
    pub derivation: Derivation,
    pub support: Vec<EvidenceUse>,
    pub contradictions: Vec<EvidenceUse>,
    /// evidence examined and rejected, with the reason it did not apply.
    pub considered: Vec<EvidenceUse>,
    /// what the corpus would need to contain for this claim to be decidable.
    pub missing: Vec<MissingEvidence>,
    /// the exact fields two observations had to agree on to be combined.
    pub identity_joins: Vec<IdentityJoin>,
    pub reasoning: Vec<ReasonStep>,
    pub limitations: Vec<String>,
    /// whether the populations this claim depends on were fully enumerated.
    pub coverage: Vec<CoverageDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// which claim this is. [`Self::External`] carries a type provided by a pack.
pub enum AssertionType {
    ConfiguredReviewRequirement,
    ReleaseReviewOperation,
    ReleaseSupplyChainPolicy,
    AdequateHumanSecurityReview,
    EveryMainChangeReviewed,
    ConfiguredIndependentReview,
    DependencyChangeVisibility,
    External(String),
}

impl AssertionType {
    /// the stable wire name of this assertion type.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::ConfiguredReviewRequirement => "configured_review_requirement",
            Self::ReleaseReviewOperation => "release_review_operation",
            Self::ReleaseSupplyChainPolicy => "release_supply_chain_policy",
            Self::AdequateHumanSecurityReview => "adequate_human_security_review",
            Self::EveryMainChangeReviewed => "every_main_change_reviewed",
            Self::ConfiguredIndependentReview => "configured_independent_review",
            Self::DependencyChangeVisibility => "dependency_change_visibility",
            Self::External(value) => value,
        }
    }
}

impl Serialize for AssertionType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AssertionType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "configured_review_requirement" => Self::ConfiguredReviewRequirement,
            "release_review_operation" => Self::ReleaseReviewOperation,
            "release_supply_chain_policy" => Self::ReleaseSupplyChainPolicy,
            "adequate_human_security_review" => Self::AdequateHumanSecurityReview,
            "every_main_change_reviewed" => Self::EveryMainChangeReviewed,
            "configured_independent_review" => Self::ConfiguredIndependentReview,
            "dependency_change_visibility" => Self::DependencyChangeVisibility,
            _ => Self::External(value),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// what a claim is about. an interval-bearing subject is required for coverage-backed claims.
pub struct AssertionSubject {
    pub repository: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// the result of an evaluation.
pub enum Outcome {
    Supported,
    Contradicted,
    InsufficientEvidence,
    Stale,
    NotAutomatable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// when a claim holds, and until when it stays fresh.
pub struct Validity {
    pub basis: ValidityBasis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub through: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// the end of a point-in-time claim's freshness.
    pub fresh_until: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// whether a claim is point-in-time, about a historical release, or not established.
pub enum ValidityBasis {
    PointInTime,
    HistoricalRelease,
    NotEstablished,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// which evaluator produced a claim, and the pack invocation behind it if any.
pub struct Derivation {
    pub evaluator: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_invocation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// one observation used, and why it was used that way.
pub struct EvidenceUse {
    pub observation_id: String,
    pub source_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// a specific requirement the corpus does not meet, and for which subject.
pub struct MissingEvidence {
    pub requirement: String,
    pub subject: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// two observations joined, and the exact fields they had to agree on.
pub struct IdentityJoin {
    pub left_observation_id: String,
    pub right_observation_id: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// one recorded step of the reasoning, with the evidence it rests on.
pub struct ReasonStep {
    pub code: String,
    pub conclusion: String,
    pub evidence_ids: Vec<String>,
}

/// run the explicit typed evaluators.
///
/// # Errors
///
/// returns an error when corpus timestamps or typed observation payloads are invalid.
pub fn evaluate_all(
    corpus: &Corpus,
    target: &EvaluationTarget,
    at: OffsetDateTime,
) -> Result<Vec<DerivedAssertion>> {
    let mut assertions = vec![
        evaluate_configured_reviews(corpus, target, at)?,
        evaluate_every_main_change_reviewed(corpus, target, at)?,
        evaluate_configured_independent_review(corpus, target, at)?,
    ];
    if target.release.is_some() {
        assertions.extend([
            evaluate_release_reviews(corpus, target, at)?,
            evaluate_supply_chain(corpus, target, at)?,
            evaluate_adequate_security_review(corpus, target, at)?,
            evaluate_dependency_change_visibility(corpus, target, at)?,
        ]);
    }
    Ok(assertions)
}

/// evaluate whether branch configuration requires at least one approving review.
///
/// # Errors
///
/// returns an error when matching evidence has an invalid timestamp or payload.
pub fn evaluate_configured_independent_review(
    corpus: &Corpus,
    target: &EvaluationTarget,
    at: OffsetDateTime,
) -> Result<DerivedAssertion> {
    let mut assertion = base_assertion(
        AssertionType::ConfiguredIndependentReview,
        &format!(
            "changes to {} are configured to require approval before merge",
            target.branch
        ),
        branch_subject(target),
        at,
        INDEPENDENT_REVIEW_VERSION,
        ValidityBasis::PointInTime,
    )?;
    let Some((latest, observed_at)) = branch_configurations(corpus, target, at)?.pop() else {
        let authority_withdrawn = corpus.observations.iter().any(|item| {
            is_github_branch_protection(item, &target.branch)
                && item.kind == ObservationKind::ConfigurationSnapshot
                && item.subject.id == target.repository
                && item.subject.qualifier("branch") == Some(target.branch.as_str())
                && !observation_authoritative(corpus, item, Proposition::BranchConfiguration)
        });
        let reason = if authority_withdrawn {
            "matching branch-protection evidence exists, but its linked acquisition contract has no current authority"
        } else {
            "current configured review intent was not observed"
        };
        assertion.missing.push(MissingEvidence {
            requirement: "branch_protection_snapshot".into(),
            subject: format!("{}#{}", target.repository, target.branch),
            reason: reason.into(),
        });
        assertion.reasoning.push(ReasonStep {
            code: "branch_configuration_unavailable".into(),
            conclusion: reason.into(),
            evidence_ids: vec![],
        });
        return Ok(assertion);
    };
    let data: BranchProtectionData = payload(latest)?;
    assertion.validity.at = Some(format_time(at)?);
    assertion.validity.fresh_until = Some(format_time(
        observed_at + Duration::days(CONFIG_FRESHNESS_DAYS),
    )?);
    if data.required_approving_review_count >= 1 {
        assertion.support.push(use_evidence(
            latest,
            &format!(
                "branch protection requires {} approving review(s)",
                data.required_approving_review_count
            ),
        ));
        assertion.outcome = if at - observed_at > Duration::days(CONFIG_FRESHNESS_DAYS) {
            Outcome::Stale
        } else {
            Outcome::Supported
        };
        assertion.reasoning.push(step(
            "approval_required",
            "the latest branch-protection snapshot requires approval before merge",
            &[latest],
        ));
    } else {
        assertion.contradictions.push(use_evidence(
            latest,
            "the latest branch-protection snapshot requires no approving reviews",
        ));
        assertion.outcome = Outcome::Contradicted;
    }
    assertion.limitations.push("this establishes configured intent only. it does not establish operating effectiveness or organizational independence".into());
    Ok(assertion)
}

/// evaluate whether an exact release dependency delta is preserved in the corpus.
///
/// # Errors
///
/// returns an error when matching evidence has an invalid timestamp or payload.
pub fn evaluate_dependency_change_visibility(
    corpus: &Corpus,
    target: &EvaluationTarget,
    at: OffsetDateTime,
) -> Result<DerivedAssertion> {
    let release = release_name(target)?;
    let mut assertion = base_assertion(
        AssertionType::DependencyChangeVisibility,
        &format!("dependency changes for release {release} are identified and preserved"),
        release_subject(target),
        at,
        DEPENDENCY_VISIBILITY_VERSION,
        ValidityBasis::HistoricalRelease,
    )?;
    let Some((diff, _)) = latest_matching(corpus, at, |item| {
        item.kind == ObservationKind::ChangeSet && matches_release(item, target)
    })?
    else {
        assertion.missing.push(missing(
            "sbom_diff",
            target,
            "no dependency delta matches the release and revision scope",
        ));
        return Ok(assertion);
    };
    assertion.support.push(use_evidence(
        diff,
        "preserves the normalized dependency delta and its byte-exact source",
    ));
    assertion.reasoning.push(step(
        "dependency_delta_preserved",
        "a source-backed SBOM delta matches the release scope",
        &[diff],
    ));
    assertion.validity.through = Some(diff.observed_at.clone());
    assertion.outcome = Outcome::Supported;
    assertion.limitations.push("the delta covers dependencies declared by the two supplied SBOMs. it does not establish runtime-loaded software or comparable generator environments".into());
    Ok(assertion)
}

/// evaluate whether every target-branch mutation was reviewed before integration.
///
/// complete mutation and review coverage supports the claim. one direct push
/// contradicts it with incomplete coverage.
///
/// # Errors
///
/// returns an error when scopes, timestamps, or typed payloads are invalid.
pub fn evaluate_every_main_change_reviewed(
    corpus: &Corpus,
    target: &EvaluationTarget,
    at: OffsetDateTime,
) -> Result<DerivedAssertion> {
    let mut assertion = base_assertion(
        AssertionType::EveryMainChangeReviewed,
        &format!(
            "every change to {} during {} .. {} was reviewed before integration",
            target.branch, target.from, target.until
        ),
        interval_branch_subject(target),
        at,
        MAIN_CHANGES_REVIEWED_VERSION,
        ValidityBasis::HistoricalRelease,
    )?;
    assertion.validity.from = Some(target.from.clone());
    assertion.validity.through = Some(target.until.clone());

    let mutation_coverage = coverage::assess(
        corpus,
        coverage_requirement(target, Proposition::RepositoryMutations),
        at,
    )?;
    let review_coverage = coverage::assess(
        corpus,
        coverage_requirement(target, Proposition::PullRequestReviews),
        at,
    )?;
    let authoritative_mutation_runs = authoritative_runs(&mutation_coverage);
    let authoritative_review_runs = authoritative_runs(&review_coverage);

    let merges = collect_mutations(corpus, target, &authoritative_mutation_runs, &mut assertion)?;
    let reviews = collect_reviews(corpus, target, &authoritative_review_runs)?;
    evaluate_mutation_reviews(target, merges, &reviews, &mut assertion)?;

    if !assertion.contradictions.is_empty() {
        assertion.outcome = Outcome::Contradicted;
    } else if mutation_coverage.outcome != CoverageOutcome::Complete
        || review_coverage.outcome != CoverageOutcome::Complete
        || !assertion.missing.is_empty()
    {
        assertion.outcome = Outcome::InsufficientEvidence;
        add_coverage_gap(&mut assertion, &mutation_coverage);
        add_coverage_gap(&mut assertion, &review_coverage);
        assertion.reasoning.push(step(
            "population_not_established",
            "no counterexample was found, but the complete authoritative population was not established",
            &[],
        ));
    } else {
        assertion.outcome = Outcome::Supported;
        assertion.reasoning.push(step(
            "universal_population_checked",
            "complete authoritative mutation and review populations were joined and every mutation had a qualifying review",
            &[],
        ));
    }
    assertion.coverage = vec![mutation_coverage, review_coverage];
    assertion.limitations.push("github audit events are treated as authoritative for recorded repository mutations only because the collection run declares that proposition and complete scope".into());
    Ok(assertion)
}

/// evaluate configured review intent for one branch at one point in time.
///
/// # Errors
///
/// returns an error when matching evidence has an invalid timestamp or payload.
pub fn evaluate_configured_reviews(
    corpus: &Corpus,
    target: &EvaluationTarget,
    at: OffsetDateTime,
) -> Result<DerivedAssertion> {
    let mut candidates = branch_configurations(corpus, target, at)?;
    let subject = branch_subject(target);
    let mut assertion = base_assertion(
        AssertionType::ConfiguredReviewRequirement,
        "main is configured to require two approvals, including approval of the last push by someone else",
        subject,
        at,
        CONFIGURED_REVIEWS_VERSION,
        ValidityBasis::PointInTime,
    )?;
    let Some((latest, observed_at)) = candidates.pop() else {
        assertion.outcome = Outcome::InsufficientEvidence;
        assertion.missing.push(MissingEvidence {
            requirement: "branch_protection_snapshot".into(),
            subject: format!("{}#{}", target.repository, target.branch),
            reason: "configured review intent cannot be established without a branch-protection observation at or before the evaluation time".into(),
        });
        assertion.reasoning.push(step(
            "configuration_missing",
            "no applicable branch-protection observation was available",
            &[],
        ));
        return Ok(assertion);
    };
    let data: BranchProtectionData = payload(latest)?;
    assertion.validity.at = Some(format_time(at)?);
    assertion.validity.fresh_until = Some(format_time(
        observed_at + Duration::days(CONFIG_FRESHNESS_DAYS),
    )?);
    for (older, _) in candidates {
        assertion.considered.push(use_evidence(
            older,
            "older configuration snapshot was superseded for this point-in-time evaluation",
        ));
    }
    if data.required_approving_review_count >= 2 && data.requires_last_push_approval {
        assertion.support.push(use_evidence(latest, "latest branch-protection snapshot requires at least two approvals and last-push approval"));
        assertion.reasoning.push(step("configured_threshold_met", "the latest observed configuration requires two approvals and a separate last-push approval", &[latest]));
        assertion.outcome = if at - observed_at > Duration::days(CONFIG_FRESHNESS_DAYS) {
            Outcome::Stale
        } else {
            Outcome::Supported
        };
    } else {
        assertion.contradictions.push(use_evidence(latest, &format!("latest branch-protection snapshot requires {} approval(s); last-push approval is {}", data.required_approving_review_count, data.requires_last_push_approval)));
        assertion.reasoning.push(step(
            "configured_threshold_not_met",
            "the latest authoritative snapshot contradicts the configured requirement",
            &[latest],
        ));
        assertion.outcome = Outcome::Contradicted;
    }
    assertion.limitations.push("github configuration establishes configured intent, not that reviews occurred or that reviewers were organizationally independent".into());
    Ok(assertion)
}

/// evaluate actual review operation across every change in one release.
///
/// # Errors
///
/// returns an error when matching evidence has an invalid timestamp or payload.
pub fn evaluate_release_reviews(
    corpus: &Corpus,
    target: &EvaluationTarget,
    at: OffsetDateTime,
) -> Result<DerivedAssertion> {
    let release = release_name(target)?;
    let subject = release_subject(target);
    let mut assertion = base_assertion(
        AssertionType::ReleaseReviewOperation,
        &format!("every change included in release {release} received the configured number of reviews before merge"),
        subject,
        at,
        RELEASE_REVIEWS_VERSION,
        ValidityBasis::HistoricalRelease,
    )?;
    let membership = latest_matching(corpus, at, |item| {
        item.kind == ObservationKind::ReleaseMembership && matches_release(item, target)
    })?;
    let Some((membership, _)) = membership else {
        assertion.outcome = Outcome::InsufficientEvidence;
        assertion.missing.push(missing(
            "release_membership",
            target,
            "the evaluator cannot determine which pull requests belong to the release",
        ));
        assertion.reasoning.push(step(
            "release_membership_missing",
            "release coverage cannot be established",
            &[],
        ));
        return Ok(assertion);
    };
    let membership_data: ReleaseMembershipData = payload(membership)?;
    assertion.support.push(use_evidence(
        membership,
        "establishes the pull requests included in the release",
    ));
    assertion.validity.through = Some(membership_data.published_at.clone());

    let review = latest_matching(corpus, at, |item| {
        item.kind == ObservationKind::ReviewRecord
            && item.evidence_class == EvidenceClass::ObservedOperation
            && matches_release(item, target)
            && item.subject.qualifier("revision") == Some(membership_data.target_revision.as_str())
    })?;
    let Some((review, _)) = review else {
        assertion.outcome = Outcome::InsufficientEvidence;
        assertion.missing.push(missing(
            "pull_request_review_records",
            target,
            "release membership alone does not establish what happened before merge",
        ));
        assertion.reasoning.push(step(
            "review_records_missing",
            "review operation is not covered for the release",
            &[membership],
        ));
        return Ok(assertion);
    };
    let review_data: PullRequestReviewData = payload(review)?;
    assertion.identity_joins.push(join(
        membership,
        review,
        &[
            ("release", release),
            ("revision", &membership_data.target_revision),
        ],
    ));
    assertion.support.push(use_evidence(
        review,
        "records review events and merge times for release pull requests",
    ));

    let first_merge = evaluate_release_pull_requests(
        corpus,
        target,
        &membership_data,
        review,
        &review_data,
        at,
        &mut assertion,
    )?;
    assertion.validity.from = first_merge.map(format_time).transpose()?;
    assertion.outcome = if !assertion.contradictions.is_empty() {
        Outcome::Contradicted
    } else if !assertion.missing.is_empty() {
        Outcome::InsufficientEvidence
    } else {
        Outcome::Supported
    };
    assertion.limitations.push("policy requirements come from an audit-derived history whose declared coverage contains each merge time; point snapshots are not substituted".into());
    assertion.limitations.push("review counts establish recorded approvals, not review quality or organizational independence".into());
    Ok(assertion)
}

/// evaluate a release supply-chain gate against the exact sbom delta it consumed.
///
/// # Errors
///
/// returns an error when matching evidence has an invalid timestamp or payload.
pub fn evaluate_supply_chain(
    corpus: &Corpus,
    target: &EvaluationTarget,
    at: OffsetDateTime,
) -> Result<DerivedAssertion> {
    let release = release_name(target)?;
    let mut assertion = base_assertion(
        AssertionType::ReleaseSupplyChainPolicy,
        &format!(
            "release {release} introduced no dependency changes forbidden by supply-chain/default"
        ),
        release_subject(target),
        at,
        SUPPLY_CHAIN_VERSION,
        ValidityBasis::HistoricalRelease,
    )?;
    let diff = latest_matching(corpus, at, |item| {
        item.kind == ObservationKind::ChangeSet && matches_release(item, target)
    })?;
    let Some((diff, _)) = diff else {
        assertion.outcome = Outcome::InsufficientEvidence;
        assertion.missing.push(missing(
            "sbom_diff",
            target,
            "the changed dependency set is unknown",
        ));
        assertion.reasoning.push(step(
            "sbom_diff_missing",
            "no release dependency delta was available",
            &[],
        ));
        return Ok(assertion);
    };
    let source = corpus
        .sources
        .iter()
        .find(|source| source.id == diff.provenance.source_id)
        .ok_or_else(|| Error::Invalid(format!("missing source: {}", diff.provenance.source_id)))?;
    let diff_base = diff.subject.qualifier("base_revision");
    let diff_revision = diff.subject.qualifier("revision");
    let exact = matching_supply_gates(corpus, target, diff, source, at, &mut assertion.considered)?;
    if exact.is_empty() {
        assertion.outcome = Outcome::InsufficientEvidence;
        assertion.support.push(use_evidence(
            diff,
            "establishes the release dependency changes, but not whether policy accepted them",
        ));
        assertion.missing.push(missing("matching_supply_chain_gate", target, "a gate result must name the same base revision, target revision, release, and exact SBOM-diff digest"));
        assertion.reasoning.push(step(
            "gate_missing",
            "dependency changes are known but no matching policy decision is available",
            &[diff],
        ));
        return Ok(assertion);
    }
    let gate = select_supply_gate(exact, &mut assertion.considered);
    assertion.identity_joins.push(join(
        diff,
        gate,
        &[
            ("release", release),
            ("base_revision", diff_base.unwrap_or("")),
            ("revision", diff_revision.unwrap_or("")),
            ("sbom_diff_sha256", &source.sha256),
        ],
    ));
    assertion.support.push(use_evidence(
        diff,
        "establishes the dependency changes from the release base to target revision",
    ));
    if gate.status == Some(Status::Pass) {
        assertion.support.push(use_evidence(
            gate,
            "the configured supply-chain policy evaluated this exact SBOM delta and passed",
        ));
        assertion.reasoning.push(step(
            "matching_gate_passed",
            "the gate consumed the exact normalized change source and returned pass",
            &[diff, gate],
        ));
        assertion.outcome = Outcome::Supported;
    } else {
        assertion.contradictions.push(use_evidence(
            gate,
            "an authoritative decision for this exact release delta failed",
        ));
        assertion.reasoning.push(step(
            "matching_gate_failed",
            "the gate consumed the exact normalized change source and returned fail",
            &[diff, gate],
        ));
        assertion.outcome = Outcome::Contradicted;
    }
    assertion.validity.through = Some(gate.observed_at.clone());
    assertion.limitations.push("coverage is limited to dependencies represented in the supplied SBOMs and rules recorded by supply-chain/default".into());
    Ok(assertion)
}

/// evaluate whether the corpus establishes adequate human security review.
///
/// # Errors
///
/// returns an error when a matching observation timestamp is invalid.
pub fn evaluate_adequate_security_review(
    corpus: &Corpus,
    target: &EvaluationTarget,
    at: OffsetDateTime,
) -> Result<DerivedAssertion> {
    let release = release_name(target)?;
    let mut assertion = base_assertion(
        AssertionType::AdequateHumanSecurityReview,
        &format!(
            "all security-relevant changes in release {release} received adequate human security review"
        ),
        release_subject(target),
        at,
        SECURITY_REVIEW_VERSION,
        ValidityBasis::NotEstablished,
    )?;
    for observation in corpus
        .observations
        .iter()
        .filter(|item| matches_release(item, target))
    {
        if parse_timestamp(&observation.observed_at)? > at {
            continue;
        }
        if matches!(
            observation.kind,
            ObservationKind::ReviewRecord | ObservationKind::PolicyCheck
        ) {
            assertion.considered.push(use_evidence(observation, "establishes recorded reviews or automated checks, but not review adequacy or security focus"));
        }
    }
    assertion.missing.push(missing("security_review_scope_and_content", target, "the corpus contains no evidence describing what reviewers examined, which changes were security-relevant, or the criteria for adequate review"));
    assertion.reasoning.push(step("semantic_limit", "review occurrence and automated gate results cannot establish the quality or security focus of human judgement", &[]));
    assertion.limitations.push("adequacy is a judgement requiring declared criteria and evidence about review content; it cannot be inferred from approval counts".into());
    assertion.outcome = Outcome::NotAutomatable;
    Ok(assertion)
}

fn evaluate_release_pull_requests(
    corpus: &Corpus,
    target: &EvaluationTarget,
    membership: &ReleaseMembershipData,
    review: &Observation,
    review_data: &PullRequestReviewData,
    known_at: OffsetDateTime,
    assertion: &mut DerivedAssertion,
) -> Result<Option<OffsetDateTime>> {
    let reviews = review_data
        .pull_requests
        .iter()
        .map(|pull_request| (pull_request.number, pull_request))
        .collect::<BTreeMap<_, _>>();
    let mut used_configurations = BTreeSet::new();
    let mut first_merge = None;
    for number in &membership.pull_requests {
        let Some(pull_request) = reviews.get(number) else {
            assertion.missing.push(MissingEvidence {
                requirement: "pull_request_review_record".into(),
                subject: format!("{}#pull/{number}", target.repository),
                reason: "the release contains this pull request but no review record was collected"
                    .into(),
            });
            continue;
        };
        let merged_at = parse_timestamp(&pull_request.merged_at)?;
        first_merge =
            Some(first_merge.map_or(merged_at, |current: OffsetDateTime| current.min(merged_at)));
        let Some((configuration, required_approvals)) =
            policy_history_at(corpus, target, merged_at, known_at)?
        else {
            assertion.missing.push(MissingEvidence {
                requirement: "complete_branch_policy_history_at_merge".into(),
                subject: format!("{}#pull/{number}", target.repository),
                reason: "the required review count at merge time cannot be established from point snapshots alone".into(),
            });
            continue;
        };
        used_configurations.insert(configuration.id.as_str());
        evaluate_pull_request(
            target,
            pull_request,
            merged_at,
            configuration,
            required_approvals,
            review,
            assertion,
        )?;
    }
    for configuration in corpus
        .observations
        .iter()
        .filter(|item| used_configurations.contains(item.id.as_str()))
    {
        assertion.support.push(use_evidence(
            configuration,
            "establishes configured review count used for one or more release merges",
        ));
    }
    Ok(first_merge)
}

fn evaluate_pull_request(
    target: &EvaluationTarget,
    pull_request: &PullRequestData,
    merged_at: OffsetDateTime,
    configuration: &Observation,
    required_approvals: u64,
    review: &Observation,
    assertion: &mut DerivedAssertion,
) -> Result<()> {
    let number = pull_request.number;
    assertion.identity_joins.push(join(
        configuration,
        review,
        &[
            ("repository", &target.repository),
            ("branch", &target.branch),
        ],
    ));
    let approvals = pull_request
        .approvals
        .iter()
        .filter(|approval| approval.state == "approved" && approval.actor != pull_request.author)
        .filter_map(|approval| {
            parse_timestamp(&approval.submitted_at)
                .ok()
                .filter(|submitted| *submitted <= merged_at)
                .map(|_| approval.actor.as_str())
        })
        .collect::<BTreeSet<_>>();
    let approval_count = u64::try_from(approvals.len())
        .map_err(|_| Error::Invalid("approval count does not fit in u64".into()))?;
    if approval_count < required_approvals {
        assertion.contradictions.push(use_evidence(review, &format!("pull request #{number} had {approval_count} qualifying approval(s), fewer than the configured {required_approvals}")));
    }
    assertion.reasoning.push(step("pull_request_review_count", &format!("pull request #{number} had {approval_count} qualifying approval(s); effective policy history required {required_approvals}"), &[review, configuration]));
    Ok(())
}

fn policy_history_at<'a>(
    corpus: &'a Corpus,
    target: &EvaluationTarget,
    effective_at: OffsetDateTime,
    known_at: OffsetDateTime,
) -> Result<Option<(&'a Observation, u64)>> {
    let history = latest_matching(corpus, known_at, |item| {
        item.kind == ObservationKind::ConfigurationHistory
            && item.evidence_class == EvidenceClass::ConfiguredIntent
            && item.subject.id == target.repository
            && item.subject.qualifier("branch") == Some(target.branch.as_str())
    })?;
    let Some((history, _)) = history else {
        return Ok(None);
    };
    let data: BranchPolicyHistoryData = payload(history)?;
    if effective_at < parse_timestamp(&data.complete_from)?
        || effective_at > parse_timestamp(&data.complete_through)?
    {
        return Ok(None);
    }
    let mut events = data
        .events
        .iter()
        .map(|event| Ok((event, parse_timestamp(&event.effective_at)?)))
        .collect::<Result<Vec<_>>>()?;
    events.retain(|(_, event_at)| *event_at <= effective_at);
    events.sort_by_key(|(event, effective_at)| (*effective_at, &event.event_id));
    Ok(events
        .pop()
        .map(|(event, _)| (history, event.required_approving_review_count)))
}

fn matching_supply_gates<'a>(
    corpus: &'a Corpus,
    target: &EvaluationTarget,
    diff: &Observation,
    source: &crate::model::SourceDocument,
    at: OffsetDateTime,
    considered: &mut Vec<EvidenceUse>,
) -> Result<Vec<(&'a Observation, OffsetDateTime)>> {
    let diff_base = diff.subject.qualifier("base_revision");
    let diff_revision = diff.subject.qualifier("revision");
    let mut exact = Vec::new();
    for gate in corpus.observations.iter().filter(|item| {
        item.claim_key == "supply-chain-gate:supply-chain/default" && matches_release(item, target)
    }) {
        let observed_at = parse_timestamp(&gate.observed_at)?;
        if observed_at > at {
            continue;
        }
        let data: SupplyChainGateData = payload(gate)?;
        if gate.subject.qualifier("base_revision") == diff_base
            && gate.subject.qualifier("revision") == diff_revision
            && Some(data.base_revision.as_str()) == diff_base
            && Some(data.target_revision.as_str()) == diff_revision
            && data.evaluated_sbom_diff_sha256 == source.sha256
        {
            exact.push((gate, observed_at));
        } else {
            considered.push(use_evidence(gate, "gate result was rejected because release revisions or the evaluated SBOM-diff digest did not match"));
        }
    }
    exact.sort_by_key(|(observation, observed_at)| (*observed_at, &observation.id));
    Ok(exact)
}

fn select_supply_gate<'a>(
    mut exact: Vec<(&'a Observation, OffsetDateTime)>,
    considered: &mut Vec<EvidenceUse>,
) -> &'a Observation {
    let selected_index = exact
        .iter()
        .rposition(|(gate, _)| gate.status == Some(Status::Fail))
        .unwrap_or(exact.len() - 1);
    let (gate, _) = exact.remove(selected_index);
    for (other, _) in exact {
        let reason = if other.status == gate.status {
            "duplicate decision for the same evaluator input was not selected"
        } else {
            "conflicting decision for the same evaluator input was preserved; collection time alone does not resolve it"
        };
        considered.push(use_evidence(other, reason));
    }
    gate
}

fn collect_mutations<'a>(
    corpus: &'a Corpus,
    target: &EvaluationTarget,
    run_ids: &BTreeSet<String>,
    assertion: &mut DerivedAssertion,
) -> Result<Vec<(&'a Observation, MutationEventData)>> {
    let interval_from = parse_timestamp(&target.from)?;
    let interval_until = parse_timestamp(&target.until)?;
    let mut merges = Vec::new();
    for observation in corpus.observations.iter().filter(|item| {
        item.kind == ObservationKind::MutationHistory
            && item.subject.id == target.repository
            && item.subject.qualifier("branch") == Some(target.branch.as_str())
            && item
                .collection_run_id
                .as_ref()
                .is_some_and(|id| run_ids.contains(id))
    }) {
        let data: MutationHistoryData = payload(observation)?;
        for event in data.events {
            let occurred_at = parse_timestamp(&event.occurred_at)?;
            if occurred_at < interval_from || occurred_at >= interval_until {
                continue;
            }
            match event.kind.as_str() {
                "direct_push" => {
                    assertion.contradictions.push(use_evidence(
                        observation,
                        &format!(
                            "mutation event {} records direct push of {}",
                            event.event_id, event.commit
                        ),
                    ));
                    assertion.reasoning.push(step(
                        "direct_push_observed",
                        "an authoritative mutation observation is a concrete counterexample",
                        &[observation],
                    ));
                }
                "pull_request_merge" => merges.push((observation, event)),
                _ => assertion.considered.push(use_evidence(
                    observation,
                    "mutation kind was preserved but is not interpreted by this evaluator",
                )),
            }
        }
    }
    Ok(merges)
}

fn collect_reviews<'a>(
    corpus: &'a Corpus,
    target: &EvaluationTarget,
    run_ids: &BTreeSet<String>,
) -> Result<BTreeMap<u64, (&'a Observation, PullRequestData)>> {
    let mut reviews = BTreeMap::new();
    for observation in corpus.observations.iter().filter(|item| {
        item.kind == ObservationKind::ReviewRecord
            && item.subject.qualifier("repository") == Some(target.repository.as_str())
            && item
                .collection_run_id
                .as_ref()
                .is_some_and(|id| run_ids.contains(id))
    }) {
        let data: PullRequestReviewData = payload(observation)?;
        for pull_request in data.pull_requests {
            reviews.insert(pull_request.number, (observation, pull_request));
        }
    }
    Ok(reviews)
}

fn evaluate_mutation_reviews(
    target: &EvaluationTarget,
    merges: Vec<(&Observation, MutationEventData)>,
    reviews: &BTreeMap<u64, (&Observation, PullRequestData)>,
    assertion: &mut DerivedAssertion,
) -> Result<()> {
    for (mutation, event) in merges {
        let Some(number) = event.pull_request else {
            assertion.missing.push(MissingEvidence {
                requirement: "mutation_to_pull_request_identity".into(),
                subject: event.commit,
                reason: "merge mutation did not identify its pull request".into(),
            });
            continue;
        };
        let Some((review_observation, pull_request)) = reviews.get(&number) else {
            assertion.missing.push(MissingEvidence {
                requirement: "pull_request_review_record".into(),
                subject: format!("{}#pull/{number}", target.repository),
                reason: "a pull-request merge was observed but no authoritative review record matched it".into(),
            });
            continue;
        };
        let occurred_at = parse_timestamp(&event.occurred_at)?;
        let reviewed = pull_request.approvals.iter().any(|approval| {
            approval.state == "approved"
                && approval.actor != pull_request.author
                && parse_timestamp(&approval.submitted_at)
                    .is_ok_and(|submitted| submitted <= occurred_at)
        });
        assertion.identity_joins.push(join(
            mutation,
            review_observation,
            &[
                ("repository", &target.repository),
                ("pull_request", &number.to_string()),
                ("commit", &event.commit),
            ],
        ));
        if reviewed {
            assertion.support.push(use_evidence(
                mutation,
                &format!(
                    "mutation {} was pull-request merge #{number}",
                    event.event_id
                ),
            ));
            assertion.support.push(use_evidence(
                review_observation,
                &format!("pull request #{number} had an independent approval before integration"),
            ));
        } else {
            assertion.contradictions.push(use_evidence(
                review_observation,
                &format!("pull request #{number} had no independent approval before integration"),
            ));
        }
    }
    Ok(())
}

fn coverage_requirement(
    target: &EvaluationTarget,
    proposition: Proposition,
) -> CoverageRequirement {
    CoverageRequirement {
        proposition,
        repository: target.repository.clone(),
        branch: Some(target.branch.clone()),
        interval: TimeRange {
            from: target.from.clone(),
            until: target.until.clone(),
        },
    }
}

fn authoritative_runs(decision: &CoverageDecision) -> BTreeSet<String> {
    decision
        .collection_runs
        .iter()
        .filter(|run| {
            matches!(
                run.disposition,
                RunDisposition::Used
                    | RunDisposition::RetentionLimited
                    | RunDisposition::PaginationIncomplete
                    | RunDisposition::Interrupted
            )
        })
        .map(|run| run.collection_run_id.clone())
        .collect()
}

fn add_coverage_gap(assertion: &mut DerivedAssertion, decision: &CoverageDecision) {
    if decision.outcome == CoverageOutcome::Complete {
        return;
    }
    let reasons = if decision.collection_runs.is_empty() {
        "no collection attempt matched this population and scope".into()
    } else {
        decision
            .collection_runs
            .iter()
            .filter(|run| run.disposition != RunDisposition::Used)
            .map(|run| format!("{}: {}", run.collection_run_id, run.reason))
            .collect::<Vec<_>>()
            .join("; ")
    };
    assertion.missing.push(MissingEvidence {
        requirement: format!(
            "complete_authoritative_{}_coverage",
            proposition_name(decision.requirement.proposition)
        ),
        subject: format!(
            "{}#{} {} .. {}",
            decision.requirement.repository,
            decision.requirement.branch.as_deref().unwrap_or("*"),
            decision.requirement.interval.from,
            decision.requirement.interval.until
        ),
        reason: if decision.uncovered_intervals.is_empty() {
            reasons
        } else {
            let intervals = decision
                .uncovered_intervals
                .iter()
                .map(|interval| format!("{} to {}", interval.from, interval.until))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{reasons}; uncovered intervals: {intervals}")
        },
    });
}

const fn proposition_name(proposition: Proposition) -> &'static str {
    match proposition {
        Proposition::PullRequestPopulation => "pull_request_population",
        Proposition::PullRequestReviews => "pull_request_reviews",
        Proposition::RepositoryMutations => "repository_mutations",
        Proposition::CommitAncestry => "commit_ancestry",
        Proposition::BranchConfiguration => "branch_configuration",
        Proposition::RevisionChecks => "revision_checks",
        Proposition::SupplyChainPolicyDecision => "supply_chain_policy_decision",
        Proposition::DeclaredDependencies => "declared_dependencies",
    }
}

fn branch_configurations<'a>(
    corpus: &'a Corpus,
    target: &EvaluationTarget,
    at: OffsetDateTime,
) -> Result<Vec<(&'a Observation, OffsetDateTime)>> {
    let mut matches = corpus
        .observations
        .iter()
        .filter(|item| {
            is_github_branch_protection(item, &target.branch)
                && item.kind == ObservationKind::ConfigurationSnapshot
                && item.evidence_class == EvidenceClass::ConfiguredIntent
                && item.subject.id == target.repository
                && item.subject.qualifier("branch") == Some(target.branch.as_str())
                && observation_authoritative(corpus, item, Proposition::BranchConfiguration)
        })
        .map(|item| Ok((item, parse_timestamp(&item.observed_at)?)))
        .collect::<Result<Vec<_>>>()?;
    matches.retain(|(_, observed_at)| *observed_at <= at);
    matches.sort_by_key(|(observation, observed_at)| (*observed_at, &observation.id));
    Ok(matches)
}

fn is_github_branch_protection(observation: &Observation, branch: &str) -> bool {
    observation.claim_key == "github:branch-protection"
        || observation
            .claim_key
            .strip_prefix("github:branch-protection:")
            == Some(branch)
}

fn observation_authoritative(
    corpus: &Corpus,
    observation: &Observation,
    proposition: Proposition,
) -> bool {
    observation.collection_run_id.as_ref().is_none_or(|run_id| {
        corpus
            .collections
            .iter()
            .find(|run| &run.id == run_id)
            .is_some_and(|run| run.authority.contains(&proposition))
    })
}

fn latest_matching<F>(
    corpus: &Corpus,
    at: OffsetDateTime,
    predicate: F,
) -> Result<Option<(&Observation, OffsetDateTime)>>
where
    F: Fn(&Observation) -> bool,
{
    let mut matches = corpus
        .observations
        .iter()
        .filter(|item| predicate(item))
        .map(|item| Ok((item, parse_timestamp(&item.observed_at)?)))
        .collect::<Result<Vec<_>>>()?;
    matches.retain(|(_, observed_at)| *observed_at <= at);
    matches.sort_by_key(|(observation, observed_at)| (*observed_at, &observation.id));
    Ok(matches.pop())
}

fn matches_release(observation: &Observation, target: &EvaluationTarget) -> bool {
    observation.subject.qualifier("repository") == Some(target.repository.as_str())
        && observation.subject.qualifier("release") == target.release.as_deref()
}

fn payload<T: for<'de> Deserialize<'de>>(observation: &Observation) -> Result<T> {
    serde_json::from_value(observation.data.clone()).map_err(|error| {
        Error::Invalid(format!(
            "{} has invalid typed payload: {error}",
            observation.id
        ))
    })
}

fn base_assertion(
    assertion_type: AssertionType,
    claim: &str,
    subject: AssertionSubject,
    at: OffsetDateTime,
    version: &str,
    basis: ValidityBasis,
) -> Result<DerivedAssertion> {
    let stable = serde_json::to_vec(&(&assertion_type, &subject)).map_err(Error::Serialize)?;
    Ok(DerivedAssertion {
        id: format!("asrt_{}", &hex_digest(&stable)[..20]),
        assertion_type,
        claim: claim.into(),
        subject,
        outcome: Outcome::InsufficientEvidence,
        evaluated_at: format_time(at)?,
        validity: Validity {
            basis,
            at: None,
            from: None,
            through: None,
            fresh_until: None,
        },
        derivation: Derivation {
            evaluator: "divinate".into(),
            version: version.into(),
            pack_invocation_id: None,
        },
        support: vec![],
        contradictions: vec![],
        considered: vec![],
        missing: vec![],
        identity_joins: vec![],
        reasoning: vec![],
        limitations: vec![],
        coverage: vec![],
    })
}

fn branch_subject(target: &EvaluationTarget) -> AssertionSubject {
    AssertionSubject {
        repository: target.repository.clone(),
        branch: Some(target.branch.clone()),
        release: None,
        from: None,
        until: None,
    }
}

fn interval_branch_subject(target: &EvaluationTarget) -> AssertionSubject {
    AssertionSubject {
        repository: target.repository.clone(),
        branch: Some(target.branch.clone()),
        release: None,
        from: Some(target.from.clone()),
        until: Some(target.until.clone()),
    }
}

fn release_subject(target: &EvaluationTarget) -> AssertionSubject {
    AssertionSubject {
        repository: target.repository.clone(),
        branch: None,
        release: target.release.clone(),
        from: None,
        until: None,
    }
}

fn use_evidence(observation: &Observation, reason: &str) -> EvidenceUse {
    EvidenceUse {
        observation_id: observation.id.clone(),
        source_id: observation.provenance.source_id.clone(),
        reason: reason.into(),
    }
}

fn missing(requirement: &str, target: &EvaluationTarget, reason: &str) -> MissingEvidence {
    MissingEvidence {
        requirement: requirement.into(),
        subject: target.release.as_ref().map_or_else(
            || target.repository.clone(),
            |release| format!("{}:{release}", target.repository),
        ),
        reason: reason.into(),
    }
}

fn release_name(target: &EvaluationTarget) -> Result<&str> {
    target
        .release
        .as_deref()
        .ok_or_else(|| Error::Invalid("release-scoped evaluation requires --release".into()))
}

fn step(code: &str, conclusion: &str, evidence: &[&Observation]) -> ReasonStep {
    ReasonStep {
        code: code.into(),
        conclusion: conclusion.into(),
        evidence_ids: evidence.iter().map(|item| item.id.clone()).collect(),
    }
}

fn join(left: &Observation, right: &Observation, fields: &[(&str, &str)]) -> IdentityJoin {
    IdentityJoin {
        left_observation_id: left.id.clone(),
        right_observation_id: right.id.clone(),
        fields: fields
            .iter()
            .map(|(field, value)| (field.to_string(), (*value).to_string()))
            .collect(),
    }
}

fn format_time(value: OffsetDateTime) -> Result<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| Error::Invalid(format!("cannot format timestamp: {error}")))
}

#[derive(Deserialize)]
struct BranchProtectionData {
    required_approving_review_count: u64,
    requires_last_push_approval: bool,
}

#[derive(Deserialize)]
struct ReleaseMembershipData {
    published_at: String,
    pull_requests: Vec<u64>,
    target_revision: String,
}

#[derive(Deserialize)]
struct PullRequestReviewData {
    pull_requests: Vec<PullRequestData>,
}

#[derive(Deserialize)]
struct PullRequestData {
    number: u64,
    author: String,
    merged_at: String,
    approvals: Vec<ApprovalData>,
}

#[derive(Deserialize)]
struct MutationHistoryData {
    events: Vec<MutationEventData>,
}

#[derive(Deserialize)]
struct MutationEventData {
    event_id: String,
    kind: String,
    occurred_at: String,
    commit: String,
    pull_request: Option<u64>,
}

#[derive(Deserialize)]
struct ApprovalData {
    actor: String,
    submitted_at: String,
    state: String,
}

#[derive(Deserialize)]
struct SupplyChainGateData {
    base_revision: String,
    evaluated_sbom_diff_sha256: String,
    target_revision: String,
}

#[derive(Deserialize)]
struct BranchPolicyHistoryData {
    complete_from: String,
    complete_through: String,
    events: Vec<BranchPolicyEventData>,
}

#[derive(Deserialize)]
struct BranchPolicyEventData {
    event_id: String,
    effective_at: String,
    required_approving_review_count: u64,
}
