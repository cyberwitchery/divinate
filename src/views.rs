//! downstream views over saved assertions.
//!
//! [`isms_update`] compares structured assertion state. [`dd_response`] selects
//! saved claims for due diligence. both report reuse and acquire no evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Serialize;

use crate::assertions::{AssertionType, DerivedAssertion, Outcome};
use crate::coverage::CoverageOutcome;
use crate::model::Proposition;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one claim whose outcome differs between two evaluations.
pub struct AssertionChange {
    pub assertion_type: AssertionType,
    pub claim: String,
    pub previous: String,
    pub current: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// what a downstream task reused versus what it had to acquire or derive.
pub struct ReuseAccounting {
    pub evidence_already_present: Vec<String>,
    pub evidence_newly_acquired: Vec<String>,
    pub assertions_reused: Vec<String>,
    pub assertions_reevaluated: Vec<String>,
    pub new_derivations: Vec<String>,
    pub new_view_logic: Vec<String>,
    pub manual_interpretation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// a structural comparison of two evaluations for a technical-controls review.
pub struct IsmsUpdate {
    pub current: Vec<DerivedAssertion>,
    pub changes: Vec<AssertionChange>,
    pub new_gaps: Vec<String>,
    pub coverage_regressions: Vec<String>,
    pub reuse: ReuseAccounting,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// saved claims selected to answer a due-diligence request.
pub struct DdResponse {
    pub claims: Vec<DerivedAssertion>,
    pub reuse: ReuseAccounting,
}

#[must_use]
/// compare assertion and coverage state across two evaluations.
pub fn isms_update(previous: &[DerivedAssertion], current: &[DerivedAssertion]) -> IsmsUpdate {
    let previous = review_assertions(previous);
    let current = review_assertions(current);
    let previous_by_type = previous
        .iter()
        .map(|assertion| (assertion.id.clone(), assertion))
        .collect::<BTreeMap<_, _>>();
    let current_by_type = current
        .iter()
        .map(|assertion| (assertion.id.clone(), assertion))
        .collect::<BTreeMap<_, _>>();
    let changes = current_by_type
        .iter()
        .filter_map(|(id, current)| {
            let previous = previous_by_type.get(id)?;
            (previous.outcome != current.outcome).then(|| AssertionChange {
                assertion_type: current.assertion_type.clone(),
                claim: current.claim.clone(),
                previous: outcome_name(previous.outcome).into(),
                current: outcome_name(current.outcome).into(),
                reason: current.reasoning.last().map_or_else(
                    || "no structured reason recorded".into(),
                    |step| step.conclusion.clone(),
                ),
            })
        })
        .collect::<Vec<_>>();
    let previous_gaps = gaps(&previous);
    let current_gaps = gaps(&current);
    let new_gaps = current_gaps
        .iter()
        .filter(|(identity, _)| !previous_gaps.contains_key(*identity))
        .map(|(_, description)| description.clone())
        .collect();
    let coverage_regressions = changes
        .iter()
        .filter(|change| {
            change.current == "insufficient evidence" && change.previous != "insufficient evidence"
        })
        .map(|change| change.claim.clone())
        .collect();
    let previous_sources = source_ids(&previous);
    let current_sources = source_ids(&current);
    IsmsUpdate {
        current: current.clone(),
        changes,
        new_gaps,
        coverage_regressions,
        reuse: ReuseAccounting {
            evidence_already_present: previous_sources.iter().cloned().collect(),
            evidence_newly_acquired: current_sources
                .difference(&previous_sources)
                .cloned()
                .collect(),
            assertions_reused: vec![],
            assertions_reevaluated: current
                .iter()
                .map(|assertion| assertion.assertion_type.as_str().into())
                .collect(),
            new_derivations: vec![],
            new_view_logic: vec!["structured assertion change view".into()],
            manual_interpretation: vec![
                "decide whether changed controls or observability gaps require action".into(),
            ],
        },
    }
}

fn review_assertions(assertions: &[DerivedAssertion]) -> Vec<DerivedAssertion> {
    let selected = [
        AssertionType::ConfiguredIndependentReview,
        AssertionType::EveryMainChangeReviewed,
        AssertionType::DependencyChangeVisibility,
        AssertionType::ReleaseSupplyChainPolicy,
        AssertionType::AdequateHumanSecurityReview,
    ];
    let mut result = selected
        .iter()
        .filter_map(|kind| {
            assertions
                .iter()
                .find(|assertion| assertion.assertion_type == *kind)
                .cloned()
        })
        .collect::<Vec<_>>();
    result.extend(
        assertions
            .iter()
            .filter(|assertion| matches!(assertion.assertion_type, AssertionType::External(_)))
            .cloned(),
    );
    result
}

#[must_use]
/// select saved claims for a due-diligence response.
pub fn dd_response(assertions: &[DerivedAssertion]) -> DdResponse {
    let selected = [
        AssertionType::ConfiguredIndependentReview,
        AssertionType::DependencyChangeVisibility,
        AssertionType::ReleaseSupplyChainPolicy,
        AssertionType::EveryMainChangeReviewed,
    ];
    let mut claims = selected
        .iter()
        .filter_map(|kind| {
            assertions
                .iter()
                .find(|assertion| assertion.assertion_type == *kind)
                .cloned()
        })
        .collect::<Vec<_>>();
    claims.extend(
        assertions
            .iter()
            .filter(|assertion| matches!(assertion.assertion_type, AssertionType::External(_)))
            .cloned(),
    );
    DdResponse {
        reuse: ReuseAccounting {
            evidence_already_present: source_ids(&claims).into_iter().collect(),
            evidence_newly_acquired: vec![],
            assertions_reused: claims
                .iter()
                .map(|assertion| assertion.id.clone())
                .collect(),
            assertions_reevaluated: vec![],
            new_derivations: vec![],
            new_view_logic: vec!["dd evidence-request selection and rendering".into()],
            manual_interpretation: vec![
                "judge whether the selected interval and supply-chain rule are adequate".into(),
            ],
        },
        claims,
    }
}

#[must_use]
/// render a technical-controls update as markdown.
pub fn render_isms(update: &IsmsUpdate) -> String {
    let mut out = String::from("# technical controls update\n\n## current state\n\n");
    for assertion in &update.current {
        writeln!(
            out,
            "- **{}**: {}",
            outcome_name(assertion.outcome),
            assertion.claim
        )
        .unwrap();
        if !assertion.support.is_empty() {
            writeln!(
                out,
                "  - supporting observations: {}",
                assertion.support.len()
            )
            .unwrap();
        }
    }
    out.push_str("\n## changed since last review\n\n");
    if update.changes.is_empty() {
        out.push_str("- no assertion state changed\n");
    }
    for change in &update.changes {
        writeln!(
            out,
            "- {}: **{} → {}**",
            change.claim, change.previous, change.current
        )
        .unwrap();
        writeln!(out, "  - {}", change.reason).unwrap();
    }
    render_strings(&mut out, "new evidence gaps", &update.new_gaps);
    render_strings(
        &mut out,
        "authority or coverage regressions",
        &update.coverage_regressions,
    );
    out
}

#[must_use]
/// render a due-diligence response as markdown.
pub fn render_dd(response: &DdResponse) -> String {
    let mut out = String::from("# technical evidence response\n\n");
    for assertion in &response.claims {
        writeln!(out, "## {}\n", assertion.claim).unwrap();
        writeln!(out, "result: **{}**\n", outcome_name(assertion.outcome)).unwrap();
        for evidence in &assertion.support {
            writeln!(
                out,
                "- evidence: {} (`{}`)",
                evidence.reason, evidence.observation_id
            )
            .unwrap();
        }
        if !assertion.support.is_empty() {
            writeln!(
                out,
                "- provenance: `divinate provenance --evaluation <label> {}`",
                assertion.id
            )
            .unwrap();
        }
        render_missing_gaps(&mut out, assertion);
        for limitation in &assertion.limitations {
            writeln!(out, "- limitation: {limitation}").unwrap();
        }
        for join in &assertion.identity_joins {
            writeln!(
                out,
                "- identity join: `{}` and `{}` match on {}",
                join.left_observation_id,
                join.right_observation_id,
                join.fields.keys().cloned().collect::<Vec<_>>().join(", ")
            )
            .unwrap();
        }
        for coverage in &assertion.coverage {
            writeln!(
                out,
                "- coverage `{}`: {}",
                proposition_name(coverage.requirement.proposition),
                coverage_outcome_name(coverage.outcome)
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }
    out
}

fn render_missing_gaps(out: &mut String, assertion: &DerivedAssertion) {
    let mut gaps = BTreeMap::<(String, String), BTreeSet<String>>::new();
    for gap in &assertion.missing {
        gaps.entry((gap.reason.clone(), gap.subject.clone()))
            .or_default()
            .insert(gap.requirement.clone());
    }
    for ((reason, _subject), requirements) in gaps {
        writeln!(out, "- gap: {reason}").unwrap();
        let coverage = requirements
            .iter()
            .filter_map(|requirement| {
                requirement
                    .strip_prefix("complete_authoritative_")
                    .and_then(|value| value.strip_suffix("_coverage"))
                    .map(human_name)
            })
            .collect::<Vec<_>>();
        if !coverage.is_empty() {
            writeln!(out, "  - missing coverage: {}", coverage.join(", ")).unwrap();
        }
    }
}

fn human_name(value: &str) -> String {
    value.replace('_', " ")
}

fn render_strings(out: &mut String, heading: &str, values: &[String]) {
    writeln!(out, "\n## {heading}\n").unwrap();
    if values.is_empty() {
        out.push_str("- none\n");
    } else {
        for value in values {
            writeln!(
                out,
                "- {}",
                value
                    .split_once(": ")
                    .map_or(value.as_str(), |(_, reason)| reason)
            )
            .unwrap();
        }
    }
}

fn gaps(assertions: &[DerivedAssertion]) -> BTreeMap<String, String> {
    assertions
        .iter()
        .flat_map(|assertion| {
            assertion.missing.iter().map(|gap| {
                (
                    format!(
                        "{}:{}:{}:{}:{}",
                        assertion.assertion_type.as_str(),
                        assertion.subject.repository,
                        assertion.subject.branch.as_deref().unwrap_or_default(),
                        assertion.subject.release.as_deref().unwrap_or_default(),
                        gap.requirement
                    ),
                    format!("{}: {}", gap.requirement, gap.reason),
                )
            })
        })
        .collect()
}

fn source_ids(assertions: &[DerivedAssertion]) -> BTreeSet<String> {
    assertions
        .iter()
        .flat_map(|assertion| assertion.support.iter().chain(&assertion.contradictions))
        .map(|evidence| evidence.source_id.clone())
        .collect()
}

const fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Supported => "supported",
        Outcome::Contradicted => "contradicted",
        Outcome::InsufficientEvidence => "insufficient evidence",
        Outcome::Stale => "stale",
        Outcome::NotAutomatable => "not automatable",
    }
}

const fn proposition_name(proposition: Proposition) -> &'static str {
    match proposition {
        Proposition::PullRequestPopulation => "pull request population",
        Proposition::PullRequestReviews => "pull-request reviews",
        Proposition::RepositoryMutations => "repository mutations",
        Proposition::CommitAncestry => "commit ancestry",
        Proposition::BranchConfiguration => "branch configuration",
        Proposition::RevisionChecks => "revision checks",
        Proposition::BuildValidationResults => "build validation results",
        Proposition::SupplyChainPolicyDecision => "supply-chain policy decision",
        Proposition::DeclaredDependencies => "declared dependencies",
    }
}

const fn coverage_outcome_name(outcome: CoverageOutcome) -> &'static str {
    match outcome {
        CoverageOutcome::Complete => "complete",
        CoverageOutcome::Incomplete => "incomplete",
    }
}
