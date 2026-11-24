//! downstream views over saved assertions.
//!
//! [`isms_update`] compares structured assertion state. it reports reuse and
//! acquires no evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Serialize;

use crate::assertions::{AssertionType, DerivedAssertion, Outcome};

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

#[must_use]
/// compare assertion and coverage state across two evaluations.
pub fn isms_update(previous: &[DerivedAssertion], current: &[DerivedAssertion]) -> IsmsUpdate {
    let previous = review_assertions(previous);
    let current = review_assertions(current);
    let previous_by_type = previous
        .iter()
        .map(|assertion| (review_key(assertion), assertion))
        .collect::<BTreeMap<_, _>>();
    let current_by_type = current
        .iter()
        .map(|assertion| (review_key(assertion), assertion))
        .collect::<BTreeMap<_, _>>();
    let changed_claims = current_by_type
        .iter()
        .filter_map(|(id, current)| {
            let previous = previous_by_type.get(id)?;
            (previous.outcome != current.outcome).then_some((*previous, *current))
        })
        .collect::<Vec<_>>();
    let changes = changed_claims
        .iter()
        .map(|(previous, current)| AssertionChange {
            assertion_type: current.assertion_type.clone(),
            claim: current.claim.clone(),
            previous: previous.outcome.to_string(),
            current: current.outcome.to_string(),
            reason: current.reasoning.last().map_or_else(
                || "no structured reason recorded".into(),
                |step| step.conclusion.clone(),
            ),
        })
        .collect();
    let previous_gaps = gaps(&previous);
    let current_gaps = gaps(&current);
    let new_gaps = current_gaps
        .iter()
        .filter(|(identity, _)| !previous_gaps.contains_key(*identity))
        .map(|(_, description)| description.clone())
        .collect();
    let coverage_regressions = changed_claims
        .iter()
        .filter(|(_, current)| current.outcome == Outcome::InsufficientEvidence)
        .map(|(_, current)| current.claim.clone())
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

type ReviewKey = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// the same claim across two evaluations: its type and subject without the interval
/// end, which advances with every collection.
fn review_key(assertion: &DerivedAssertion) -> ReviewKey {
    (
        assertion.assertion_type.as_str().into(),
        assertion.subject.repository.clone(),
        assertion.subject.branch.clone(),
        assertion.subject.release.clone(),
        assertion.subject.from.clone(),
    )
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
/// render a technical-controls update as markdown.
pub fn render_isms(update: &IsmsUpdate) -> String {
    let mut out = String::from("# technical controls update\n\n## current state\n\n");
    for assertion in &update.current {
        writeln!(out, "- **{}**: {}", assertion.outcome, assertion.claim).unwrap();
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
    render_strings(
        &mut out,
        "new evidence gaps",
        update.new_gaps.iter().map(|gap| {
            gap.split_once(": ")
                .map_or(gap.as_str(), |(_requirement, reason)| reason)
        }),
    );
    render_strings(
        &mut out,
        "authority or coverage regressions",
        update.coverage_regressions.iter().map(String::as_str),
    );
    out
}

fn render_strings<'a>(out: &mut String, heading: &str, values: impl Iterator<Item = &'a str>) {
    writeln!(out, "\n## {heading}\n").unwrap();
    let mut values = values.peekable();
    if values.peek().is_none() {
        out.push_str("- none\n");
    }
    for value in values {
        writeln!(out, "- {value}").unwrap();
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
