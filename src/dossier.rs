//! technical-controls dossier construction and rendering.
//!
//! [`build_with_registry`] projects assertions, provenance, coverage, gaps, and
//! limitations into a portable view. assertion ids and evaluator versions retain
//! the link to the source derivations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Serialize;
use time::OffsetDateTime;

use crate::acquisition::{self, AcquisitionTranscript, ContractRegistry, ContractStatus};
use crate::assertions::{AssertionType, DerivedAssertion, EvaluationTarget, EvidenceUse, Outcome};
use crate::coverage::{CoverageOutcome, RunDisposition};
use crate::error::{Error, Result};
use crate::model::{
    CollectionOutcome, CollectionRun, Corpus, Observation, ObservationKind, Proposition,
};
use crate::provenance;
use crate::{hex_digest, source_bytes};

/// the dossier format version this build writes.
pub const DOSSIER_SCHEMA_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// a portable technical-controls artifact, addressed by the digest of its contents.
pub struct Dossier {
    pub id: String,
    pub schema_version: String,
    pub contents: DossierContents,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// the projected view: evidence summaries, coverage, history, and per-control entries.
pub struct DossierContents {
    pub repository: String,
    pub evaluated_at: String,
    pub interval: DossierInterval,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    pub corpus_sha256: String,
    pub evidence_sources: Vec<EvidenceSourceSummary>,
    pub acquisitions: Vec<AcquisitionSummary>,
    pub collections: Vec<CollectionSummary>,
    pub historical_context: Vec<HistoricalContext>,
    pub controls: Vec<ControlEntry>,
    pub reproduction: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// the interval the dossier covers.
pub struct DossierInterval {
    pub from: String,
    pub until: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one producer and how many observations it contributed.
pub struct EvidenceSourceSummary {
    pub producer: String,
    pub version: String,
    pub collector: String,
    pub observations: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one acquisition's integrity, contract status, enumeration, and resulting authority.
pub struct AcquisitionSummary {
    pub transcript_id: String,
    pub contract: String,
    pub contract_status: String,
    pub subject: String,
    pub proposition: String,
    pub requested_scope: String,
    pub integrity: String,
    pub enumeration: String,
    pub authority: Vec<String>,
    pub pages: u64,
    pub items: u64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one collection attempt, its outcome, and its declared authority.
pub struct CollectionSummary {
    pub id: String,
    pub acquisition_transcript_ids: Vec<String>,
    pub subject: String,
    pub proposition: String,
    pub requested_scope: String,
    pub outcome: String,
    pub authority: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one dated observation rendered as context, including why it may not be comparable.
pub struct HistoricalContext {
    pub observed_at: String,
    pub subject: String,
    pub summary: String,
    pub observation_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one control: its state, the reasoning, its evidence, and its gaps.
///
/// `manual_work_without_dossier` records what producing this claim by hand costs.
pub struct ControlEntry {
    pub assertion_id: String,
    pub title: String,
    pub semantics: String,
    pub state: String,
    pub why: Vec<String>,
    pub evidence: Vec<DossierEvidence>,
    pub coverage: Vec<DossierCoverage>,
    pub contradictions: Vec<DossierEvidence>,
    pub missing: Vec<DossierGap>,
    pub identity_joins: Vec<String>,
    pub limitations: Vec<String>,
    pub evaluator: String,
    pub manual_work_without_dossier: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one piece of evidence with its digest and a command to recover it.
pub struct DossierEvidence {
    pub observation_id: String,
    pub source_id: String,
    pub source_sha256: String,
    pub collection_run_id: Option<String>,
    pub reason: String,
    pub drill_down: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// a coverage decision rendered for a reader, including uncovered intervals.
pub struct DossierCoverage {
    pub proposition: String,
    pub outcome: String,
    pub interval: String,
    pub collection_runs: Vec<String>,
    pub uncovered: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one specific missing requirement.
pub struct DossierGap {
    pub requirement: String,
    pub subject: String,
    pub reason: String,
}

/// build the machine-readable dossier view from assertions and their corpus.
///
/// # Errors
///
/// returns an error when evidence references do not resolve or serialization fails.
pub fn build(
    corpus: &Corpus,
    assertions: &[DerivedAssertion],
    acquisitions: &[AcquisitionTranscript],
    target: &EvaluationTarget,
    evaluated_at: OffsetDateTime,
) -> Result<Dossier> {
    build_with_registry(
        corpus,
        assertions,
        acquisitions,
        &ContractRegistry::default(),
        target,
        evaluated_at,
    )
}

/// build a dossier under an explicit current collector-contract registry.
///
/// # Errors
///
/// returns an error when provenance links do not resolve or serialization fails.
pub fn build_with_registry(
    corpus: &Corpus,
    assertions: &[DerivedAssertion],
    acquisitions: &[AcquisitionTranscript],
    registry: &ContractRegistry,
    target: &EvaluationTarget,
    evaluated_at: OffsetDateTime,
) -> Result<Dossier> {
    provenance::verify_collection_links(corpus, acquisitions, registry)?;
    let mut selected = vec![
        AssertionType::ConfiguredIndependentReview,
        AssertionType::EveryMainChangeReviewed,
    ];
    if target.release.is_some() {
        selected.extend([
            AssertionType::DependencyChangeVisibility,
            AssertionType::ReleaseSupplyChainPolicy,
            AssertionType::AdequateHumanSecurityReview,
        ]);
    }
    let mut controls = selected
        .iter()
        .map(|kind| {
            assertions
                .iter()
                .find(|assertion| assertion.assertion_type == *kind)
                .ok_or_else(|| Error::Invalid(format!("missing dossier assertion: {kind:?}")))
                .and_then(|assertion| control_entry(corpus, assertion))
        })
        .collect::<Result<Vec<_>>>()?;
    controls.extend(
        assertions
            .iter()
            .filter(|assertion| matches!(assertion.assertion_type, AssertionType::External(_)))
            .map(|assertion| control_entry(corpus, assertion))
            .collect::<Result<Vec<_>>>()?,
    );
    let evaluated_at = evaluated_at
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| Error::Invalid(format!("cannot format timestamp: {error}")))?;
    let corpus_bytes = serde_json::to_vec(corpus).map_err(Error::Serialize)?;
    let contents = DossierContents {
        repository: target.repository.clone(),
        evaluated_at: evaluated_at.clone(),
        interval: DossierInterval {
            from: target.from.clone(),
            until: target.until.clone(),
        },
        release: target.release.clone(),
        corpus_sha256: hex_digest(&corpus_bytes),
        evidence_sources: source_summaries(corpus),
        acquisitions: acquisitions
            .iter()
            .map(|transcript| acquisition_summary(transcript, registry))
            .collect(),
        collections: corpus.collections.iter().map(collection_summary).collect(),
        historical_context: historical_context(corpus),
        controls,
        reproduction: vec![
            "divinate verify --state .evidence".into(),
            "divinate provenance --state .evidence --evaluation <label> <assertion-id>".into(),
        ],
    };
    let bytes = serde_json::to_vec(&contents).map_err(Error::Serialize)?;
    Ok(Dossier {
        id: format!("dossier_{}", &hex_digest(&bytes)[..20]),
        schema_version: DOSSIER_SCHEMA_VERSION.into(),
        contents,
    })
}

/// render a concise markdown view from the machine-readable dossier.
#[must_use]
pub fn render_markdown(dossier: &Dossier) -> String {
    let mut out = String::new();
    writeln!(out, "# technical controls dossier\n").unwrap();
    writeln!(out, "repository: `{}`  ", dossier.contents.repository).unwrap();
    writeln!(out, "evaluated: `{}`  ", dossier.contents.evaluated_at).unwrap();
    writeln!(
        out,
        "interval: `{}` to `{}`  ",
        dossier.contents.interval.from, dossier.contents.interval.until
    )
    .unwrap();
    if let Some(release) = &dossier.contents.release {
        writeln!(out, "release: `{release}`  ").unwrap();
    }
    writeln!(out).unwrap();
    render_overview(&mut out, dossier);
    render_history(&mut out, &dossier.contents.historical_context);
    for control in &dossier.contents.controls {
        render_control(&mut out, control);
    }
    writeln!(out, "## verify and inspect\n").unwrap();
    for command in &dossier.contents.reproduction {
        writeln!(out, "- `{command}`").unwrap();
    }
    out
}

fn control_entry(corpus: &Corpus, assertion: &DerivedAssertion) -> Result<ControlEntry> {
    Ok(ControlEntry {
        assertion_id: assertion.id.clone(),
        title: control_title(assertion),
        semantics: control_semantics(&assertion.assertion_type).into(),
        state: outcome_name(assertion.outcome).into(),
        why: assertion
            .reasoning
            .iter()
            .map(|step| step.conclusion.clone())
            .collect(),
        evidence: assertion
            .support
            .iter()
            .map(|item| evidence(corpus, item))
            .collect::<Result<_>>()?,
        coverage: assertion
            .coverage
            .iter()
            .map(|decision| DossierCoverage {
                proposition: proposition_name(decision.requirement.proposition).into(),
                outcome: coverage_outcome_name(decision.outcome).into(),
                interval: format!(
                    "{} to {}",
                    decision.requirement.interval.from, decision.requirement.interval.until
                ),
                collection_runs: decision
                    .collection_runs
                    .iter()
                    .map(|run| {
                        format!(
                            "{}: {}: {}",
                            run.collection_run_id,
                            run_disposition_name(run.disposition),
                            run.reason
                        )
                    })
                    .collect(),
                uncovered: decision
                    .uncovered_intervals
                    .iter()
                    .map(|gap| format!("{} to {}", gap.from, gap.until))
                    .collect(),
            })
            .collect(),
        contradictions: assertion
            .contradictions
            .iter()
            .map(|item| evidence(corpus, item))
            .collect::<Result<_>>()?,
        missing: assertion
            .missing
            .iter()
            .map(|item| DossierGap {
                requirement: item.requirement.clone(),
                subject: item.subject.clone(),
                reason: item.reason.clone(),
            })
            .collect(),
        identity_joins: assertion
            .identity_joins
            .iter()
            .map(|join| {
                format!(
                    "{} and {} match on {}",
                    join.left_observation_id,
                    join.right_observation_id,
                    join.fields.keys().cloned().collect::<Vec<_>>().join(", ")
                )
            })
            .collect(),
        limitations: assertion.limitations.clone(),
        evaluator: assertion.derivation.version.clone(),
        manual_work_without_dossier: manual_work(&assertion.assertion_type),
    })
}

fn evidence(corpus: &Corpus, item: &EvidenceUse) -> Result<DossierEvidence> {
    let observation = corpus
        .observations
        .iter()
        .find(|observation| observation.id == item.observation_id)
        .ok_or_else(|| Error::Invalid(format!("missing observation: {}", item.observation_id)))?;
    let source = corpus
        .sources
        .iter()
        .find(|source| source.id == item.source_id)
        .ok_or_else(|| Error::Invalid(format!("missing source: {}", item.source_id)))?;
    source_bytes(corpus, &observation.id)?;
    Ok(DossierEvidence {
        observation_id: observation.id.clone(),
        source_id: source.id.clone(),
        source_sha256: source.sha256.clone(),
        collection_run_id: observation.collection_run_id.clone(),
        reason: item.reason.clone(),
        drill_down: format!("divinate source .evidence/corpus.json {}", observation.id),
    })
}

fn source_summaries(corpus: &Corpus) -> Vec<EvidenceSourceSummary> {
    let mut counts = BTreeMap::new();
    for observation in &corpus.observations {
        *counts
            .entry((
                observation.producer.name.clone(),
                observation.producer.version.clone(),
                observation.producer.collector.clone(),
            ))
            .or_insert(0_u64) += 1;
    }
    counts
        .into_iter()
        .map(
            |((producer, version, collector), observations)| EvidenceSourceSummary {
                producer,
                version,
                collector,
                observations,
            },
        )
        .collect()
}

fn acquisition_summary(
    transcript: &AcquisitionTranscript,
    registry: &ContractRegistry,
) -> AcquisitionSummary {
    let assessment = acquisition::assess(transcript, registry);
    AcquisitionSummary {
        transcript_id: transcript.id.clone(),
        contract: transcript.contents.collector_contract.clone(),
        contract_status: contract_status_name(&assessment.contract),
        subject: transcript.contents.subject.id.clone(),
        proposition: proposition_name(transcript.contents.proposition).into(),
        requested_scope: format!(
            "{} to {}",
            transcript.contents.requested_scope.from, transcript.contents.requested_scope.until
        ),
        integrity: serde_name(&assessment.integrity),
        enumeration: serde_name(&assessment.enumeration),
        authority: assessment
            .authority
            .iter()
            .map(|item| proposition_name(*item).into())
            .collect(),
        pages: assessment.pages,
        items: assessment.items,
        reasons: assessment.reasons,
    }
}

fn collection_summary(run: &CollectionRun) -> CollectionSummary {
    CollectionSummary {
        id: run.id.clone(),
        acquisition_transcript_ids: run.acquisition_transcript_ids.clone(),
        subject: run.subject.id.clone(),
        proposition: proposition_name(run.requested_scope.proposition).into(),
        requested_scope: format!(
            "{} to {}",
            run.requested_scope.interval.from, run.requested_scope.interval.until
        ),
        outcome: collection_outcome_name(run.outcome).into(),
        authority: run
            .authority
            .iter()
            .map(|item| proposition_name(*item).into())
            .collect(),
        limitations: run
            .limitations
            .iter()
            .map(|item| item.detail.clone())
            .collect(),
    }
}

fn historical_context(corpus: &Corpus) -> Vec<HistoricalContext> {
    let mut result = corpus
        .observations
        .iter()
        .filter_map(history_item)
        .collect::<Vec<_>>();
    result.sort_by(|left, right| {
        (&left.observed_at, &left.observation_id).cmp(&(&right.observed_at, &right.observation_id))
    });
    result
}

fn history_item(observation: &Observation) -> Option<HistoricalContext> {
    match observation.kind {
        ObservationKind::ConfigurationSnapshot => Some(HistoricalContext {
            observed_at: observation.observed_at.clone(),
            subject: observation.subject.id.clone(),
            summary: format!(
                "branch protection required {} approving review(s)",
                observation
                    .data
                    .get("required_approving_review_count")?
                    .as_u64()?
            ),
            observation_id: observation.id.clone(),
        }),
        ObservationKind::ChangeSet => {
            let counts = observation.data.get("counts")?;
            let metadata_note = observation
                .data
                .get("metadata_changed")
                .filter(|value| !value.is_null())
                .map_or("", |metadata| {
                    if metadata.get("tools").is_some() {
                        "; not directly comparable because generator metadata changed"
                    } else {
                        "; generator metadata changed"
                    }
                });
            Some(HistoricalContext {
                observed_at: observation.observed_at.clone(),
                subject: observation.subject.id.clone(),
                summary: format!(
                    "SBOM delta: {} added, {} removed, {} changed{metadata_note}",
                    counts.get("added")?.as_u64()?,
                    counts.get("removed")?.as_u64()?,
                    counts.get("changed")?.as_u64()?
                ),
                observation_id: observation.id.clone(),
            })
        }
        _ => None,
    }
}

fn render_overview(out: &mut String, dossier: &Dossier) {
    writeln!(out, "## at a glance\n").unwrap();
    writeln!(out, "| control | state | semantics |").unwrap();
    writeln!(out, "|---|---|---|").unwrap();
    for control in &dossier.contents.controls {
        writeln!(
            out,
            "| {} | **{}** | {} |",
            control.title, control.state, control.semantics
        )
        .unwrap();
    }
    writeln!(out).unwrap();
    writeln!(
        out,
        "evidence sources: {} · collection attempts: {} · acquisition transcripts: {}\n",
        dossier.contents.evidence_sources.len(),
        dossier.contents.collections.len(),
        dossier.contents.acquisitions.len()
    )
    .unwrap();
    writeln!(out, "### acquisition and coverage\n").unwrap();
    for acquisition in &dossier.contents.acquisitions {
        writeln!(
            out,
            "- source acquisition: integrity {}, enumeration {}, contract {}, {} for `{}` over {}",
            acquisition.integrity,
            acquisition.enumeration,
            acquisition.contract_status,
            human_name(&acquisition.proposition),
            acquisition.subject,
            acquisition.requested_scope
        )
        .unwrap();
    }
    for collection in &dossier.contents.collections {
        writeln!(
            out,
            "- collection: **{}**, {} for `{}` over {}",
            human_name(&collection.outcome),
            human_name(&collection.proposition),
            collection.subject,
            collection.requested_scope
        )
        .unwrap();
        for limitation in &collection.limitations {
            writeln!(out, "  - {limitation}").unwrap();
        }
    }
    writeln!(out).unwrap();
}

fn render_history(out: &mut String, history: &[HistoricalContext]) {
    if history.is_empty() {
        return;
    }
    writeln!(out, "## current and historical context\n").unwrap();
    for item in history {
        writeln!(
            out,
            "- `{}` for `{}`: {}",
            item.observed_at, item.subject, item.summary
        )
        .unwrap();
    }
    writeln!(out).unwrap();
}

fn render_control(out: &mut String, control: &ControlEntry) {
    writeln!(out, "## {}\n", control.title).unwrap();
    writeln!(out, "state: **{}**  ", control.state).unwrap();
    writeln!(out, "semantics: {}  ", control.semantics).unwrap();
    writeln!(
        out,
        "derivation: `{}` (`{}`)\n",
        control.evaluator, control.assertion_id
    )
    .unwrap();
    render_list(out, "why", &control.why);
    render_evidence(out, "evidence", &control.evidence);
    render_coverage(out, &control.coverage);
    render_evidence(out, "contradictions", &control.contradictions);
    let missing = control
        .missing
        .iter()
        .filter(|gap| !gap.requirement.starts_with("complete_authoritative_"))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        writeln!(out, "### evidence gaps\n").unwrap();
        for gap in missing {
            writeln!(out, "- {} ({})", gap.reason, gap.subject).unwrap();
        }
        writeln!(out).unwrap();
    }
    render_list(out, "identity joins", &control.identity_joins);
    render_list(out, "limitations", &control.limitations);
}

fn render_evidence(out: &mut String, heading: &str, evidence: &[DossierEvidence]) {
    if evidence.is_empty() {
        return;
    }
    writeln!(out, "### {heading}\n").unwrap();
    for item in evidence {
        writeln!(out, "- {} (`{}`)", item.reason, item.observation_id).unwrap();
        if let Some(run) = &item.collection_run_id {
            writeln!(out, "  - collection: `{run}`").unwrap();
        }
    }
    writeln!(out).unwrap();
}

fn render_coverage(out: &mut String, coverage: &[DossierCoverage]) {
    if coverage.is_empty() {
        return;
    }
    writeln!(out, "### coverage\n").unwrap();
    let mut gaps = BTreeMap::<&str, BTreeSet<String>>::new();
    for item in coverage {
        writeln!(
            out,
            "- {}: **{}**, {}",
            human_name(&item.proposition),
            item.outcome,
            item.interval
        )
        .unwrap();
        for run in &item.collection_runs {
            writeln!(out, "  - {run}").unwrap();
        }
        for gap in &item.uncovered {
            gaps.entry(gap)
                .or_default()
                .insert(human_name(&item.proposition));
        }
    }
    for (gap, propositions) in gaps {
        writeln!(out, "- uncovered: {gap}").unwrap();
        writeln!(
            out,
            "  - missing coverage: {}",
            propositions.into_iter().collect::<Vec<_>>().join(", ")
        )
        .unwrap();
    }
    writeln!(out).unwrap();
}

fn render_list(out: &mut String, heading: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    writeln!(out, "### {heading}\n").unwrap();
    for item in items {
        writeln!(out, "- {item}").unwrap();
    }
    writeln!(out).unwrap();
}

fn human_name(value: &str) -> String {
    value.replace('_', " ")
}

fn control_title(assertion: &DerivedAssertion) -> String {
    match &assertion.assertion_type {
        AssertionType::ConfiguredIndependentReview => format!(
            "approval required on {}",
            assertion
                .subject
                .branch
                .as_deref()
                .unwrap_or("target branch")
        ),
        AssertionType::EveryMainChangeReviewed => {
            "changes received approving review before integration".into()
        }
        AssertionType::DependencyChangeVisibility => "release dependency changes preserved".into(),
        AssertionType::ReleaseSupplyChainPolicy => "release dependency gate".into(),
        AssertionType::AdequateHumanSecurityReview => "adequate human security review".into(),
        AssertionType::ConfiguredReviewRequirement => "two-review configuration".into(),
        AssertionType::ReleaseReviewOperation => "release review operation".into(),
        AssertionType::External(value) if value == "github_current_revision_checks_passed" => {
            "observed GitHub revision results acceptable".into()
        }
        AssertionType::External(value) => human_name(value),
    }
}

const fn control_semantics(kind: &AssertionType) -> &'static str {
    match kind {
        AssertionType::ConfiguredIndependentReview | AssertionType::ConfiguredReviewRequirement => {
            "configured intent"
        }
        AssertionType::EveryMainChangeReviewed => "observed operating effectiveness",
        AssertionType::DependencyChangeVisibility => "historical release evidence",
        AssertionType::ReleaseSupplyChainPolicy => "cross-source derived claim",
        AssertionType::AdequateHumanSecurityReview => "human judgement boundary",
        AssertionType::ReleaseReviewOperation => "observed operation",
        AssertionType::External(_) => "pack-provided claim",
    }
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

fn manual_work(kind: &AssertionType) -> Vec<String> {
    let items: &[&str] = match kind {
        AssertionType::ConfiguredIndependentReview => &[
            "open repository settings and record the active branch rule",
            "retain the response and explain that configuration is not operating effectiveness",
        ],
        AssertionType::EveryMainChangeReviewed => &[
            "enumerate every repository mutation and every pull-request review",
            "reconcile commits to pull requests and determine whether direct pushes are observable",
        ],
        AssertionType::DependencyChangeVisibility => &[
            "locate both release SBOMs and retain their exact diff",
            "check whether generator and platform differences make the comparison misleading",
        ],
        AssertionType::ReleaseSupplyChainPolicy => &[
            "locate the gate result and verify its release revisions and exact SBOM-diff digest",
        ],
        AssertionType::AdequateHumanSecurityReview => &[
            "define security relevance and adequacy criteria, then inspect review content manually",
        ],
        AssertionType::ConfiguredReviewRequirement
        | AssertionType::ReleaseReviewOperation
        | AssertionType::External(_) => &[],
    };
    items.iter().map(|item| (*item).into()).collect()
}

fn serde_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

fn contract_status_name(value: &ContractStatus) -> String {
    match value {
        ContractStatus::Accepted => "accepted".into(),
        ContractStatus::Unsupported => "unsupported".into(),
        ContractStatus::Invalidated {
            discovered_at,
            reason,
        } => {
            format!("invalidated at {discovered_at}: {reason}")
        }
    }
}

const fn proposition_name(value: Proposition) -> &'static str {
    match value {
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

const fn collection_outcome_name(value: CollectionOutcome) -> &'static str {
    match value {
        CollectionOutcome::Complete => "complete",
        CollectionOutcome::Partial => "partial",
        CollectionOutcome::PermissionDenied => "permission_denied",
        CollectionOutcome::RetentionLimited => "retention_limited",
        CollectionOutcome::Interrupted => "interrupted",
        CollectionOutcome::Failed => "failed",
        CollectionOutcome::NotAttempted => "not_attempted",
    }
}

const fn coverage_outcome_name(value: CoverageOutcome) -> &'static str {
    match value {
        CoverageOutcome::Complete => "complete",
        CoverageOutcome::Incomplete => "incomplete",
    }
}

const fn run_disposition_name(value: RunDisposition) -> &'static str {
    match value {
        RunDisposition::Used => "used",
        RunDisposition::ScopeMismatch => "scope_mismatch",
        RunDisposition::NotAuthoritative => "not_authoritative",
        RunDisposition::PaginationIncomplete => "pagination_incomplete",
        RunDisposition::PermissionDenied => "permission_denied",
        RunDisposition::RetentionLimited => "retention_limited",
        RunDisposition::Interrupted => "interrupted",
        RunDisposition::Failed => "failed",
        RunDisposition::NotAttempted => "not_attempted",
    }
}
