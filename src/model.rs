//! evidence corpus types.
//!
//! [`Corpus`] contains retained [`SourceDocument`] values, typed
//! [`Observation`] values, and [`CollectionRun`] coverage records.
//! [`EvidenceClass`] separates intent, operation, and state. [`Proposition`]
//! scopes source authority. [`CollectionOutcome`] records how enumeration ended.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// the accumulated, append-only evidence record for one repository.
pub struct Corpus {
    #[serde(default)]
    pub collections: Vec<CollectionRun>,
    pub observations: Vec<Observation>,
    pub schema_version: String,
    pub sources: Vec<SourceDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// retained source bytes, addressed by the sha-256 of their content.
pub struct SourceDocument {
    pub content: String,
    pub format: String,
    pub id: String,
    pub media_type: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// a typed interpretation bound to retained source bytes and provenance.
pub struct Observation {
    /// stable key for the fact being stated, used to match evaluators to inputs.
    pub claim_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// the enumeration attempt this came from, if it came from one.
    pub collection_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// the local executions whose exact output this resolves to.
    pub execution_transcript_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// the pack calls that planned, normalized, and identified this observation.
    pub pack_invocation_ids: Vec<String>,
    pub data: Value,
    pub evidence_class: EvidenceClass,
    pub id: String,
    pub kind: ObservationKind,
    /// when the fact was observed, not when it was recorded.
    pub observed_at: String,
    pub producer: Producer,
    pub provenance: Provenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    pub subject: Subject,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
/// what kind of fact an observation states.
///
/// observation kinds remain distinct inputs to evaluators.
pub enum ObservationKind {
    ChangeSet,
    ConfigurationHistory,
    ConfigurationSnapshot,
    MutationHistory,
    PolicyCheck,
    ReleaseMembership,
    ReviewRecord,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
/// whether evidence describes intent, operation, or state.
pub enum EvidenceClass {
    ConfiguredIntent,
    ObservedOperation,
    ObservedState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
/// severity reported by a policy check, carried through unmodified.
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
/// pass, fail, warning, or unknown, as reported by a policy check.
pub enum Status {
    Pass,
    Fail,
    Warning,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// the tool and collector that produced an observation.
pub struct Producer {
    pub name: String,
    pub version: String,
    pub collector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// the source document an observation resolves to.
pub struct Provenance {
    pub pointer: String,
    pub source_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// what an observation or collection is about.
///
/// `kind` and `id` identify the subject; `qualifiers` carry the fields that
/// identity joins are made on, such as `branch`, `release`, or `revision`.
pub struct Subject {
    pub kind: String,
    pub id: String,
    #[serde(flatten)]
    pub qualifiers: BTreeMap<String, Value>,
}

impl Subject {
    /// read one subject qualifier as a string, if present and textual.
    pub fn qualifier(&self, name: &str) -> Option<&str> {
        self.qualifiers.get(name).and_then(Value::as_str)
    }
}

#[derive(Debug, Deserialize)]
/// an explicitly authored set of sources, for the interchange collection path.
pub struct Manifest {
    #[serde(default)]
    pub collection_runs: Vec<CollectionRun>,
    pub sources: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
/// an explicitly authored set of sources, for the interchange collection path.
pub struct ManifestEntry {
    pub adapter: String,
    pub collection_run: Option<String>,
    #[serde(default)]
    pub execution_transcripts: Vec<String>,
    pub path: String,
    pub observed_at: String,
    pub producer: Producer,
    pub subject: Subject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// an attempt to enumerate a source population.
pub struct CollectionRun {
    pub id: String,
    #[serde(default)]
    /// the transcripts backing this run's coverage statement.
    pub acquisition_transcript_ids: Vec<String>,
    pub collector: Producer,
    pub endpoint: String,
    pub subject: Subject,
    /// the population and interval the collector asked for.
    pub requested_scope: CollectionScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// what it actually reached. absent means no coverage can be claimed.
    pub observed_scope: Option<CollectionScope>,
    pub enumeration: Enumeration,
    pub outcome: CollectionOutcome,
    #[serde(default)]
    pub limitations: Vec<CollectionLimitation>,
    /// the propositions this collector claims its contract can establish.
    pub authority: Vec<Proposition>,
    #[serde(default)]
    pub observation_ids: Vec<String>,
    pub started_at: String,
    pub completed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// the proposition, branch, and interval a collection covers or requested.
pub struct CollectionScope {
    pub proposition: Proposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub interval: TimeRange,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// a half-open interval, `from` inclusive and `until` exclusive.
pub struct TimeRange {
    pub from: String,
    pub until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// how far enumeration actually got.
///
/// pagination state used to establish complete enumeration.
pub struct Enumeration {
    pub items_fetched: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// the total the source claimed, where it reports one.
    pub items_reported: Option<u64>,
    pub pages_fetched: u64,
    /// whether the source's own pagination said this was the last page.
    pub terminal_page_reached: bool,
    /// whether a further page was still on offer when enumeration stopped.
    pub next_token_present: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// how a collection attempt ended.
pub enum CollectionOutcome {
    Complete,
    Partial,
    PermissionDenied,
    RetentionLimited,
    Interrupted,
    Failed,
    NotAttempted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// a specific reason a collection did not cover its requested scope.
pub struct CollectionLimitation {
    pub kind: CollectionLimitationKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// the category of a collection limitation.
pub enum CollectionLimitationKind {
    PaginationIncomplete,
    PermissionDenied,
    RetentionBoundary,
    Interrupted,
    SourceError,
    NotAttempted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
/// what a source contract can establish.
pub enum Proposition {
    PullRequestPopulation,
    PullRequestReviews,
    RepositoryMutations,
    CommitAncestry,
    BranchConfiguration,
    RevisionChecks,
    SupplyChainPolicyDecision,
    DeclaredDependencies,
}
