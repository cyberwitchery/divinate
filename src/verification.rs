//! offline verification of a stored evidence state.

use std::path::Path;

use serde::Serialize;

use crate::acquisition;
use crate::error::{provenance_error, Error, Result};
use crate::model::Corpus;
use crate::{execution, load_corpus};

/// what [`verify`] checked.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub acquisition_transcripts: usize,
    pub collection_acquisition_links: usize,
    pub configured_collection_cycles: usize,
    pub content_blobs: usize,
    pub corpus: CorpusPresence,
    pub execution_transcripts: usize,
    pub observation_execution_links: usize,
    pub pack_invocations: usize,
    pub status: VerificationStatus,
}

/// whether the state holds a `corpus.json`.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CorpusPresence {
    Present,
    Absent,
}

/// a [`VerificationReport`] is only returned for a verified state.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    Verified,
}

/// verify every retained object in `state` and the links between them.
///
/// checks each transcript's integrity, each execution and pack invocation
/// against its blobs, the evidence graph, and the configured collection
/// cycles; a state without a corpus must hold no cycles or saved evaluations.
/// nothing is written.
///
/// # Errors
///
/// returns an error for the first object or link that fails.
pub fn verify(state: &Path) -> Result<VerificationReport> {
    let corpus_path = crate::workflow::corpus_path(state);
    let corpus = corpus_path
        .is_file()
        .then(|| load_corpus(&corpus_path))
        .transpose()?;
    let acquisitions = crate::workflow::load_transcripts(state).map_err(provenance_error)?;
    let executions = crate::workflow::load_executions(state).map_err(provenance_error)?;
    let blobs = crate::workflow::load_blobs(state).map_err(provenance_error)?;
    let registry = crate::workflow::load_registry(state)?;
    for transcript in &acquisitions {
        let assessment = acquisition::assess(transcript, &registry);
        if assessment.integrity != acquisition::IntegrityStatus::Verified {
            return Err(Error::Provenance(format!(
                "acquisition transcript {} failed integrity: {}",
                transcript.id,
                assessment.reasons.join("; ")
            )));
        }
    }
    for transcript in &executions {
        execution::verify_stored(transcript, &blobs).map_err(provenance_error)?;
    }
    let pack_invocations = crate::workflow::load_pack_invocations(state)?;
    for invocation in &pack_invocations {
        crate::pack::verify_stored(invocation, &blobs).map_err(provenance_error)?;
    }
    let empty = Corpus {
        collections: vec![],
        observations: vec![],
        schema_version: crate::SCHEMA_VERSION.into(),
        sources: vec![],
    };
    let links = crate::provenance::verify_graph(
        crate::provenance::EvidenceGraph {
            corpus: corpus.as_ref().unwrap_or(&empty),
            acquisitions: &acquisitions,
            executions: &executions,
            pack_invocations: &pack_invocations,
            blobs: &blobs,
        },
        &registry,
    )
    .map_err(provenance_error)?;
    let (corpus_status, configured_cycles) = if let Some(corpus) = &corpus {
        let configured_cycles = crate::workflow::verify_configuration_provenance(
            state,
            corpus,
            &executions,
            &pack_invocations,
        )
        .map_err(provenance_error)?;
        (CorpusPresence::Present, configured_cycles)
    } else {
        if !crate::workflow::load_collection_cycles(state)?.is_empty() {
            return Err(Error::Provenance(
                "collection cycles are present but corpus.json is absent".into(),
            ));
        }
        let assertions = state.join("assertions");
        if assertions.is_dir()
            && std::fs::read_dir(&assertions)
                .map_err(|source| Error::Io {
                    path: assertions.clone(),
                    source,
                })?
                .filter_map(std::result::Result::ok)
                .any(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|value| value == "json")
                })
        {
            return Err(Error::Provenance(
                "saved evaluations are present but corpus.json is absent".into(),
            ));
        }
        (CorpusPresence::Absent, 0)
    };
    Ok(VerificationReport {
        acquisition_transcripts: acquisitions.len(),
        collection_acquisition_links: links.collections.len(),
        configured_collection_cycles: configured_cycles,
        content_blobs: blobs.len(),
        corpus: corpus_status,
        execution_transcripts: executions.len(),
        observation_execution_links: links.executions.len(),
        pack_invocations: pack_invocations.len(),
        status: VerificationStatus::Verified,
    })
}
