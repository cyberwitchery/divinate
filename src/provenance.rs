//! links from derived evidence to retained source bytes.
//!
//! [`verify_execution_links`] resolves observations to execution output.
//! [`verify_collection_links`] checks collection and acquisition identity.
//! [`with_current_authority`] applies current contract status to a copied corpus.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::acquisition::{
    self, AcquisitionTranscript, ContractRegistry, ContractStatus, IntegrityStatus,
};
use crate::error::{Error, Result};
use crate::execution::{self, ExecutionTranscript, Integrity as ExecutionIntegrity};
use crate::model::{CollectionOutcome, Corpus};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one collection resolved to its acquisition, with current authority.
pub struct CollectionTranscriptLink {
    pub collection_run_id: String,
    pub transcript_id: String,
    pub integrity: IntegrityStatus,
    pub contract: ContractStatus,
    pub currently_authoritative: bool,
    pub source_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// one observation resolved to the exact execution output behind it.
pub struct ObservationExecutionLink {
    pub observation_id: String,
    pub source_id: String,
    pub execution_transcript_id: String,
    pub integrity: ExecutionIntegrity,
    pub output: String,
}

/// resolve observation-to-execution links through exact retained output bytes.
///
/// # Errors
///
/// returns an error for missing or invalid transcripts and when the observation
/// source bytes are not an exact execution stream or declared output.
pub fn verify_execution_links(
    corpus: &Corpus,
    transcripts: &[ExecutionTranscript],
    blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<ObservationExecutionLink>> {
    let mut by_id = BTreeMap::new();
    for transcript in transcripts {
        if by_id.insert(transcript.id.as_str(), transcript).is_some() {
            return Err(Error::Invalid(format!(
                "duplicate execution transcript: {}",
                transcript.id
            )));
        }
    }
    let mut links = Vec::new();
    for observation in &corpus.observations {
        crate::source_bytes(corpus, &observation.id)?;
        let source = corpus
            .sources
            .iter()
            .find(|source| source.id == observation.provenance.source_id)
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "missing source: {}",
                    observation.provenance.source_id
                ))
            })?;
        for transcript_id in &observation.execution_transcript_ids {
            let transcript = by_id.get(transcript_id.as_str()).ok_or_else(|| {
                Error::Invalid(format!(
                    "observation {} references missing execution transcript {transcript_id}",
                    observation.id
                ))
            })?;
            execution::verify(transcript, blobs)?;
            let output = if transcript.contents.stdout.sha256 == source.sha256 {
                "stdout".to_owned()
            } else if transcript.contents.stderr.sha256 == source.sha256 {
                "stderr".to_owned()
            } else if let Some(output) = transcript
                .contents
                .outputs
                .iter()
                .find(|output| output.blob.sha256 == source.sha256)
            {
                format!("output:{}", output.name)
            } else if normalized_gate_matches(source, transcript) {
                "normalized_execution_result".to_owned()
            } else {
                return Err(Error::Invalid(format!(
                    "source {} is not an exact output of execution {transcript_id}",
                    source.id
                )));
            };
            links.push(ObservationExecutionLink {
                observation_id: observation.id.clone(),
                source_id: source.id.clone(),
                execution_transcript_id: transcript.id.clone(),
                integrity: ExecutionIntegrity::Verified,
                output,
            });
        }
    }
    Ok(links)
}

fn normalized_gate_matches(
    source: &crate::model::SourceDocument,
    transcript: &ExecutionTranscript,
) -> bool {
    if source.format != "supply-chain-gate" {
        return false;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&source.content) else {
        return false;
    };
    let rules_match = value
        .pointer("/policy/rules")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|rules| {
            rules.iter().all(|rule| {
                rule.as_str() == Some("no-added-components")
                    && transcript
                        .contents
                        .argv
                        .windows(2)
                        .any(|pair| pair == ["--fail-on", "added-components"])
            })
        });
    rules_match
        && value
            .pointer("/tool/name")
            .and_then(serde_json::Value::as_str)
            == Some(transcript.contents.tool.name.as_str())
        && value
            .pointer("/tool/version")
            .and_then(serde_json::Value::as_str)
            == transcript.contents.tool.reported_version.as_deref()
        && value
            .pointer("/execution/transcript_id")
            .and_then(serde_json::Value::as_str)
            == Some(transcript.id.as_str())
        && value
            .pointer("/execution/result_from")
            .and_then(serde_json::Value::as_str)
            == Some("exit_status")
        && value.get("passed").and_then(serde_json::Value::as_bool)
            == Some(transcript.contents.exit.success)
        && value
            .pointer("/input/sbom_diff_sha256")
            .and_then(serde_json::Value::as_str)
            == Some(transcript.contents.stdout.sha256.as_str())
}

/// resolve and verify collection-to-acquisition links.
///
/// observations must resolve to bytes in a linked response. zero-result attempts
/// retain their transcript link.
///
/// # Errors
///
/// returns an error for duplicate or missing transcripts, broken integrity,
/// mismatched scope, or source bytes absent from the linked acquisition.
pub fn verify_collection_links(
    corpus: &Corpus,
    transcripts: &[AcquisitionTranscript],
    registry: &ContractRegistry,
) -> Result<Vec<CollectionTranscriptLink>> {
    let mut by_id = BTreeMap::new();
    for transcript in transcripts {
        if by_id.insert(transcript.id.as_str(), transcript).is_some() {
            return Err(Error::Invalid(format!(
                "duplicate acquisition transcript: {}",
                transcript.id
            )));
        }
    }
    let mut links = Vec::new();
    for run in &corpus.collections {
        if run.outcome != CollectionOutcome::NotAttempted
            && run.acquisition_transcript_ids.is_empty()
        {
            continue;
        }
        let mut run_links = Vec::new();
        let mut digest_owner = BTreeMap::new();
        for transcript_id in &run.acquisition_transcript_ids {
            let transcript = by_id.get(transcript_id.as_str()).ok_or_else(|| {
                Error::Invalid(format!(
                    "collection {} references missing acquisition transcript {transcript_id}",
                    run.id
                ))
            })?;
            if transcript.contents.subject.id != run.subject.id
                || transcript.contents.proposition != run.requested_scope.proposition
                || transcript.contents.requested_scope != run.requested_scope.interval
            {
                return Err(Error::Invalid(format!(
                    "collection {} and acquisition {transcript_id} have different subject, proposition, or scope",
                    run.id
                )));
            }
            let assessment = acquisition::assess(transcript, registry);
            if assessment.integrity != IntegrityStatus::Verified {
                return Err(Error::Invalid(format!(
                    "collection {} links acquisition {transcript_id} with failed integrity",
                    run.id
                )));
            }
            let owner = run_links.len();
            for exchange in &transcript.contents.exchanges {
                digest_owner.insert(exchange.response.body_sha256.as_str(), owner);
            }
            run_links.push(CollectionTranscriptLink {
                collection_run_id: run.id.clone(),
                transcript_id: transcript.id.clone(),
                integrity: assessment.integrity,
                contract: assessment.contract,
                currently_authoritative: assessment
                    .authority
                    .contains(&run.requested_scope.proposition),
                source_ids: vec![],
            });
        }
        for observation in corpus
            .observations
            .iter()
            .filter(|observation| observation.collection_run_id.as_deref() == Some(run.id.as_str()))
        {
            let source = corpus
                .sources
                .iter()
                .find(|source| source.id == observation.provenance.source_id)
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "missing source: {}",
                        observation.provenance.source_id
                    ))
                })?;
            let owner = digest_owner.get(source.sha256.as_str()).ok_or_else(|| {
                Error::Invalid(format!(
                    "source {} is not present in a linked acquisition for collection {}",
                    source.id, run.id
                ))
            })?;
            run_links[*owner].source_ids.push(source.id.clone());
        }
        for link in &mut run_links {
            link.source_ids.sort();
            link.source_ids.dedup();
        }
        links.extend(run_links);
    }
    Ok(links)
}

/// apply the current contract registry to a copied corpus.
///
/// # Errors
///
/// returns an error when a collection-to-transcript link is invalid.
pub fn with_current_authority(
    corpus: &Corpus,
    transcripts: &[AcquisitionTranscript],
    registry: &ContractRegistry,
) -> Result<Corpus> {
    let links = verify_collection_links(corpus, transcripts, registry)?;
    let mut current = corpus.clone();
    for link in links.iter().filter(|link| !link.currently_authoritative) {
        if let Some(run) = current
            .collections
            .iter_mut()
            .find(|run| run.id == link.collection_run_id)
        {
            run.authority
                .retain(|proposition| proposition != &run.requested_scope.proposition);
        }
    }
    Ok(current)
}
