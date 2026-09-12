//! local security evidence and traceable claims.
//!
//! ```text
//! acquisition and execution transcripts
//!   → collection coverage
//!   → observations
//!   → assertions
//!   → views
//! ```
//!
//! [`workflow`] stores the graph in `.evidence/`. [`release`] collects the
//! baseline release comparison. [`pack`] lets external executables add typed
//! collectors and evaluators while core retains identity, execution, coverage,
//! and persistence.
//!
//! # verifying a stored claim
//!
//! ```no_run
//! use std::path::Path;
//! use divinate::{load_corpus, workflow, provenance};
//!
//! let state = Path::new(".evidence");
//! let corpus = load_corpus(&workflow::corpus_path(state))?;
//! let executions = workflow::load_executions(state)?;
//! let blobs = workflow::load_blobs(state)?;
//!
//! let links = provenance::verify_execution_links(&corpus, &executions, &blobs)?;
//! println!("{} verified observation-to-execution links", links.len());
//! # Ok::<(), divinate::error::Error>(())
//! ```

pub mod acquisition;
pub mod adapters;
pub mod assertions;
pub mod coverage;
pub mod dossier;
pub mod error;
pub mod execution;
pub mod model;
pub mod pack;
pub mod project;
pub mod provenance;
pub mod release;
pub mod views;
pub mod workflow;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::adapters::adapt;
use crate::error::{Error, Result};
use crate::model::{CollectionRun, Corpus, Manifest, Observation, Provenance, SourceDocument};

/// the corpus format version this build reads and writes.
///
/// [`load_corpus`] accepts only this version.
pub const SCHEMA_VERSION: &str = "0.1.0";

/// collect every manifest source into a deterministic corpus.
///
/// # Errors
///
/// returns an error when the manifest or a source cannot be read, parsed, or adapted.
pub fn collect(path: &Path) -> Result<Corpus> {
    let manifest: Manifest = read_json(path)?;
    if manifest.sources.is_empty() {
        return Err(Error::Invalid("manifest.sources must not be empty".into()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut collections = manifest.collection_runs;
    validate_collection_runs(&collections)?;
    let collection_ids = collections
        .iter()
        .map(|run| run.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut sources = BTreeMap::new();
    let mut observations = Vec::with_capacity(manifest.sources.len());

    for entry in manifest.sources {
        if let Some(run_id) = &entry.collection_run {
            if !collection_ids.contains(run_id.as_str()) {
                return Err(Error::Invalid(format!("unknown collection run: {run_id}")));
            }
        }
        parse_timestamp(&entry.observed_at)?;
        let source_path = parent.join(&entry.path);
        let bytes = fs::read(&source_path).map_err(|source| Error::Io {
            path: source_path.clone(),
            source,
        })?;
        let content = String::from_utf8(bytes.clone()).map_err(|source| Error::Utf8 {
            path: source_path.clone(),
            source,
        })?;
        let payload = serde_json::from_slice(&bytes).map_err(|source| Error::Json {
            path: source_path.clone(),
            source,
        })?;
        let digest = hex_digest(&bytes);
        let source_id = format!("src_{}", &digest[..20]);
        let source = SourceDocument {
            content,
            format: entry.adapter.clone(),
            id: source_id.clone(),
            media_type: "application/json".into(),
            path: entry.path.clone(),
            sha256: digest.clone(),
        };
        if let Some(existing) = sources.insert(source_id.clone(), source.clone()) {
            if existing.content != source.content {
                return Err(Error::Invalid(format!("source id collision: {source_id}")));
            }
        }

        let adapted = adapt(&entry.adapter, &payload, &entry.subject)?;
        let identity = serde_json::json!({
            "adapter": entry.adapter,
            "claim_key": adapted.claim_key,
            "collection_run": entry.collection_run,
            "execution_transcripts": entry.execution_transcripts,
            "observed_at": entry.observed_at,
            "source_sha256": digest,
            "subject": entry.subject,
        });
        let id = format!("ev_{}", &hex_digest(&canonical_json(&identity)?)[..20]);
        observations.push(Observation {
            claim_key: adapted.claim_key,
            collection_run_id: entry.collection_run,
            execution_transcript_ids: entry.execution_transcripts,
            pack_invocation_ids: vec![],
            data: adapted.data,
            evidence_class: adapted.evidence_class,
            id,
            kind: adapted.kind,
            observed_at: entry.observed_at,
            producer: entry.producer,
            provenance: Provenance {
                pointer: String::new(),
                source_id,
            },
            severity: adapted.severity,
            status: adapted.status,
            subject: entry.subject,
        });
    }

    observations
        .sort_by(|left, right| (&left.observed_at, &left.id).cmp(&(&right.observed_at, &right.id)));
    for run in &mut collections {
        run.observation_ids = observations
            .iter()
            .filter(|observation| observation.collection_run_id.as_deref() == Some(run.id.as_str()))
            .map(|observation| observation.id.clone())
            .collect();
    }
    Ok(Corpus {
        collections,
        observations,
        schema_version: SCHEMA_VERSION.into(),
        sources: sources.into_values().collect(),
    })
}

fn validate_collection_runs(collections: &[CollectionRun]) -> Result<()> {
    for run in collections {
        let started_at = parse_timestamp(&run.started_at)?;
        let completed_at = parse_timestamp(&run.completed_at)?;
        if started_at > completed_at {
            return Err(Error::Invalid(format!(
                "collection {} completes before it starts",
                run.id
            )));
        }
        let requested_from = parse_timestamp(&run.requested_scope.interval.from)?;
        let requested_until = parse_timestamp(&run.requested_scope.interval.until)?;
        if requested_from >= requested_until {
            return Err(Error::Invalid(format!(
                "collection {} has an empty requested interval",
                run.id
            )));
        }
        if let Some(scope) = &run.observed_scope {
            let observed_from = parse_timestamp(&scope.interval.from)?;
            let observed_until = parse_timestamp(&scope.interval.until)?;
            if observed_from >= observed_until {
                return Err(Error::Invalid(format!(
                    "collection {} has an empty observed interval",
                    run.id
                )));
            }
        }
    }
    let collection_ids = collections
        .iter()
        .map(|run| run.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if collection_ids.len() != collections.len() {
        return Err(Error::Invalid("collection run ids must be unique".into()));
    }
    Ok(())
}

/// read a corpus and check its schema version.
///
/// # Errors
///
/// returns an error when the file cannot be read, parsed, or has an unsupported version.
pub fn load_corpus(path: &Path) -> Result<Corpus> {
    let corpus: Corpus = read_json(path)?;
    if corpus.schema_version != SCHEMA_VERSION {
        return Err(Error::Invalid(format!(
            "unsupported corpus schema version: {:?}",
            corpus.schema_version
        )));
    }
    Ok(corpus)
}

/// recover the hash-verified source bytes for an observation.
///
/// # Errors
///
/// returns an error when the observation or source is missing, or the source hash differs.
pub fn source_bytes<'a>(corpus: &'a Corpus, evidence_id: &str) -> Result<&'a [u8]> {
    let observation = corpus
        .observations
        .iter()
        .find(|item| item.id == evidence_id)
        .ok_or_else(|| Error::Invalid(format!("unknown evidence id: {evidence_id}")))?;
    let source = corpus
        .sources
        .iter()
        .find(|item| item.id == observation.provenance.source_id)
        .ok_or_else(|| {
            Error::Invalid(format!(
                "missing source: {}",
                observation.provenance.source_id
            ))
        })?;
    let bytes = source.content.as_bytes();
    let digest = hex_digest(bytes);
    if digest != source.sha256 {
        return Err(Error::Invalid(format!(
            "source hash mismatch: {}",
            source.id
        )));
    }
    if source.id != format!("src_{}", &digest[..20]) {
        return Err(Error::Invalid(format!(
            "source content address mismatch: {}",
            source.id
        )));
    }
    Ok(bytes)
}

/// deserialize a json file.
///
/// # Errors
///
/// returns an error when the file cannot be read or parsed.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| Error::Json {
        path: path.to_path_buf(),
        source,
    })
}

/// serialize a json value for hashing.
///
/// # Errors
///
/// returns an error when serialization fails.
pub fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(Error::Serialize)
}

/// parse an rfc 3339 timestamp with an explicit offset.
///
/// # Errors
///
/// returns an error when the value is not rfc 3339.
pub fn parse_timestamp(value: &str) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).map_err(
        |source| Error::Timestamp {
            value: value.into(),
            source,
        },
    )
}

/// return a lowercase sha-256 digest.
#[must_use]
pub fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// serialize a value as pretty json and write it to a file.
///
/// # Errors
///
/// returns an error when serialization or writing fails.
pub fn write_json<T: serde::Serialize>(value: &T, path: &Path) -> Result<()> {
    let mut rendered = serde_json::to_vec_pretty(value).map_err(Error::Serialize)?;
    rendered.push(b'\n');
    fs::write(path, rendered).map_err(|source| Error::Io {
        path: PathBuf::from(path),
        source,
    })
}
