//! repository-local evidence state.
//!
//! accumulation reuses equal content-addressed objects and rejects conflicting
//! ids. [`as_of_with_provenance`] returns a closed historical graph containing
//! only evidence whose complete provenance existed at the evaluation time.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::acquisition::{self, AcquisitionTranscript, ContractRegistry, IntegrityStatus};
use crate::error::{Error, Result};
use crate::execution::{self, ExecutionCapture, ExecutionTranscript};
use crate::model::{Corpus, SourceDocument};
use crate::{read_json, write_json, SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// the accumulated corpus, relative to the state directory.
pub const CORPUS_FILE: &str = "corpus.json";
/// the current contract invalidations, relative to the state directory.
pub const CONTRACTS_FILE: &str = "contracts.json";
/// the repository identity and configured packs, relative to the state directory.
pub const CONFIG_FILE: &str = "config.json";

#[derive(Debug, Clone, PartialEq)]
/// a referentially closed view: a corpus and exactly the provenance justifying it.
pub struct HistoricalEvidence {
    pub corpus: Corpus,
    pub acquisitions: Vec<AcquisitionTranscript>,
    pub executions: Vec<ExecutionTranscript>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// repository identity, branch, and configured packs.
pub struct ProjectConfig {
    pub repository: String,
    #[serde(default = "default_branch")]
    pub branch: String,
    #[serde(default)]
    pub packs: BTreeMap<String, crate::pack::PackConfig>,
}

/// create repository-local state directories and a default contract registry.
///
/// # Errors
///
/// returns an error when the state cannot be created.
pub fn init(root: &Path) -> Result<()> {
    for directory in [
        "acquisitions",
        "assertions",
        "blobs",
        "dossiers",
        "executions",
        "pack-invocations",
        "views",
    ] {
        let path = root.join(directory);
        fs::create_dir_all(&path).map_err(|source| Error::Io { path, source })?;
    }
    let contracts = root.join(CONTRACTS_FILE);
    if !contracts.exists() {
        write_json(&ContractRegistry::default(), &contracts)?;
    }
    Ok(())
}

/// store verified pack invocations and their executable blobs.
///
/// # Errors
///
/// returns an error for invalid provenance or a content-address collision.
pub fn store_pack_invocations(root: &Path, captures: &[crate::pack::PackCapture]) -> Result<()> {
    init(root)?;
    for capture in captures {
        let digest = crate::hex_digest(&capture.executable_bytes);
        if digest != capture.invocation.contents.executable.sha256 {
            return Err(Error::Provenance("pack executable digest mismatch".into()));
        }
        let blob_path = root.join("blobs").join(&digest);
        if blob_path.exists() {
            let existing = fs::read(&blob_path).map_err(|source| Error::Io {
                path: blob_path.clone(),
                source,
            })?;
            if existing != capture.executable_bytes {
                return Err(Error::Invalid(format!("blob collision: {digest}")));
            }
        } else {
            fs::write(&blob_path, &capture.executable_bytes).map_err(|source| Error::Io {
                path: blob_path,
                source,
            })?;
        }
        let path = root
            .join("pack-invocations")
            .join(format!("{}.json", capture.invocation.id));
        if path.exists() {
            let existing: crate::pack::PackInvocation = read_json(&path)?;
            if existing != capture.invocation {
                return Err(Error::Invalid(format!(
                    "pack invocation id collision: {}",
                    capture.invocation.id
                )));
            }
        } else {
            write_json(&capture.invocation, &path)?;
        }
    }
    Ok(())
}

/// load every retained pack invocation.
///
/// # Errors
///
/// returns an error when an invocation file is invalid.
pub fn load_pack_invocations(root: &Path) -> Result<Vec<crate::pack::PackInvocation>> {
    load_json_directory(&root.join("pack-invocations"))
}

/// write repository identity and pack configuration.
///
/// # Errors
///
/// returns an error when the repository identity is empty or the file cannot be written.
pub fn configure(root: &Path, config: &ProjectConfig) -> Result<()> {
    init(root)?;
    if config.repository.trim().is_empty() {
        return Err(Error::Invalid(
            "repository identity must not be empty".into(),
        ));
    }
    let path = root.join(CONFIG_FILE);
    if path.exists() {
        let existing: ProjectConfig = read_json(&path)?;
        if existing != *config {
            return Err(Error::Invalid(format!(
                "configuration already identifies repository {:?}; edit {} intentionally to change it",
                existing.repository,
                path.display()
            )));
        }
        return Ok(());
    }
    write_json(config, &path)
}

/// load repository workflow configuration.
///
/// # Errors
///
/// returns an error when configuration is absent or invalid.
pub fn load_config(root: &Path) -> Result<ProjectConfig> {
    let path = root.join(CONFIG_FILE);
    if !path.exists() {
        return Err(Error::Invalid(format!(
            "missing configuration {}; run `divinate init --repository <identity>`",
            path.display()
        )));
    }
    read_json(&path)
}

/// append a corpus increment and acquisition transcripts.
///
/// # Errors
///
/// returns an error for invalid state, transcript integrity failure, or collision.
pub fn accumulate(
    root: &Path,
    increment: &Corpus,
    transcripts: &[AcquisitionTranscript],
) -> Result<Corpus> {
    accumulate_with_executions(root, increment, transcripts, &[])
}

/// append a corpus increment and immutable acquisition or execution provenance.
///
/// # Errors
///
/// returns an error for invalid state, integrity failure, a broken provenance
/// link, or a content-address collision.
pub fn accumulate_with_executions(
    root: &Path,
    increment: &Corpus,
    transcripts: &[AcquisitionTranscript],
    executions: &[ExecutionCapture],
) -> Result<Corpus> {
    init(root)?;
    for transcript in transcripts {
        let assessment = acquisition::assess(transcript, &ContractRegistry::default());
        if assessment.integrity != IntegrityStatus::Verified {
            return Err(Error::Invalid(format!(
                "acquisition {} failed integrity verification",
                transcript.id
            )));
        }
        let path = root
            .join("acquisitions")
            .join(format!("{}.json", transcript.id));
        if path.exists() {
            let existing: AcquisitionTranscript = read_json(&path)?;
            if existing != *transcript {
                return Err(Error::Invalid(format!(
                    "acquisition id collision: {}",
                    transcript.id
                )));
            }
        } else {
            write_json(transcript, &path)?;
        }
    }
    for capture in executions {
        store_execution(root, capture)?;
    }
    let corpus_path = root.join(CORPUS_FILE);
    let base = if corpus_path.exists() {
        read_json(&corpus_path)?
    } else {
        Corpus {
            collections: vec![],
            observations: vec![],
            schema_version: SCHEMA_VERSION.into(),
            sources: vec![],
        }
    };
    let merged = merge(&base, increment)?;
    let all_transcripts = load_transcripts(root)?;
    crate::provenance::verify_collection_links(
        &merged,
        &all_transcripts,
        &ContractRegistry::default(),
    )?;
    let all_executions = load_executions(root)?;
    let blobs = load_blobs(root)?;
    crate::provenance::verify_execution_links(&merged, &all_executions, &blobs)?;
    let pack_invocations = load_pack_invocations(root)?;
    let stored_executions = load_executions(root)?;
    crate::pack::verify_observation_links(&merged, &pack_invocations, &stored_executions, &blobs)?;
    write_json(&merged, &corpus_path)?;
    Ok(merged)
}

/// store an execution transcript and its content-addressed blobs immutably.
///
/// # Errors
///
/// returns an error when integrity verification or immutable storage fails.
pub fn store_execution(root: &Path, capture: &ExecutionCapture) -> Result<()> {
    init(root)?;
    execution::verify(&capture.transcript, &capture.blobs)?;
    for (digest, bytes) in &capture.blobs {
        if crate::hex_digest(bytes) != *digest {
            return Err(Error::Invalid(format!(
                "execution capture contains misaddressed blob: {digest}"
            )));
        }
        let path = root.join("blobs").join(digest);
        if path.exists() {
            let existing = fs::read(&path).map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
            if existing != *bytes {
                return Err(Error::Invalid(format!("blob collision: {digest}")));
            }
        } else {
            fs::write(&path, bytes).map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
        }
    }
    let path = root
        .join("executions")
        .join(format!("{}.json", capture.transcript.id));
    if path.exists() {
        let existing: ExecutionTranscript = read_json(&path)?;
        if existing != capture.transcript {
            return Err(Error::Invalid(format!(
                "execution id collision: {}",
                capture.transcript.id
            )));
        }
    } else {
        write_json(&capture.transcript, &path)?;
    }
    Ok(())
}

/// load every immutable execution transcript in stable id order.
///
/// # Errors
///
/// returns an error when a transcript cannot be read.
pub fn load_executions(root: &Path) -> Result<Vec<ExecutionTranscript>> {
    load_json_directory(&root.join("executions"))
}

/// load all content-addressed execution blobs.
///
/// # Errors
///
/// returns an error when a blob cannot be read or its filename is not its digest.
pub fn load_blobs(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let directory = root.join("blobs");
    if !directory.exists() {
        return Ok(BTreeMap::new());
    }
    let mut blobs = BTreeMap::new();
    let entries = fs::read_dir(&directory).map_err(|source| Error::Io {
        path: directory.clone(),
        source,
    })?;
    for entry in entries {
        let path = entry
            .map_err(|source| Error::Io {
                path: directory.clone(),
                source,
            })?
            .path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::Invalid(format!("invalid blob filename: {}", path.display())))?
            .to_owned();
        let bytes = fs::read(&path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        if crate::hex_digest(&bytes) != name {
            return Err(Error::Invalid(format!(
                "blob filename does not match content: {}",
                path.display()
            )));
        }
        blobs.insert(name, bytes);
    }
    Ok(blobs)
}

/// load every immutable acquisition in stable id order.
///
/// # Errors
///
/// returns an error when an acquisition file cannot be read.
pub fn load_transcripts(root: &Path) -> Result<Vec<AcquisitionTranscript>> {
    load_json_directory(&root.join("acquisitions"))
}

fn load_json_directory<T: serde::de::DeserializeOwned>(directory: &Path) -> Result<Vec<T>> {
    if !directory.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(directory).map_err(|source| Error::Io {
        path: directory.to_path_buf(),
        source,
    })?;
    let mut paths = entries
        .map(|entry| {
            entry.map(|entry| entry.path()).map_err(|source| Error::Io {
                path: directory.to_path_buf(),
                source,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    paths.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    });
    paths.sort();
    paths.iter().map(|path| read_json(path)).collect()
}

/// read the current contract registry from repository state.
///
/// # Errors
///
/// returns an error when the registry cannot be read.
pub fn load_registry(root: &Path) -> Result<ContractRegistry> {
    read_json(&root.join(CONTRACTS_FILE))
}

/// merge two immutable corpora by stable object id.
///
/// # Errors
///
/// returns an error when equal ids carry different contents.
pub fn merge(left: &Corpus, right: &Corpus) -> Result<Corpus> {
    Ok(Corpus {
        collections: merge_objects(
            &left.collections,
            &right.collections,
            |item| item.id.as_str(),
            "collection run",
        )?,
        observations: merge_objects(
            &left.observations,
            &right.observations,
            |item| item.id.as_str(),
            "observation",
        )?,
        schema_version: SCHEMA_VERSION.into(),
        sources: merge_sources(&left.sources, &right.sources)?,
    })
}

/// derive a corpus-only historical view without modifying accumulated evidence.
///
/// persisted evaluations should use [`as_of_with_provenance`].
///
/// # Errors
///
/// returns an error when an observation or collection timestamp is invalid.
pub fn as_of(corpus: &Corpus, at: OffsetDateTime) -> Result<Corpus> {
    let mut observations = corpus
        .observations
        .iter()
        .map(|observation| {
            crate::parse_timestamp(&observation.observed_at)
                .map(|observed_at| (observed_at <= at).then(|| observation.clone()))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    observations.sort_by(|left, right| left.id.cmp(&right.id));
    let observation_ids = observations
        .iter()
        .map(|observation| observation.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let source_ids = observations
        .iter()
        .map(|observation| observation.provenance.source_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut collections: Vec<_> = corpus
        .collections
        .iter()
        .map(|run| {
            crate::parse_timestamp(&run.completed_at).map(|completed_at| {
                (completed_at <= at).then(|| {
                    let mut run = run.clone();
                    run.observation_ids
                        .retain(|id| observation_ids.contains(id.as_str()));
                    run
                })
            })
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    collections.sort_by(|left, right| left.id.cmp(&right.id));
    let sources = corpus
        .sources
        .iter()
        .filter(|source| source_ids.contains(source.id.as_str()))
        .cloned()
        .collect();
    Ok(Corpus {
        collections,
        observations,
        schema_version: corpus.schema_version.clone(),
        sources,
    })
}

/// derive a referentially closed historical evidence graph.
///
/// the result contains evidence whose complete provenance was captured by `at`.
///
/// # Errors
///
/// returns an error for invalid timestamps or missing provenance references.
pub fn as_of_with_provenance(
    corpus: &Corpus,
    acquisitions: &[AcquisitionTranscript],
    executions: &[ExecutionTranscript],
    at: OffsetDateTime,
) -> Result<HistoricalEvidence> {
    let mut historical = as_of(corpus, at)?;
    let acquisition_times = acquisition_times(acquisitions)?;
    let execution_times = execution_times(executions)?;

    let mut available_collection_ids = std::collections::BTreeSet::new();
    for run in &historical.collections {
        let mut available = true;
        for transcript_id in &run.acquisition_transcript_ids {
            let captured_at = acquisition_times
                .get(transcript_id.as_str())
                .ok_or_else(|| {
                    Error::Provenance(format!(
                        "collection {} references missing acquisition transcript {transcript_id}",
                        run.id
                    ))
                })?;
            available &= *captured_at <= at;
        }
        if available {
            available_collection_ids.insert(run.id.clone());
        }
    }
    historical
        .collections
        .retain(|run| available_collection_ids.contains(&run.id));

    let all_collection_ids = corpus
        .collections
        .iter()
        .map(|run| run.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut observations = Vec::new();
    for observation in historical.observations {
        let collection_available = if let Some(run_id) = &observation.collection_run_id {
            if !all_collection_ids.contains(run_id.as_str()) {
                return Err(Error::Provenance(format!(
                    "observation {} references missing collection {run_id}",
                    observation.id
                )));
            }
            available_collection_ids.contains(run_id)
        } else {
            true
        };
        let mut executions_available = true;
        for transcript_id in &observation.execution_transcript_ids {
            let completed_at = execution_times.get(transcript_id.as_str()).ok_or_else(|| {
                Error::Provenance(format!(
                    "observation {} references missing execution transcript {transcript_id}",
                    observation.id
                ))
            })?;
            executions_available &= *completed_at <= at;
        }
        if collection_available && executions_available {
            observations.push(observation);
        }
    }
    let observation_ids = observations
        .iter()
        .map(|observation| observation.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for run in &mut historical.collections {
        run.observation_ids
            .retain(|id| observation_ids.contains(id.as_str()));
    }
    let source_ids = observations
        .iter()
        .map(|observation| observation.provenance.source_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    historical
        .sources
        .retain(|source| source_ids.contains(source.id.as_str()));
    historical.observations = observations;

    let acquisition_ids = historical
        .collections
        .iter()
        .flat_map(|run| run.acquisition_transcript_ids.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>();
    let execution_ids = historical
        .observations
        .iter()
        .flat_map(|observation| observation.execution_transcript_ids.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>();
    Ok(HistoricalEvidence {
        corpus: historical,
        acquisitions: acquisitions
            .iter()
            .filter(|transcript| acquisition_ids.contains(&transcript.id))
            .cloned()
            .collect(),
        executions: executions
            .iter()
            .filter(|transcript| execution_ids.contains(&transcript.id))
            .cloned()
            .collect(),
    })
}

fn acquisition_times(
    acquisitions: &[AcquisitionTranscript],
) -> Result<BTreeMap<&str, OffsetDateTime>> {
    acquisitions
        .iter()
        .map(|transcript| {
            crate::parse_timestamp(&transcript.contents.captured_at)
                .map(|captured_at| (transcript.id.as_str(), captured_at))
        })
        .collect()
}

fn execution_times(executions: &[ExecutionTranscript]) -> Result<BTreeMap<&str, OffsetDateTime>> {
    executions
        .iter()
        .map(|transcript| {
            crate::parse_timestamp(&transcript.contents.completed_at)
                .map(|completed_at| (transcript.id.as_str(), completed_at))
        })
        .collect()
}

/// return the single most recently observed release at or before an evaluation time.
///
/// # Errors
///
/// returns an error when no release evidence exists or equally recent evidence
/// identifies more than one release.
pub fn latest_release(corpus: &Corpus, at: OffsetDateTime) -> Result<String> {
    let mut candidates = Vec::new();
    for observation in &corpus.observations {
        let Some(release) = observation.subject.qualifier("release") else {
            continue;
        };
        let observed_at = crate::parse_timestamp(&observation.observed_at)?;
        if observed_at <= at {
            candidates.push((observed_at, release));
        }
    }
    let latest = candidates
        .iter()
        .map(|(observed_at, _)| *observed_at)
        .max()
        .ok_or_else(|| {
            Error::Invalid(
                "--release is required because repository state contains no release evidence"
                    .into(),
            )
        })?;
    let releases = candidates
        .iter()
        .filter(|(observed_at, _)| *observed_at == latest)
        .map(|(_, release)| *release)
        .collect::<std::collections::BTreeSet<_>>();
    if releases.len() != 1 {
        return Err(Error::Invalid(format!(
            "--release is required because equally recent evidence identifies: {}",
            releases.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    releases
        .into_iter()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| Error::Invalid("latest release selection was empty".into()))
}

fn merge_objects<T, F>(left: &[T], right: &[T], id: F, kind: &str) -> Result<Vec<T>>
where
    T: Clone + PartialEq,
    F: Fn(&T) -> &str,
{
    let mut objects = BTreeMap::<String, T>::new();
    for item in left.iter().chain(right) {
        let item_id = id(item).to_owned();
        if let Some(existing) = objects.get(&item_id) {
            if existing != item {
                return Err(Error::Invalid(format!("{kind} id collision: {item_id}")));
            }
        } else {
            objects.insert(item_id, item.clone());
        }
    }
    Ok(objects.into_values().collect())
}

fn merge_sources(left: &[SourceDocument], right: &[SourceDocument]) -> Result<Vec<SourceDocument>> {
    let mut sources = BTreeMap::<String, SourceDocument>::new();
    for source in left.iter().chain(right) {
        if let Some(existing) = sources.get(&source.id) {
            if existing.content != source.content
                || existing.sha256 != source.sha256
                || existing.format != source.format
                || existing.media_type != source.media_type
            {
                return Err(Error::Invalid(format!(
                    "source id collision: {}",
                    source.id
                )));
            }
        } else {
            sources.insert(source.id.clone(), source.clone());
        }
    }
    Ok(sources.into_values().collect())
}

#[must_use]
/// the corpus path inside a state directory.
pub fn corpus_path(root: &Path) -> PathBuf {
    root.join(CORPUS_FILE)
}

fn default_branch() -> String {
    "main".into()
}
