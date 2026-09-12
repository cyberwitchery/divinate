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
use serde_json::Value;
use time::OffsetDateTime;

/// the accumulated corpus, relative to the state directory.
pub const CORPUS_FILE: &str = "corpus.json";
/// the current contract invalidations, relative to the state directory.
pub const CONTRACTS_FILE: &str = "contracts.json";
/// the legacy live configuration filename, retained for migration only.
pub const CONFIG_FILE: &str = "config.json";
/// the repository identity bound to this evidence state.
pub const REPOSITORY_FILE: &str = "repository.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// the repository identity bound to an evidence directory.
pub struct RepositoryState {
    pub repository: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// one source result recorded for a configured collection cycle.
pub struct SourceCollectionRecord {
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// immutable links between one collection cycle and its project configuration.
pub struct CollectionCycle {
    pub id: String,
    pub schema_version: String,
    pub contents: CollectionCycleContents,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// the configuration and evidence identities used by one collection cycle.
pub struct CollectionCycleContents {
    pub repository: String,
    pub branch: String,
    pub project_config_sha256: String,
    pub sources: BTreeMap<String, SourceCollectionRecord>,
    pub observation_ids: Vec<String>,
    pub execution_transcript_ids: Vec<String>,
    pub pack_invocation_ids: Vec<String>,
    pub completed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// the project configuration used for one saved evaluation.
pub struct EvaluationConfiguration {
    pub project_config_sha256: String,
}

#[derive(Debug, Clone, PartialEq)]
/// a referentially closed view: a corpus and exactly the provenance justifying it.
pub struct HistoricalEvidence {
    pub corpus: Corpus,
    pub acquisitions: Vec<AcquisitionTranscript>,
    pub executions: Vec<ExecutionTranscript>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// repository identity, branch, packs, and recurring evidence sources.
pub struct ProjectConfig {
    pub repository: String,
    #[serde(default = "default_branch")]
    pub branch: String,
    #[serde(default)]
    pub packs: BTreeMap<String, crate::pack::PackConfig>,
    #[serde(default)]
    pub sources: BTreeMap<String, SourceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// one evidence source enabled for routine collection.
pub struct SourceConfig {
    pub provider: SourceProvider,
    #[serde(default)]
    pub configuration: Value,
    #[serde(default)]
    pub context: SourceContext,
    #[serde(default = "enabled_source")]
    pub enabled: bool,
    #[serde(default = "required_source")]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// the built-in source or pack collector behind an evidence source.
pub enum SourceProvider {
    Builtin { source: String },
    Pack { pack: String, collector: String },
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// whether a source receives repository or release collection context.
pub enum SourceContext {
    #[default]
    Repository,
    Release,
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
        "project-configs",
        "collection-cycles",
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

/// bind an evidence directory to one repository identity.
///
/// # Errors
///
/// returns an error when existing state names another repository.
pub fn ensure_repository_identity(root: &Path, repository: &str) -> Result<()> {
    init(root)?;
    let path = root.join(REPOSITORY_FILE);
    if path.exists() {
        let state: RepositoryState = read_json(&path)?;
        if state.repository != repository {
            return Err(Error::Provenance(format!(
                "evidence state identifies repository {}, not {repository}",
                state.repository
            )));
        }
        return Ok(());
    }
    let legacy = root.join(CONFIG_FILE);
    if legacy.exists() {
        let state: ProjectConfig = read_json(&legacy)?;
        if state.repository != repository {
            return Err(Error::Provenance(format!(
                "evidence state identifies repository {}, not {repository}",
                state.repository
            )));
        }
    }
    write_json(
        &RepositoryState {
            repository: repository.into(),
        },
        &path,
    )
}

/// retain exact checked-in project configuration bytes by digest.
///
/// # Errors
///
/// returns an error for a digest mismatch, collision, or write failure.
pub fn store_project_configuration(root: &Path, sha256: &str, bytes: &[u8]) -> Result<()> {
    init(root)?;
    if crate::hex_digest(bytes) != sha256 {
        return Err(Error::Provenance(
            "project configuration digest mismatch".into(),
        ));
    }
    let path = root.join("project-configs").join(format!("{sha256}.yaml"));
    if path.exists() {
        let existing = fs::read(&path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        if existing != bytes {
            return Err(Error::Invalid(format!(
                "project configuration collision: {sha256}"
            )));
        }
    } else {
        fs::write(&path, bytes).map_err(|source| Error::Io { path, source })?;
    }
    Ok(())
}

/// construct and retain one immutable configured collection cycle.
///
/// # Errors
///
/// returns an error for invalid identity, collisions, or write failure.
pub fn store_collection_cycle(
    root: &Path,
    contents: CollectionCycleContents,
) -> Result<CollectionCycle> {
    init(root)?;
    let identity = serde_json::to_value(&contents).map_err(Error::Serialize)?;
    let digest = crate::hex_digest(&crate::canonical_json(&identity)?);
    let cycle = CollectionCycle {
        id: format!("cycle_{}", &digest[..20]),
        schema_version: crate::SCHEMA_VERSION.into(),
        contents,
    };
    let path = root
        .join("collection-cycles")
        .join(format!("{}.json", cycle.id));
    if path.exists() {
        let existing: CollectionCycle = read_json(&path)?;
        if existing != cycle {
            return Err(Error::Invalid(format!(
                "collection cycle id collision: {}",
                cycle.id
            )));
        }
    } else {
        write_json(&cycle, &path)?;
    }
    Ok(cycle)
}

/// load retained configured collection cycles in deterministic order.
///
/// # Errors
///
/// returns an error when a cycle cannot be read.
pub fn load_collection_cycles(root: &Path) -> Result<Vec<CollectionCycle>> {
    load_json_directory(&root.join("collection-cycles"))
}

/// verify retained project configuration snapshots and their collection links.
///
/// # Errors
///
/// returns an error for altered configuration, cycle identity, or missing links.
pub fn verify_configuration_provenance(
    root: &Path,
    corpus: &crate::model::Corpus,
    executions: &[ExecutionTranscript],
    invocations: &[crate::pack::PackInvocation],
) -> Result<usize> {
    let cycles = load_collection_cycles(root)?;
    let observation_ids = corpus
        .observations
        .iter()
        .map(|item| item.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let execution_ids = executions
        .iter()
        .map(|item| item.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let invocation_ids = invocations
        .iter()
        .map(|item| item.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for cycle in &cycles {
        if cycle.schema_version != crate::SCHEMA_VERSION {
            return Err(Error::Provenance(format!(
                "collection cycle {} uses unsupported schema {}",
                cycle.id, cycle.schema_version
            )));
        }
        let identity = serde_json::to_value(&cycle.contents).map_err(Error::Serialize)?;
        let digest = crate::hex_digest(&crate::canonical_json(&identity)?);
        if cycle.id != format!("cycle_{}", &digest[..20]) {
            return Err(Error::Provenance(format!(
                "collection cycle identity mismatch: {}",
                cycle.id
            )));
        }
        verify_project_configuration(root, &cycle.contents.project_config_sha256)?;
        verify_references(
            "observation",
            &cycle.contents.observation_ids,
            &observation_ids,
        )?;
        verify_references(
            "execution transcript",
            &cycle.contents.execution_transcript_ids,
            &execution_ids,
        )?;
        verify_references(
            "pack invocation",
            &cycle.contents.pack_invocation_ids,
            &invocation_ids,
        )?;
    }
    verify_evaluation_configurations(root)?;
    Ok(cycles.len())
}

fn verify_project_configuration(root: &Path, sha256: &str) -> Result<()> {
    let path = root.join("project-configs").join(format!("{sha256}.yaml"));
    let bytes = fs::read(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    if crate::hex_digest(&bytes) != sha256 {
        return Err(Error::Provenance(format!(
            "project configuration digest mismatch: {sha256}"
        )));
    }
    serde_yaml_ng::from_slice::<crate::project::ProjectFile>(&bytes)
        .map_err(|source| Error::Yaml { path, source })?;
    Ok(())
}

fn verify_references(
    kind: &str,
    references: &[String],
    available: &std::collections::BTreeSet<&str>,
) -> Result<()> {
    if let Some(missing) = references
        .iter()
        .find(|reference| !available.contains(reference.as_str()))
    {
        return Err(Error::Provenance(format!(
            "collection cycle references missing {kind} {missing}"
        )));
    }
    Ok(())
}

fn verify_evaluation_configurations(root: &Path) -> Result<()> {
    let directory = root.join("assertions");
    if !directory.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&directory).map_err(|source| Error::Io {
        path: directory.clone(),
        source,
    })? {
        let path = entry
            .map_err(|source| Error::Io {
                path: directory.clone(),
                source,
            })?
            .path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".configuration.json"))
        {
            continue;
        }
        let reference: EvaluationConfiguration = read_json(&path)?;
        verify_project_configuration(root, &reference.project_config_sha256)?;
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

/// load the pre-YAML project configuration for migration.
///
/// # Errors
///
/// returns an error when configuration is absent or invalid.
pub fn load_legacy_config(root: &Path) -> Result<ProjectConfig> {
    let path = root.join(CONFIG_FILE);
    if !path.exists() {
        return Err(Error::Invalid(format!(
            "missing legacy configuration {}",
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

const fn enabled_source() -> bool {
    true
}

const fn required_source() -> bool {
    true
}
