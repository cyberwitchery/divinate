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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collection_run_ids: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// the system of record this repository mirrors, when it is a mirror.
    pub mirror_of: Option<String>,
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
    let collection_run_ids = corpus
        .collections
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
            "collection run",
            &cycle.contents.collection_run_ids,
            &collection_run_ids,
        )?;
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
    crate::project::parse(&path, &bytes)?;
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

/// store verified pack invocations and their executable blobs. only the new
/// objects and their links are checked, not the stored graph.
///
/// # Errors
///
/// returns an error for invalid provenance, a content-address collision, or an
/// invocation naming a transcript that is not stored; nothing is written in
/// that case.
pub fn store_pack_invocations(root: &Path, captures: &[crate::pack::PackCapture]) -> Result<()> {
    store_objects(root, &[], captures)
}

/// load every retained pack invocation.
///
/// # Errors
///
/// returns an error when an invocation file is invalid.
pub fn load_pack_invocations(root: &Path) -> Result<Vec<crate::pack::PackInvocation>> {
    load_json_directory(&root.join("pack-invocations"))
}

/// append a corpus increment and acquisition transcripts.
///
/// # Errors
///
/// returns an error for invalid state, transcript integrity failure, a broken
/// provenance link, or collision; nothing is written in that case.
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
/// link, or a content-address collision; nothing is written in that case.
pub fn accumulate_with_executions(
    root: &Path,
    increment: &Corpus,
    transcripts: &[AcquisitionTranscript],
    executions: &[ExecutionCapture],
) -> Result<Corpus> {
    commit(
        root,
        Increment {
            corpus: Some(increment),
            acquisitions: transcripts,
            executions,
            packs: &[],
        },
    )
}

/// store an execution transcript and its content-addressed blobs immutably.
/// only the new objects are checked, not the stored graph.
///
/// # Errors
///
/// returns an error when integrity verification or immutable storage fails;
/// nothing is written in that case.
pub fn store_execution(root: &Path, capture: &ExecutionCapture) -> Result<()> {
    store_objects(root, std::slice::from_ref(capture), &[])
}

fn store_objects(
    root: &Path,
    executions: &[ExecutionCapture],
    packs: &[crate::pack::PackCapture],
) -> Result<()> {
    let mut stage = Stage::default();
    for capture in executions {
        stage.execution(root, capture)?;
    }
    for capture in packs {
        stage.pack(root, capture)?;
    }
    for capture in packs {
        crate::pack::check_transcript_links(
            &capture.invocation,
            |id| {
                stage.executions.iter().any(|item| item.id == id)
                    || is_stored(root, "executions", id)
            },
            |id| is_stored(root, "acquisitions", id),
        )?;
    }
    stage.write(root)
}

fn is_stored(root: &Path, directory: &str, id: &str) -> bool {
    root.join(directory).join(format!("{id}.json")).is_file()
}

/// one increment of evidence for [`commit`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Increment<'a> {
    /// merged into the stored corpus; `None` leaves `corpus.json` untouched.
    pub corpus: Option<&'a Corpus>,
    pub acquisitions: &'a [AcquisitionTranscript],
    pub executions: &'a [ExecutionCapture],
    pub packs: &'a [crate::pack::PackCapture],
}

/// stage an increment against the stored state, verify the merged graph, and
/// only then write it.
///
/// # Errors
///
/// returns an error for invalid state, integrity failure, a content-address
/// collision, or a broken provenance link; nothing is written in that case.
pub fn commit(root: &Path, increment: Increment<'_>) -> Result<Corpus> {
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
    let registry = if root.join(CONTRACTS_FILE).exists() {
        load_registry(root)?
    } else {
        ContractRegistry::default()
    };
    let mut stage = Stage::load(root)?;
    for transcript in increment.acquisitions {
        stage.acquisition(root, transcript, &registry)?;
    }
    for capture in increment.executions {
        stage.execution(root, capture)?;
    }
    for capture in increment.packs {
        stage.pack(root, capture)?;
    }
    let merged = increment
        .corpus
        .map(|corpus| merge(&base, corpus))
        .transpose()?;
    crate::provenance::verify_graph(
        crate::provenance::EvidenceGraph {
            corpus: merged.as_ref().unwrap_or(&base),
            acquisitions: &stage.acquisitions,
            executions: &stage.executions,
            pack_invocations: &stage.pack_invocations,
            blobs: &stage.blobs,
        },
        &registry,
    )?;
    stage.write(root)?;
    match merged {
        Some(merged) => {
            write_json(&merged, &corpus_path)?;
            Ok(merged)
        }
        None => Ok(base),
    }
}

#[derive(Default)]
struct Stage {
    acquisitions: Vec<AcquisitionTranscript>,
    executions: Vec<ExecutionTranscript>,
    pack_invocations: Vec<crate::pack::PackInvocation>,
    blobs: BTreeMap<String, Vec<u8>>,
    stored_acquisitions: usize,
    stored_executions: usize,
    stored_invocations: usize,
    new_blobs: Vec<String>,
}

impl Stage {
    fn load(root: &Path) -> Result<Self> {
        let acquisitions = load_transcripts(root)?;
        let executions = load_executions(root)?;
        let pack_invocations = load_pack_invocations(root)?;
        Ok(Self {
            stored_acquisitions: acquisitions.len(),
            stored_executions: executions.len(),
            stored_invocations: pack_invocations.len(),
            acquisitions,
            executions,
            pack_invocations,
            blobs: load_blobs(root)?,
            new_blobs: Vec::new(),
        })
    }

    fn acquisition(
        &mut self,
        root: &Path,
        transcript: &AcquisitionTranscript,
        registry: &ContractRegistry,
    ) -> Result<()> {
        if acquisition::assess(transcript, registry).integrity != IntegrityStatus::Verified {
            return Err(Error::Invalid(format!(
                "acquisition {} failed integrity verification",
                transcript.id
            )));
        }
        stage_object(
            &root.join("acquisitions"),
            &mut self.acquisitions,
            transcript,
            |item| item.id.as_str(),
            "acquisition",
        )
    }

    fn execution(&mut self, root: &Path, capture: &ExecutionCapture) -> Result<()> {
        execution::verify(&capture.transcript, &capture.blobs)?;
        for (digest, bytes) in &capture.blobs {
            if crate::hex_digest(bytes) != *digest {
                return Err(Error::Invalid(format!(
                    "execution capture contains misaddressed blob: {digest}"
                )));
            }
            self.blob(root, digest, bytes)?;
        }
        stage_object(
            &root.join("executions"),
            &mut self.executions,
            &capture.transcript,
            |item| item.id.as_str(),
            "execution",
        )
    }

    fn pack(&mut self, root: &Path, capture: &crate::pack::PackCapture) -> Result<()> {
        let digest = crate::hex_digest(&capture.executable_bytes);
        if digest != capture.invocation.contents.executable.sha256 {
            return Err(Error::Provenance("pack executable digest mismatch".into()));
        }
        self.blob(root, &digest, &capture.executable_bytes)?;
        crate::pack::verify_stored(&capture.invocation, &self.blobs)?;
        stage_object(
            &root.join("pack-invocations"),
            &mut self.pack_invocations,
            &capture.invocation,
            |item| item.id.as_str(),
            "pack invocation",
        )
    }

    fn blob(&mut self, root: &Path, digest: &str, bytes: &[u8]) -> Result<()> {
        let path = root.join("blobs").join(digest);
        if !self.blobs.contains_key(digest) && path.exists() {
            let stored = fs::read(&path).map_err(|source| Error::Io { path, source })?;
            self.blobs.insert(digest.to_owned(), stored);
        }
        match self.blobs.get(digest) {
            Some(existing) if existing != bytes => {
                Err(Error::Invalid(format!("blob collision: {digest}")))
            }
            Some(_) => Ok(()),
            None => {
                self.blobs.insert(digest.to_owned(), bytes.to_vec());
                self.new_blobs.push(digest.to_owned());
                Ok(())
            }
        }
    }

    fn write(&self, root: &Path) -> Result<()> {
        init(root)?;
        for digest in &self.new_blobs {
            let path = root.join("blobs").join(digest);
            fs::write(&path, &self.blobs[digest]).map_err(|source| Error::Io { path, source })?;
        }
        for transcript in &self.acquisitions[self.stored_acquisitions..] {
            write_json(
                transcript,
                &root
                    .join("acquisitions")
                    .join(format!("{}.json", transcript.id)),
            )?;
        }
        for transcript in &self.executions[self.stored_executions..] {
            write_json(
                transcript,
                &root
                    .join("executions")
                    .join(format!("{}.json", transcript.id)),
            )?;
        }
        for invocation in &self.pack_invocations[self.stored_invocations..] {
            write_json(
                invocation,
                &root
                    .join("pack-invocations")
                    .join(format!("{}.json", invocation.id)),
            )?;
        }
        Ok(())
    }
}

fn stage_object<T, F>(
    directory: &Path,
    items: &mut Vec<T>,
    item: &T,
    id: F,
    kind: &str,
) -> Result<()>
where
    T: Clone + PartialEq + serde::de::DeserializeOwned,
    F: Fn(&T) -> &str,
{
    let path = directory.join(format!("{}.json", id(item)));
    let same = match items.iter().find(|existing| id(existing) == id(item)) {
        Some(existing) => existing == item,
        None if path.exists() => read_json::<T>(&path)? == *item,
        None => {
            items.push(item.clone());
            return Ok(());
        }
    };
    if same {
        Ok(())
    } else {
        Err(Error::Invalid(format!("{kind} id collision: {}", id(item))))
    }
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
/// # Errors
///
/// returns an error when an observation or collection timestamp is invalid.
fn as_of(corpus: &Corpus, at: OffsetDateTime) -> Result<Corpus> {
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

const fn required_source() -> bool {
    true
}
