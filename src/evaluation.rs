//! the evaluation pipeline.
//!
//! [`evaluate`] verifies a state's evidence graph, derives core and pack
//! assertions from the evidence available at the evaluation time, and stores
//! them with a dossier under a label.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::assertions::{self, EvaluationTarget};
use crate::dossier;
use crate::error::{provenance_error, Error, Result};
use crate::workflow::ProjectConfig;
use crate::{load_corpus, parse_timestamp, read_json, write_json};

/// what to evaluate; unset fields default to the project configuration.
#[derive(Debug, Clone)]
pub struct EvaluationRequest {
    pub repository: Option<String>,
    pub branch: Option<String>,
    /// release tag; `None` evaluates the repository.
    pub release: Option<String>,
    pub from: String,
    pub until: String,
    /// evaluation time; selects the evidence available then. defaults to now.
    pub at: Option<String>,
}

/// [`evaluate`] with the configuration in `repository_path`.
///
/// binds `state` to the configured repository and stores the configuration
/// bytes before evaluating.
///
/// # Errors
///
/// returns an error when the configuration cannot be loaded, the state belongs
/// to another repository, or [`evaluate`] fails.
pub fn evaluate_repository(
    state: &Path,
    repository_path: &Path,
    label: &str,
    contracts: Option<&Path>,
    request: EvaluationRequest,
) -> Result<()> {
    let project = crate::project::load(repository_path)?;
    crate::workflow::ensure_repository_identity(state, &project.config.repository)?;
    crate::workflow::store_project_configuration(state, &project.sha256, &project.bytes)?;
    evaluate(
        state,
        &project.config,
        Some(&project.sha256),
        label,
        contracts,
        request,
        &BTreeSet::new(),
    )
}

/// evaluate `state` and store the assertions and dossier as `label`.
///
/// the label, the stored evidence graph and the links from pack assertions to
/// their invocations are checked before anything is written. `contracts`
/// replaces the stored contract registry; packs in `unavailable_optional_packs`
/// are skipped.
///
/// # Errors
///
/// returns an error for an invalid label or timestamp, a broken evidence graph,
/// a failing or misidentified pack, a duplicate assertion id, or a failed write.
#[allow(clippy::too_many_lines)]
pub fn evaluate(
    state: &Path,
    project: &ProjectConfig,
    project_config_sha256: Option<&str>,
    label: &str,
    contracts: Option<&Path>,
    request: EvaluationRequest,
    unavailable_optional_packs: &BTreeSet<String>,
) -> Result<()> {
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::Invalid(
            "evaluation label must contain only letters, numbers, '-' or '_'".into(),
        ));
    }
    let corpus = load_corpus(&crate::workflow::corpus_path(state))?;
    let at = request.at.as_ref().map_or_else(
        || Ok(time::OffsetDateTime::now_utc()),
        |value| parse_timestamp(value),
    )?;
    let transcripts = crate::workflow::load_transcripts(state)?;
    let executions = crate::workflow::load_executions(state)?;
    let blobs = crate::workflow::load_blobs(state).map_err(provenance_error)?;
    let registry = contracts.map_or_else(|| crate::workflow::load_registry(state), read_json)?;
    let pack_invocations = crate::workflow::load_pack_invocations(state)?;
    crate::provenance::verify_graph(
        crate::provenance::EvidenceGraph {
            corpus: &corpus,
            acquisitions: &transcripts,
            executions: &executions,
            pack_invocations: &pack_invocations,
            blobs: &blobs,
        },
        &registry,
    )
    .map_err(provenance_error)?;
    let historical =
        crate::workflow::as_of_with_provenance(&corpus, &transcripts, &executions, at)?;
    let target = evaluation_in_project(project, request);
    crate::provenance::verify_execution_links(&historical.corpus, &historical.executions, &blobs)
        .map_err(provenance_error)?;
    let current = crate::provenance::with_current_authority(
        &historical.corpus,
        &historical.acquisitions,
        &registry,
    )
    .map_err(provenance_error)?;
    let current = match &project.mirror_of {
        Some(upstream) => {
            crate::provenance::with_declared_mirror(&current, &project.repository, upstream)
        }
        None => current,
    };
    let mut assertions = assertions::evaluate_all(&current, &target, at)?;
    let evaluated_at = assertions
        .first()
        .map(|assertion| assertion.evaluated_at.clone())
        .ok_or_else(|| Error::Invalid("core evaluation returned no assertions".into()))?;
    let mut pack_captures = Vec::new();
    for (configured_id, config) in &project.packs {
        if unavailable_optional_packs.contains(configured_id) {
            continue;
        }
        let (metadata, described) = crate::pack::describe(config)?;
        if metadata.id != *configured_id {
            return Err(Error::Invalid(format!(
                "configured pack {configured_id:?} identifies itself as {:?}",
                metadata.id
            )));
        }
        if !metadata.evaluators.is_empty() {
            pack_captures.push(described);
        }
        for evaluator in &metadata.evaluators {
            let (mut derived, capture) = crate::pack::evaluate(
                config,
                &metadata,
                evaluator,
                &current,
                &target,
                &evaluated_at,
            )?;
            pack_captures.push(capture);
            assertions.append(&mut derived);
        }
    }
    let mut assertion_ids = BTreeSet::new();
    if let Some(duplicate) = assertions
        .iter()
        .find(|assertion| !assertion_ids.insert(assertion.id.as_str()))
    {
        return Err(Error::Invalid(format!(
            "duplicate assertion id: {}",
            duplicate.id
        )));
    }
    let staged = pack_captures
        .iter()
        .map(|capture| capture.invocation.clone())
        .collect::<Vec<_>>();
    let mut executables = BTreeMap::new();
    for capture in &pack_captures {
        executables
            .entry(capture.invocation.contents.executable.sha256.clone())
            .or_insert_with(|| capture.executable_bytes.clone());
    }
    crate::pack::verify_assertion_links(&assertions, &staged, &executables)?;
    crate::workflow::store_pack_invocations(state, &pack_captures)?;
    let dossier = dossier::build_with_registry(
        &current,
        &assertions,
        &historical.acquisitions,
        &registry,
        &target,
        at,
    )?;
    write_json(
        &assertions,
        &state.join("assertions").join(format!("{label}.json")),
    )?;
    write_json(
        &registry,
        &state
            .join("assertions")
            .join(format!("{label}.contracts.json")),
    )?;
    if let Some(sha256) = project_config_sha256 {
        write_json(
            &crate::workflow::EvaluationConfiguration {
                project_config_sha256: sha256.into(),
            },
            &state
                .join("assertions")
                .join(format!("{label}.configuration.json")),
        )?;
    }
    write_json(
        &dossier,
        &state.join("dossiers").join(format!("{label}.json")),
    )?;
    let markdown = state.join("dossiers").join(format!("{label}.md"));
    std::fs::write(&markdown, dossier::render_markdown(&dossier)).map_err(|source| Error::Io {
        path: markdown,
        source,
    })
}

fn evaluation_in_project(config: &ProjectConfig, request: EvaluationRequest) -> EvaluationTarget {
    let repository = request
        .repository
        .unwrap_or_else(|| config.repository.clone());
    EvaluationTarget {
        mirror_of: (repository == config.repository)
            .then(|| config.mirror_of.clone())
            .flatten(),
        repository,
        branch: request.branch.unwrap_or_else(|| config.branch.clone()),
        release: request.release,
        from: request.from,
        until: request.until,
    }
}
