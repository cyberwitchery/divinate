//! release dependency collection.
//!
//! [`collect`] resolves release tags, validates sbom identities, and records
//! `sbom-diff` and its policy gate as separate executions. both observations must
//! agree on the releases, revisions, and diff digest. execution completion sets the
//! observation time.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::adapters::adapt;
use crate::error::{Error, Result};
use crate::execution::{self, ExecutionCapture, ExecutionRequest, ExecutionTranscript, NamedPath};
use crate::model::{Corpus, Observation, Producer, Provenance, SourceDocument, Subject};
use crate::{canonical_json, hex_digest, SCHEMA_VERSION};

#[derive(Debug, Clone)]
/// the two releases to compare, their sboms, and the tool and policy to record.
pub struct ReleaseRequest {
    pub repository: String,
    pub repository_path: PathBuf,
    pub base_release: String,
    pub release: String,
    pub expected_base_revision: Option<String>,
    pub expected_revision: Option<String>,
    pub base_sbom: PathBuf,
    pub target_sbom: PathBuf,
    pub executable: PathBuf,
    pub reported_version: Option<String>,
    pub policy_id: String,
    pub fail_on: String,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize)]
/// what the collection bound: resolved revisions, executions, and observations.
pub struct ReleaseResult {
    pub repository: String,
    pub base_release: String,
    pub base_revision: String,
    pub release: String,
    pub revision: String,
    pub diff_execution_id: String,
    pub gate_execution_id: String,
    pub reused_executions: Vec<String>,
    pub observation_ids: Vec<String>,
}

#[derive(Debug, Clone)]
/// the derived corpus, the executions behind it, and the binding result.
pub struct ReleaseCapture {
    pub corpus: Corpus,
    pub executions: Vec<ExecutionCapture>,
    pub result: ReleaseResult,
}

/// collect the baseline release dependency evidence without a user-authored manifest.
///
/// # Errors
///
/// returns a provenance error when release, sbom, execution, policy, or output
/// identities cannot be bound exactly.
pub fn collect(
    request: &ReleaseRequest,
    existing: &[ExecutionTranscript],
    blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<ReleaseCapture> {
    validate_request(request)?;
    validate_repository_identity(&request.repository_path, &request.repository)?;
    let base_revision = resolve_release(&request.repository_path, &request.base_release)?;
    let revision = resolve_release(&request.repository_path, &request.release)?;
    if request
        .expected_base_revision
        .as_deref()
        .is_some_and(|expected| expected != base_revision)
    {
        return provenance(format!(
            "base release {} resolves to {base_revision}, not expected revision {}",
            request.base_release,
            request
                .expected_base_revision
                .as_deref()
                .unwrap_or_default()
        ));
    }
    if request
        .expected_revision
        .as_deref()
        .is_some_and(|expected| expected != revision)
    {
        return provenance(format!(
            "release {} resolves to {revision}, not expected revision {}",
            request.release,
            request.expected_revision.as_deref().unwrap_or_default()
        ));
    }
    if base_revision == revision {
        return provenance("base and target releases resolve to the same revision");
    }
    validate_sbom(
        &request.base_sbom,
        &request.repository,
        &request.base_release,
    )?;
    validate_sbom(&request.target_sbom, &request.repository, &request.release)?;

    let diff_request = tool_request(request, false);
    let (diff, diff_reused) = capture_or_reuse(&diff_request, request.force, existing, blobs)?;
    if !diff.transcript.contents.exit.success {
        return provenance(format!(
            "sbom-diff execution failed with exit {:?}",
            diff.transcript.contents.exit.code
        ));
    }
    let diff_bytes = execution::stdout_bytes(&diff.transcript)?;
    serde_json::from_slice::<serde_json::Value>(&diff_bytes)
        .map_err(|error| Error::Provenance(format!("sbom-diff output is not json: {error}")))?;

    let gate_request = tool_request(request, true);
    let (gate, gate_reused) = capture_or_reuse(&gate_request, request.force, existing, blobs)?;
    let gate_bytes = execution::stdout_bytes(&gate.transcript)?;
    if hex_digest(&gate_bytes) != hex_digest(&diff_bytes) {
        return provenance("gate output does not match the recorded dependency diff");
    }
    let gate_code = gate.transcript.contents.exit.code.ok_or_else(|| {
        Error::Provenance("gate execution ended without a numeric exit status".into())
    })?;
    if !matches!(gate_code, 0 | 2 | 3) {
        return provenance(format!(
            "gate execution failed with non-policy exit {gate_code}"
        ));
    }

    let corpus = derived_corpus(
        request,
        (&base_revision, &revision),
        &diff,
        &gate,
        &diff_bytes,
        gate_code,
    )?;
    let mut reused_executions = Vec::new();
    if diff_reused {
        reused_executions.push(diff.transcript.id.clone());
    }
    if gate_reused {
        reused_executions.push(gate.transcript.id.clone());
    }
    let observation_ids = corpus
        .observations
        .iter()
        .map(|observation| observation.id.clone())
        .collect();
    Ok(ReleaseCapture {
        corpus,
        executions: vec![diff.clone(), gate.clone()],
        result: ReleaseResult {
            repository: request.repository.clone(),
            base_release: request.base_release.clone(),
            base_revision,
            release: request.release.clone(),
            revision,
            diff_execution_id: diff.transcript.id,
            gate_execution_id: gate.transcript.id,
            reused_executions,
            observation_ids,
        },
    })
}

fn derived_corpus(
    request: &ReleaseRequest,
    revisions: (&str, &str),
    diff: &ExecutionCapture,
    gate: &ExecutionCapture,
    diff_bytes: &[u8],
    gate_code: i32,
) -> Result<Corpus> {
    let (base_revision, revision) = revisions;
    let subject = release_subject(request, base_revision, revision);
    let observed_at = &gate.transcript.contents.completed_at;
    let diff_source = source(
        diff_bytes,
        "sbom-diff",
        &format!("execution:{}:stdout", diff.transcript.id),
    )?;
    let diff_observation = observation(
        "sbom-diff",
        diff_bytes,
        &diff_source,
        &diff.transcript,
        &subject,
        observed_at,
        request,
    )?;
    let gate_bytes = gate_result_bytes(
        request,
        base_revision,
        revision,
        &diff_source.sha256,
        &gate.transcript,
        gate_code == 0,
    )?;
    let gate_source = source(
        &gate_bytes,
        "supply-chain-gate",
        &format!("execution:{}:exit", gate.transcript.id),
    )?;
    let gate_observation = observation(
        "supply-chain-gate",
        &gate_bytes,
        &gate_source,
        &gate.transcript,
        &subject,
        observed_at,
        request,
    )?;
    Ok(Corpus {
        collections: vec![],
        observations: vec![diff_observation, gate_observation],
        schema_version: SCHEMA_VERSION.into(),
        sources: vec![diff_source, gate_source],
    })
}

fn tool_request(request: &ReleaseRequest, gate: bool) -> ExecutionRequest {
    let mut argv = vec![
        request.base_sbom.to_string_lossy().into_owned(),
        request.target_sbom.to_string_lossy().into_owned(),
        "-o".into(),
        "json".into(),
    ];
    if gate {
        argv.extend(["--fail-on".into(), request.fail_on.clone()]);
    }
    ExecutionRequest {
        tool_name: "sbom-diff".into(),
        reported_version: request.reported_version.clone(),
        executable: request.executable.clone(),
        argv,
        working_directory: None,
        environment: BTreeMap::new(),
        inputs: vec![
            NamedPath {
                name: "base".into(),
                path: request.base_sbom.clone(),
            },
            NamedPath {
                name: "target".into(),
                path: request.target_sbom.clone(),
            },
        ],
        outputs: vec![],
    }
}

fn capture_or_reuse(
    request: &ExecutionRequest,
    force: bool,
    existing: &[ExecutionTranscript],
    blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<(ExecutionCapture, bool)> {
    if !force {
        let mut matching = Vec::new();
        for transcript in existing {
            if execution::matches_request(transcript, request)? {
                execution::verify(transcript, blobs)?;
                matching.push(transcript);
            }
        }
        if let Some(transcript) = matching
            .into_iter()
            .max_by_key(|transcript| &transcript.contents.completed_at)
        {
            return Ok((
                ExecutionCapture {
                    transcript: transcript.clone(),
                    blobs: blobs.clone(),
                },
                true,
            ));
        }
    }
    execution::capture(request).map(|capture| (capture, false))
}

fn resolve_release(repository: &Path, release: &str) -> Result<String> {
    let reference = format!("{release}^{{commit}}");
    let output = Command::new("git")
        .args(["-C"])
        .arg(repository)
        .args(["rev-parse", "--verify", &reference])
        .output()
        .map_err(|error| Error::Provenance(format!("cannot run git: {error}")))?;
    if !output.status.success() {
        return provenance(format!(
            "release {release:?} cannot be resolved in {}",
            repository.display()
        ));
    }
    let revision = String::from_utf8(output.stdout)
        .map_err(|_| Error::Provenance("git returned a non-utf8 revision".into()))?
        .trim()
        .to_owned();
    if !matches!(revision.len(), 40 | 64) || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return provenance(format!("git returned invalid revision {revision:?}"));
    }
    Ok(revision)
}

fn validate_repository_identity(repository: &Path, expected: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["-C"])
        .arg(repository)
        .args(["remote", "get-url", "origin"])
        .output()
        .map_err(|error| Error::Provenance(format!("cannot inspect git origin: {error}")))?;
    if !output.status.success() {
        return provenance(format!(
            "repository {} has no resolvable origin",
            repository.display()
        ));
    }
    let origin = String::from_utf8(output.stdout)
        .map_err(|_| Error::Provenance("git origin is not utf-8".into()))?;
    let actual = github_identity(origin.trim()).ok_or_else(|| {
        Error::Provenance(format!(
            "git origin {:?} is not a supported github url",
            origin.trim()
        ))
    })?;
    if actual != expected {
        return provenance(format!(
            "repository path resolves to {actual}, not configured repository {expected}"
        ));
    }
    Ok(())
}

fn github_identity(origin: &str) -> Option<String> {
    let path = origin
        .strip_prefix("git@github.com:")
        .or_else(|| origin.strip_prefix("https://github.com/"))
        .or_else(|| origin.strip_prefix("ssh://git@github.com/"))?;
    let path = path.strip_suffix(".git").unwrap_or(path).trim_matches('/');
    (path.split('/').count() == 2).then(|| format!("github:{path}"))
}

fn validate_request(request: &ReleaseRequest) -> Result<()> {
    if request.repository.trim().is_empty()
        || request.base_release.trim().is_empty()
        || request.release.trim().is_empty()
        || request.policy_id.trim().is_empty()
    {
        return provenance("release binding fields must not be empty");
    }
    if request.fail_on != "added-components" {
        return provenance(format!(
            "baseline policy requires --fail-on added-components, got {:?}",
            request.fail_on
        ));
    }
    Ok(())
}

fn validate_sbom(path: &Path, repository: &str, release: &str) -> Result<()> {
    let bytes = fs::read(path).map_err(|error| {
        Error::Provenance(format!("cannot read SBOM {}: {error}", path.display()))
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        Error::Provenance(format!("SBOM {} is not json: {error}", path.display()))
    })?;
    let actual_version = value
        .pointer("/metadata/component/version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::Provenance(format!(
                "SBOM {} has no metadata component version",
                path.display()
            ))
        })?;
    let expected_version = release.strip_prefix('v').unwrap_or(release);
    if actual_version != expected_version {
        return provenance(format!(
            "SBOM {} identifies version {actual_version:?}, not release {release:?}",
            path.display()
        ));
    }
    let expected_name = repository.rsplit('/').next().unwrap_or(repository);
    let actual_name = value
        .pointer("/metadata/component/name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::Provenance(format!(
                "SBOM {} has no metadata component name",
                path.display()
            ))
        })?;
    if actual_name != expected_name {
        return provenance(format!(
            "SBOM {} identifies component {actual_name:?}, not repository {expected_name:?}",
            path.display()
        ));
    }
    Ok(())
}

fn release_subject(request: &ReleaseRequest, base_revision: &str, revision: &str) -> Subject {
    Subject {
        kind: "release".into(),
        id: format!("{}:{}", request.repository, request.release),
        qualifiers: BTreeMap::from([
            ("repository".into(), request.repository.clone().into()),
            ("release".into(), request.release.clone().into()),
            ("base_release".into(), request.base_release.clone().into()),
            ("base_revision".into(), base_revision.into()),
            ("revision".into(), revision.into()),
        ]),
    }
}

fn source(bytes: &[u8], format: &str, path: &str) -> Result<SourceDocument> {
    let content = String::from_utf8(bytes.to_vec())
        .map_err(|_| Error::Provenance(format!("{format} output is not utf-8")))?;
    let sha256 = hex_digest(bytes);
    Ok(SourceDocument {
        content,
        format: format.into(),
        id: format!("src_{}", &sha256[..20]),
        media_type: "application/json".into(),
        path: path.into(),
        sha256,
    })
}

fn observation(
    adapter: &str,
    bytes: &[u8],
    source: &SourceDocument,
    execution: &ExecutionTranscript,
    subject: &Subject,
    observed_at: &str,
    request: &ReleaseRequest,
) -> Result<Observation> {
    let payload = serde_json::from_slice(bytes)
        .map_err(|error| Error::Provenance(format!("{adapter} output is not json: {error}")))?;
    let normalized = adapt(adapter, &payload, subject)?;
    let identity = serde_json::json!({
        "adapter": adapter,
        "claim_key": normalized.claim_key,
        "collection_run": null,
        "execution_transcripts": [execution.id],
        "observed_at": observed_at,
        "source_sha256": source.sha256,
        "subject": subject,
    });
    let digest = hex_digest(&canonical_json(&identity)?);
    Ok(Observation {
        claim_key: normalized.claim_key,
        collection_run_id: None,
        execution_transcript_ids: vec![execution.id.clone()],
        pack_invocation_ids: vec![],
        data: normalized.data,
        evidence_class: normalized.evidence_class,
        id: format!("ev_{}", &digest[..20]),
        kind: normalized.kind,
        observed_at: observed_at.into(),
        producer: Producer {
            name: "sbom-diff".into(),
            version: request.reported_version.clone().unwrap_or_else(|| {
                format!(
                    "sha256:{}",
                    &execution.contents.tool.executable.sha256[..12]
                )
            }),
            collector: format!("divinate/{adapter}"),
        },
        provenance: Provenance {
            pointer: if adapter == "supply-chain-gate" {
                "/execution"
            } else {
                ""
            }
            .into(),
            source_id: source.id.clone(),
        },
        severity: normalized.severity,
        status: normalized.status,
        subject: subject.clone(),
    })
}

fn gate_result_bytes(
    request: &ReleaseRequest,
    base_revision: &str,
    revision: &str,
    diff_sha256: &str,
    transcript: &ExecutionTranscript,
    passed: bool,
) -> Result<Vec<u8>> {
    let mut tool = serde_json::Map::from_iter([("name".into(), "sbom-diff".into())]);
    if let Some(version) = &request.reported_version {
        tool.insert("version".into(), version.clone().into());
    }
    let violations = if passed {
        vec![]
    } else {
        vec![
            serde_json::json!({"rule": request.fail_on, "exit_code": transcript.contents.exit.code}),
        ]
    };
    let value = serde_json::json!({
        "tool": tool,
        "policy": {"id": request.policy_id, "rules": ["no-added-components"]},
        "input": {
            "sbom_diff_sha256": diff_sha256,
            "base_revision": base_revision,
            "target_revision": revision,
        },
        "execution": {"transcript_id": transcript.id, "result_from": "exit_status"},
        "passed": passed,
        "violations": violations,
    });
    let mut bytes = serde_json::to_vec_pretty(&value).map_err(Error::Serialize)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn provenance<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Provenance(message.into()))
}
