//! external pack protocol.
//!
//! packs implement `describe`, `collect`, `normalize`, and `evaluate` through
//! one json request and response. core executes command plans, assigns evidence
//! identity, persists state, and verifies declared coverage.
//!
//! [`PackInvocation`] retains executable identity and exact protocol data. packs
//! define source-specific semantics and run unsandboxed with a cleared environment,
//! temporary working directory, omitted state path, and timeout.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::assertions::{
    AssertionSubject, AssertionType, Derivation, DerivedAssertion, EvaluationTarget, EvidenceUse,
    IdentityJoin, MissingEvidence, Outcome, ReasonStep, Validity,
};
use crate::coverage::{self, CoverageDecision, CoverageOutcome};
use crate::error::{Error, Result};
use crate::execution::{BlobRef, ExecutionRequest, NamedPath};
use crate::model::{EvidenceClass, ObservationKind, Proposition, Severity, Status, Subject};
use crate::{canonical_json, hex_digest};

/// the pack protocol version this build speaks.
///
/// breaking changes use a new integer version.
pub const PROTOCOL_VERSION: u8 = 1;
/// the pack invocation format version this build writes.
pub const TRANSCRIPT_SCHEMA_VERSION: &str = "0.1.0";
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// where a pack executable lives, its configuration, and its timeout.
pub struct PackConfig {
    pub executable: PathBuf,
    #[serde(default)]
    pub configuration: Value,
    #[serde(default = "default_timeout_seconds")]
    /// how long one operation may run before it is terminated.
    pub timeout_seconds: u64,
}

const fn default_timeout_seconds() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// what a pack says it provides.
///
/// evaluator input and coverage declarations.
pub struct PackMetadata {
    pub id: String,
    pub version: String,
    pub protocol_version: u8,
    #[serde(default)]
    pub collectors: Vec<String>,
    #[serde(default)]
    pub evaluators: Vec<String>,
    #[serde(default)]
    /// claim keys visible to each evaluator.
    pub evaluator_inputs: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    /// propositions visible to and required from each evaluator.
    pub evaluator_propositions: BTreeMap<String, Vec<Proposition>>,
    #[serde(default)]
    pub source_contracts: Vec<String>,
    #[serde(default)]
    pub configuration_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol_version: u8,
    operation: String,
    configuration: Value,
    input: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// one retained pack call, addressed by the digest of its contents.
pub struct PackInvocation {
    pub id: String,
    pub schema_version: String,
    pub contents: PackInvocationContents,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// the pack identity, executable digest, and the exact request and response.
pub struct PackInvocationContents {
    pub pack_id: String,
    pub pack_version: String,
    pub protocol_version: u8,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// for a collection, the execution core ran on the pack's behalf.
    pub execution_transcript_id: Option<String>,
    pub executable: BlobRef,
    pub request_sha256: String,
    pub response_sha256: String,
    pub request: String,
    pub response: String,
}

#[derive(Debug, Clone)]
/// a sealed invocation, the executable bytes behind it, and the parsed result.
pub struct PackCapture {
    pub invocation: PackInvocation,
    pub executable_bytes: Vec<u8>,
    pub result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// what a pack asks core to run, and how to interpret the result.
pub struct CollectionPlan {
    pub adapter: String,
    pub subject: Subject,
    pub observed_at: String,
    pub command: CommandPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// the command a pack asks core to execute on its behalf.
pub struct CommandPlan {
    pub tool_name: String,
    #[serde(default)]
    pub reported_version: Option<String>,
    pub executable: PathBuf,
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub inputs: BTreeMap<String, PathBuf>,
}

impl CommandPlan {
    /// convert this plan into a core execution request.
    #[must_use]
    pub fn execution_request(&self) -> ExecutionRequest {
        ExecutionRequest {
            tool_name: self.tool_name.clone(),
            reported_version: self.reported_version.clone(),
            executable: self.executable.clone(),
            argv: self.argv.clone(),
            working_directory: None,
            environment: BTreeMap::new(),
            inputs: self
                .inputs
                .iter()
                .map(|(name, path)| NamedPath {
                    name: name.clone(),
                    path: path.clone(),
                })
                .collect(),
            outputs: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// typed observation fields returned by a pack, before core assigns identity.
pub struct NormalizedObservation {
    pub claim_key: String,
    pub data: Value,
    pub evidence_class: EvidenceClass,
    pub kind: ObservationKind,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub status: Option<Status>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackAssertion {
    #[serde(default, rename = "id")]
    _legacy_id: Option<String>,
    assertion_type: AssertionType,
    claim: String,
    subject: AssertionSubject,
    outcome: Outcome,
    evaluated_at: String,
    validity: Validity,
    #[serde(default, rename = "derivation")]
    _legacy_derivation: Option<Derivation>,
    support: Vec<EvidenceUse>,
    contradictions: Vec<EvidenceUse>,
    considered: Vec<EvidenceUse>,
    missing: Vec<MissingEvidence>,
    identity_joins: Vec<IdentityJoin>,
    reasoning: Vec<ReasonStep>,
    limitations: Vec<String>,
    coverage: Vec<CoverageDecision>,
}

/// inspect an external pack and retain the exchange.
///
/// # Errors
///
/// returns an error when execution, protocol parsing, or metadata validation fails.
pub fn describe(config: &PackConfig) -> Result<(PackMetadata, PackCapture)> {
    let capture = invoke(config, None, "describe", Value::Null)?;
    let metadata: PackMetadata = serde_json::from_value(capture.result.clone())
        .map_err(|error| Error::Invalid(format!("invalid pack metadata: {error}")))?;
    validate_metadata(&metadata)?;
    let capture = reseal(capture, &metadata)?;
    Ok((metadata, capture))
}

/// ask a named collector for a core-executable command plan.
///
/// # Errors
///
/// returns an error when the collector is absent or its plan is invalid.
pub fn plan(
    config: &PackConfig,
    metadata: &PackMetadata,
    collector: &str,
    context: &Value,
) -> Result<(CollectionPlan, PackCapture)> {
    if !metadata.collectors.iter().any(|item| item == collector) {
        return Err(Error::Invalid(format!(
            "pack {} does not provide collector {collector}",
            metadata.id
        )));
    }
    let capture = invoke(
        config,
        Some(metadata),
        "collect",
        serde_json::json!({"collector": collector, "context": context}),
    )?;
    let plan = serde_json::from_value(capture.result.clone())
        .map_err(|error| Error::Invalid(format!("invalid pack collection plan: {error}")))?;
    Ok((plan, capture))
}

/// bind a core execution transcript to the collection plan that caused it.
///
/// # Errors
///
/// returns an error when the captured execution does not match the plan.
pub fn bind_execution(
    mut capture: PackCapture,
    transcript: &crate::execution::ExecutionTranscript,
) -> Result<PackCapture> {
    if capture.invocation.contents.operation != "collect" {
        return Err(Error::Invalid(
            "only a collect invocation can bind an execution".into(),
        ));
    }
    let plan: CollectionPlan = serde_json::from_value(capture.result.clone())
        .map_err(|error| Error::Invalid(format!("invalid retained collection plan: {error}")))?;
    validate_captured_execution(&plan.command, transcript)?;
    capture.invocation.contents.execution_transcript_id = Some(transcript.id.clone());
    capture.invocation = seal(capture.invocation.contents)?;
    Ok(capture)
}

/// ask a pack to normalize exact retained source bytes.
///
/// # Errors
///
/// returns an error when invocation or typed response validation fails.
pub fn normalize(
    config: &PackConfig,
    metadata: &PackMetadata,
    adapter: &str,
    source: &[u8],
    source_sha256: &str,
    subject: &Subject,
) -> Result<(NormalizedObservation, PackCapture)> {
    let content = String::from_utf8(source.to_vec())
        .map_err(|_| Error::Invalid("pack source is not utf-8".into()))?;
    let capture = invoke(
        config,
        Some(metadata),
        "normalize",
        serde_json::json!({
            "adapter": adapter,
            "source": {"content": content, "sha256": source_sha256},
            "subject": subject,
        }),
    )?;
    let observation = serde_json::from_value(capture.result.clone())
        .map_err(|error| Error::Invalid(format!("invalid pack observation: {error}")))?;
    Ok((observation, capture))
}

/// run one named pack evaluator over an explicit corpus and target.
///
/// # Errors
///
/// returns an error when invocation or assertion reference validation fails.
pub fn evaluate(
    config: &PackConfig,
    metadata: &PackMetadata,
    evaluator: &str,
    corpus: &crate::model::Corpus,
    target: &EvaluationTarget,
    evaluated_at: &str,
) -> Result<(Vec<DerivedAssertion>, PackCapture)> {
    if !metadata.evaluators.iter().any(|item| item == evaluator) {
        return Err(Error::Invalid(format!(
            "pack {} does not provide evaluator {evaluator}",
            metadata.id
        )));
    }
    let claim_keys = metadata.evaluator_inputs.get(evaluator).ok_or_else(|| {
        Error::Invalid(format!(
            "pack {} does not declare inputs for evaluator {evaluator}",
            metadata.id
        ))
    })?;
    let propositions = metadata
        .evaluator_propositions
        .get(evaluator)
        .ok_or_else(|| {
            Error::Invalid(format!(
                "pack {} does not declare coverage propositions for evaluator {evaluator}",
                metadata.id
            ))
        })?;
    let mut scoped = corpus.clone();
    let coverage_run_ids = scoped
        .collections
        .iter()
        .filter(|run| propositions.contains(&run.requested_scope.proposition))
        .map(|run| run.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    scoped.observations.retain(|item| {
        claim_keys.iter().any(|key| key == &item.claim_key)
            || item
                .collection_run_id
                .as_deref()
                .is_some_and(|id| coverage_run_ids.contains(id))
    });
    let source_ids = scoped
        .observations
        .iter()
        .map(|item| item.provenance.source_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    scoped
        .sources
        .retain(|source| source_ids.contains(source.id.as_str()));
    let observation_ids = scoped
        .observations
        .iter()
        .map(|item| item.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    scoped.collections.retain(|run| {
        propositions.contains(&run.requested_scope.proposition)
            || run
                .observation_ids
                .iter()
                .any(|id| observation_ids.contains(id.as_str()))
    });
    let capture = invoke(
        config,
        Some(metadata),
        "evaluate",
        serde_json::json!({
            "evaluator": evaluator,
            "corpus": scoped,
            "target": {
                "repository": target.repository,
                "branch": target.branch,
                "release": target.release,
                "from": target.from,
                "until": target.until,
            },
            "evaluated_at": evaluated_at,
        }),
    )?;
    let returned: Vec<PackAssertion> = serde_json::from_value(capture.result.clone())
        .map_err(|error| Error::Invalid(format!("invalid pack assertions: {error}")))?;
    let mut assertions = returned
        .into_iter()
        .map(|assertion| derived_assertion(assertion, &metadata.id, &metadata.version, evaluator))
        .collect::<Result<Vec<_>>>()?;
    validate_assertions(&assertions, corpus, metadata, evaluator, evaluated_at)?;
    for assertion in &mut assertions {
        assertion.derivation.pack_invocation_id = Some(capture.invocation.id.clone());
    }
    Ok((assertions, capture))
}

fn derived_assertion(
    assertion: PackAssertion,
    pack_id: &str,
    pack_version: &str,
    evaluator: &str,
) -> Result<DerivedAssertion> {
    let stable = serde_json::to_vec(&(&assertion.assertion_type, &assertion.subject))
        .map_err(Error::Serialize)?;
    Ok(DerivedAssertion {
        id: format!("asrt_{}", &hex_digest(&stable)[..20]),
        assertion_type: assertion.assertion_type,
        claim: assertion.claim,
        subject: assertion.subject,
        outcome: assertion.outcome,
        evaluated_at: assertion.evaluated_at,
        validity: assertion.validity,
        derivation: Derivation {
            evaluator: format!("pack:{pack_id}/{evaluator}"),
            version: pack_version.into(),
            pack_invocation_id: None,
        },
        support: assertion.support,
        contradictions: assertion.contradictions,
        considered: assertion.considered,
        missing: assertion.missing,
        identity_joins: assertion.identity_joins,
        reasoning: assertion.reasoning,
        limitations: assertion.limitations,
        coverage: assertion.coverage,
    })
}

/// bind normalized pack output to a core-owned observation.
///
/// # Errors
///
/// returns an error when its timestamp or deterministic identity is invalid.
pub fn observation(
    normalized: NormalizedObservation,
    metadata: &PackMetadata,
    invocation: &PackInvocation,
    source: &crate::model::SourceDocument,
    subject: Subject,
    observed_at: String,
    execution_transcript_id: String,
) -> Result<crate::model::Observation> {
    crate::parse_timestamp(&observed_at)?;
    let identity = serde_json::json!({
        "claim_key": normalized.claim_key,
        "execution_transcript": execution_transcript_id,
        "observed_at": observed_at,
        "pack_invocation": invocation.id,
        "source_sha256": source.sha256,
        "subject": subject,
    });
    let digest = hex_digest(&canonical_json(&identity)?);
    Ok(crate::model::Observation {
        claim_key: normalized.claim_key,
        collection_run_id: None,
        execution_transcript_ids: vec![execution_transcript_id],
        pack_invocation_ids: vec![invocation.id.clone()],
        data: normalized.data,
        evidence_class: normalized.evidence_class,
        id: format!("ev_{}", &digest[..20]),
        kind: normalized.kind,
        observed_at,
        producer: crate::model::Producer {
            name: metadata.id.clone(),
            version: metadata.version.clone(),
            collector: format!("pack:{}/{}", metadata.id, invocation.contents.operation),
        },
        provenance: crate::model::Provenance {
            pointer: String::new(),
            source_id: source.id.clone(),
        },
        severity: normalized.severity,
        status: normalized.status,
        subject,
    })
}

fn invoke(
    config: &PackConfig,
    metadata: Option<&PackMetadata>,
    operation: &str,
    input: Value,
) -> Result<PackCapture> {
    if !(1..=3600).contains(&config.timeout_seconds) {
        return Err(Error::Invalid(
            "pack timeout_seconds must be between 1 and 3600".into(),
        ));
    }
    reject_sensitive_configuration(&config.configuration, "configuration")?;
    let request = Request {
        protocol_version: PROTOCOL_VERSION,
        operation: operation.into(),
        configuration: config.configuration.clone(),
        input,
    };
    let request_bytes = canonical_json(&serde_json::to_value(&request).map_err(Error::Serialize)?)?;
    let executable_path = fs::canonicalize(&config.executable).map_err(|source| Error::Io {
        path: config.executable.clone(),
        source,
    })?;
    let executable_bytes = fs::read(&executable_path).map_err(|source| Error::Io {
        path: executable_path.clone(),
        source,
    })?;
    let mut child = Command::new(&executable_path)
        .env_clear()
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| Error::Io {
            path: executable_path,
            source,
        })?;
    let request_write = child
        .stdin
        .take()
        .ok_or_else(|| Error::Invalid("pack stdin unavailable".into()))?
        .write_all(&request_bytes);
    let (status, stdout, stderr) = wait_for_pack(
        &mut child,
        StdDuration::from_secs(config.timeout_seconds),
        operation,
    )?;
    if !status.success() {
        return Err(Error::Collection(format!(
            "pack {operation} exited with {:?}: {}",
            status.code(),
            String::from_utf8_lossy(&stderr).trim()
        )));
    }
    request_write
        .map_err(|source| Error::Collection(format!("cannot write pack request: {source}")))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&stdout);
    let response = Response::deserialize(&mut deserializer).map_err(|error| {
        Error::Collection(format!("invalid pack {operation} response: {error}"))
    })?;
    deserializer.end().map_err(|error| {
        Error::Collection(format!(
            "trailing output after pack {operation} response: {error}"
        ))
    })?;
    if !response.ok {
        return Err(Error::Collection(response.error.unwrap_or_else(|| {
            format!("pack {operation} failed without an error")
        })));
    }
    let result = response
        .result
        .ok_or_else(|| Error::Collection(format!("pack {operation} response missing result")))?;
    let response_bytes = canonical_json(&result)?;
    let executable = BlobRef {
        sha256: hex_digest(&executable_bytes),
        size: u64::try_from(executable_bytes.len())
            .map_err(|_| Error::Invalid("pack executable is too large".into()))?,
    };
    let contents = PackInvocationContents {
        pack_id: metadata
            .map_or("unresolved", |item| item.id.as_str())
            .into(),
        pack_version: metadata
            .map_or("unresolved", |item| item.version.as_str())
            .into(),
        protocol_version: PROTOCOL_VERSION,
        operation: operation.into(),
        execution_transcript_id: None,
        executable,
        request_sha256: hex_digest(&request_bytes),
        response_sha256: hex_digest(&response_bytes),
        request: String::from_utf8(request_bytes)
            .map_err(|_| Error::Invalid("pack request is not utf-8".into()))?,
        response: String::from_utf8(response_bytes)
            .map_err(|_| Error::Invalid("pack response is not utf-8".into()))?,
    };
    Ok(PackCapture {
        invocation: seal(contents)?,
        executable_bytes,
        result,
    })
}

fn wait_for_pack(
    child: &mut Child,
    timeout: StdDuration,
    operation: &str,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Collection("pack stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::Collection("pack stderr unavailable".into()))?;
    let (stdout_tx, stdout_rx) = mpsc::channel();
    let (stderr_tx, stderr_rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = stdout_tx.send(read_all(stdout));
    });
    thread::spawn(move || {
        let _ = stderr_tx.send(read_all(stderr));
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child
            .try_wait()
            .map_err(|source| Error::Collection(format!("cannot wait for pack: {source}")))?
        {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Collection(format!(
                    "pack {operation} timed out after {} second(s)",
                    timeout.as_secs()
                )));
            }
            None => thread::sleep(StdDuration::from_millis(10)),
        }
    };
    let stdout = receive_output(&stdout_rx, deadline, operation, "stdout")?;
    let stderr = receive_output(&stderr_rx, deadline, operation, "stderr")?;
    Ok((status, stdout, stderr))
}

fn receive_output(
    receiver: &mpsc::Receiver<std::io::Result<Vec<u8>>>,
    deadline: Instant,
    operation: &str,
    stream: &str,
) -> Result<Vec<u8>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    receiver
        .recv_timeout(remaining)
        .map_err(|_| {
            Error::Collection(format!(
                "pack {operation} {stream} did not close before timeout"
            ))
        })?
        .map_err(|source| Error::Collection(format!("cannot read pack {stream}: {source}")))
}

fn read_all(mut input: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn reject_sensitive_configuration(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let lowered = key.to_ascii_lowercase();
                if ["token", "password", "secret", "credential", "authorization"]
                    .iter()
                    .any(|word| lowered.contains(word))
                {
                    return Err(Error::Invalid(format!(
                        "refusing to retain credential-like pack configuration key {path}.{key}"
                    )));
                }
                reject_sensitive_configuration(value, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_sensitive_configuration(value, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// reject configuration that would retain credential-like values.
///
/// # Errors
///
/// returns an error when a nested key appears to contain credentials.
pub fn validate_configuration(value: &Value) -> Result<()> {
    reject_sensitive_configuration(value, "configuration")
}

fn reseal(mut capture: PackCapture, metadata: &PackMetadata) -> Result<PackCapture> {
    capture.invocation.contents.pack_id.clone_from(&metadata.id);
    capture
        .invocation
        .contents
        .pack_version
        .clone_from(&metadata.version);
    capture.invocation = seal(capture.invocation.contents)?;
    Ok(capture)
}

fn seal(contents: PackInvocationContents) -> Result<PackInvocation> {
    let digest = hex_digest(&canonical_json(
        &serde_json::to_value(&contents).map_err(Error::Serialize)?,
    )?);
    Ok(PackInvocation {
        id: format!("packrun_{}", &digest[..20]),
        schema_version: TRANSCRIPT_SCHEMA_VERSION.into(),
        contents,
    })
}

/// verify one retained pack invocation offline.
///
/// # Errors
///
/// returns an error when its identity, executable, request, or response changed.
pub fn verify(invocation: &PackInvocation, blobs: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    if seal(invocation.contents.clone())?.id != invocation.id
        || invocation.schema_version != TRANSCRIPT_SCHEMA_VERSION
    {
        return Err(Error::Provenance(format!(
            "pack invocation identity mismatch: {}",
            invocation.id
        )));
    }
    let executable = blobs
        .get(&invocation.contents.executable.sha256)
        .ok_or_else(|| Error::Provenance("pack executable blob is missing".into()))?;
    if hex_digest(executable) != invocation.contents.executable.sha256
        || u64::try_from(executable.len()).ok() != Some(invocation.contents.executable.size)
        || hex_digest(invocation.contents.request.as_bytes()) != invocation.contents.request_sha256
        || hex_digest(invocation.contents.response.as_bytes())
            != invocation.contents.response_sha256
    {
        return Err(Error::Provenance(format!(
            "pack invocation failed integrity: {}",
            invocation.id
        )));
    }
    Ok(())
}

/// verify every observation-to-pack link.
///
/// # Errors
///
/// returns an error for missing, invalid, or semantically mismatched invocations.
pub fn verify_observation_links(
    corpus: &crate::model::Corpus,
    invocations: &[PackInvocation],
    executions: &[crate::execution::ExecutionTranscript],
    blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let by_id = invocations
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    for observation in &corpus.observations {
        let mut identity: Option<(&str, &str, &BlobRef)> = None;
        let mut operations = BTreeMap::new();
        for invocation_id in &observation.pack_invocation_ids {
            let invocation = by_id.get(invocation_id.as_str()).ok_or_else(|| {
                Error::Provenance(format!(
                    "observation {} references missing pack invocation {invocation_id}",
                    observation.id
                ))
            })?;
            verify(invocation, blobs)?;
            let current = (
                invocation.contents.pack_id.as_str(),
                invocation.contents.pack_version.as_str(),
                &invocation.contents.executable,
            );
            if let Some(expected) = identity {
                if current != expected {
                    return Err(Error::Provenance(format!(
                        "observation {} mixes identities from different pack executables",
                        observation.id
                    )));
                }
            } else {
                identity = Some(current);
            }
            let source = corpus
                .sources
                .iter()
                .find(|item| item.id == observation.provenance.source_id)
                .ok_or_else(|| {
                    Error::Provenance(format!(
                        "observation {} references missing source {}",
                        observation.id, observation.provenance.source_id
                    ))
                })?;
            verify_observation_invocation(observation, source, invocation, executions)?;
            *operations
                .entry(invocation.contents.operation.as_str())
                .or_insert(0_usize) += 1;
        }
        if let Some((pack_id, pack_version, _)) = identity {
            if operations.get("describe") != Some(&1)
                || operations.get("collect") != Some(&1)
                || operations.get("normalize") != Some(&1)
                || operations.len() != 3
                || observation.producer.name != pack_id
                || observation.producer.version != pack_version
            {
                return Err(Error::Provenance(format!(
                    "observation {} is not bound to its normalizing pack identity",
                    observation.id
                )));
            }
        }
    }
    Ok(())
}

fn verify_observation_invocation(
    observation: &crate::model::Observation,
    source: &crate::model::SourceDocument,
    invocation: &PackInvocation,
    executions: &[crate::execution::ExecutionTranscript],
) -> Result<()> {
    match invocation.contents.operation.as_str() {
        "describe" => {
            let metadata: PackMetadata = serde_json::from_str(&invocation.contents.response)
                .map_err(|error| {
                    Error::Provenance(format!("invalid retained pack metadata: {error}"))
                })?;
            validate_metadata(&metadata)?;
            if metadata.id != observation.producer.name
                || metadata.version != observation.producer.version
            {
                return Err(Error::Provenance(format!(
                    "describe invocation does not bind observation {} producer",
                    observation.id
                )));
            }
        }
        "collect" => {
            let plan: CollectionPlan = serde_json::from_str(&invocation.contents.response)
                .map_err(|error| {
                    Error::Provenance(format!("invalid retained collection plan: {error}"))
                })?;
            if plan.subject != observation.subject
                || plan.observed_at != observation.observed_at
                || plan.adapter != source.format
            {
                return Err(Error::Provenance(format!(
                    "collect invocation does not bind observation {} subject, time, or adapter",
                    observation.id
                )));
            }
            let Some(execution_id) = &invocation.contents.execution_transcript_id else {
                return Err(Error::Provenance(format!(
                    "collect invocation does not name the execution for observation {}",
                    observation.id
                )));
            };
            if !observation.execution_transcript_ids.contains(execution_id) {
                return Err(Error::Provenance(format!(
                    "collect invocation execution does not match observation {}",
                    observation.id
                )));
            }
            let execution = executions
                .iter()
                .find(|item| item.id == *execution_id)
                .ok_or_else(|| {
                    Error::Provenance(format!(
                        "collect invocation references missing execution {execution_id}"
                    ))
                })?;
            validate_retained_execution(&plan.command, execution)?;
            if execution.contents.stdout.sha256 != source.sha256 {
                return Err(Error::Provenance(format!(
                    "collect execution output does not match observation {} source",
                    observation.id
                )));
            }
        }
        "normalize" => {
            let request: Value =
                serde_json::from_str(&invocation.contents.request).map_err(|error| {
                    Error::Provenance(format!("invalid retained normalize request: {error}"))
                })?;
            if request["input"]["adapter"] != source.format
                || request["input"]["source"]["sha256"] != source.sha256
                || request["input"]["subject"]
                    != serde_json::to_value(&observation.subject).map_err(Error::Serialize)?
            {
                return Err(Error::Provenance(format!(
                    "normalize invocation does not bind observation {}",
                    observation.id
                )));
            }
        }
        _ => {
            return Err(Error::Provenance(format!(
                "pack operation {} cannot bind an observation",
                invocation.contents.operation
            )));
        }
    }
    Ok(())
}

fn validate_captured_execution(
    plan: &CommandPlan,
    transcript: &crate::execution::ExecutionTranscript,
) -> Result<()> {
    validate_retained_execution(plan, transcript)?;
    let executable = fs::read(&plan.executable).map_err(|source| Error::Io {
        path: plan.executable.clone(),
        source,
    })?;
    if hex_digest(&executable) != transcript.contents.tool.executable.sha256 {
        return Err(Error::Provenance(
            "pack collection executable does not match captured execution".into(),
        ));
    }
    for (name, path) in &plan.inputs {
        let input = fs::read(path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        let retained = transcript
            .contents
            .inputs
            .iter()
            .find(|item| item.name == *name)
            .ok_or_else(|| {
                Error::Provenance(format!("pack collection input {name} was not captured"))
            })?;
        if hex_digest(&input) != retained.blob.sha256 {
            return Err(Error::Provenance(format!(
                "pack collection input {name} does not match captured execution"
            )));
        }
    }
    Ok(())
}

fn validate_retained_execution(
    plan: &CommandPlan,
    transcript: &crate::execution::ExecutionTranscript,
) -> Result<()> {
    let input_names = plan.inputs.keys().cloned().collect::<Vec<_>>();
    let retained_names = transcript
        .contents
        .inputs
        .iter()
        .map(|item| item.name.clone())
        .collect::<Vec<_>>();
    if transcript.contents.tool.name != plan.tool_name
        || transcript.contents.tool.reported_version != plan.reported_version
        || transcript.contents.argv != plan.argv
        || transcript.contents.working_directory.is_some()
        || !transcript.contents.environment.is_empty()
        || !transcript.contents.outputs.is_empty()
        || input_names != retained_names
    {
        return Err(Error::Provenance(format!(
            "execution {} does not match its pack collection plan",
            transcript.id
        )));
    }
    Ok(())
}

/// verify every assertion-to-pack link.
///
/// # Errors
///
/// returns an error for missing, invalid, or mismatched evaluator invocations.
pub fn verify_assertion_links(
    assertions: &[DerivedAssertion],
    invocations: &[PackInvocation],
    blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    for assertion in assertions {
        let Some(invocation_id) = &assertion.derivation.pack_invocation_id else {
            continue;
        };
        let invocation = invocations
            .iter()
            .find(|item| item.id == *invocation_id)
            .ok_or_else(|| {
                Error::Provenance(format!(
                    "assertion {} references missing pack invocation {invocation_id}",
                    assertion.id
                ))
            })?;
        verify(invocation, blobs)?;
        if invocation.contents.operation != "evaluate"
            || assertion.derivation.evaluator
                != format!(
                    "pack:{}/{}",
                    invocation.contents.pack_id,
                    evaluator_name(assertion)
                )
            || assertion.derivation.version != invocation.contents.pack_version
        {
            return Err(Error::Provenance(format!(
                "pack invocation {invocation_id} does not bind assertion {}",
                assertion.id
            )));
        }
        let request: Value =
            serde_json::from_str(&invocation.contents.request).map_err(|error| {
                Error::Provenance(format!("invalid retained pack evaluation request: {error}"))
            })?;
        let evaluator = request["input"]["evaluator"].as_str().ok_or_else(|| {
            Error::Provenance("pack evaluation request does not name an evaluator".into())
        })?;
        let returned: Vec<PackAssertion> = serde_json::from_str(&invocation.contents.response)
            .map_err(|error| {
                Error::Provenance(format!("invalid retained pack assertion response: {error}"))
            })?;
        let expected = returned
            .into_iter()
            .map(|item| {
                let mut derived = derived_assertion(
                    item,
                    &invocation.contents.pack_id,
                    &invocation.contents.pack_version,
                    evaluator,
                )?;
                derived.derivation.pack_invocation_id = Some(invocation.id.clone());
                Ok(derived)
            })
            .collect::<Result<Vec<_>>>()?;
        if !expected.contains(assertion) {
            return Err(Error::Provenance(format!(
                "saved assertion {} does not match its retained pack response",
                assertion.id
            )));
        }
    }
    Ok(())
}

fn evaluator_name(assertion: &DerivedAssertion) -> &str {
    assertion
        .derivation
        .evaluator
        .rsplit('/')
        .next()
        .unwrap_or(&assertion.derivation.evaluator)
}

fn validate_metadata(metadata: &PackMetadata) -> Result<()> {
    if metadata.protocol_version != PROTOCOL_VERSION {
        return Err(Error::Invalid(format!(
            "pack {} uses protocol {}, expected {}",
            metadata.id, metadata.protocol_version, PROTOCOL_VERSION
        )));
    }
    if metadata.id.trim().is_empty() || metadata.version.trim().is_empty() {
        return Err(Error::Invalid(
            "pack id and version must not be empty".into(),
        ));
    }
    Ok(())
}

fn validate_assertions(
    assertions: &[DerivedAssertion],
    corpus: &crate::model::Corpus,
    metadata: &PackMetadata,
    evaluator: &str,
    evaluated_at: &str,
) -> Result<()> {
    let evaluated_at_time = crate::parse_timestamp(evaluated_at)?;
    let declared_propositions =
        metadata
            .evaluator_propositions
            .get(evaluator)
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "pack {} does not declare coverage propositions for evaluator {evaluator}",
                    metadata.id
                ))
            })?;
    for assertion in assertions {
        if assertion.evaluated_at != evaluated_at {
            return Err(Error::Invalid(format!(
                "pack {} returned an assertion for a different evaluation time",
                metadata.id
            )));
        }
        for decision in &assertion.coverage {
            if !declared_propositions.contains(&decision.requirement.proposition) {
                return Err(Error::Invalid(format!(
                    "pack {} returned undeclared coverage proposition {:?}",
                    metadata.id, decision.requirement.proposition
                )));
            }
            let expected =
                coverage::assess(corpus, decision.requirement.clone(), evaluated_at_time)?;
            if expected != *decision {
                return Err(Error::Invalid(format!(
                    "pack {} returned a coverage decision that does not match core assessment",
                    metadata.id
                )));
            }
        }
        if assertion.outcome == Outcome::Supported {
            validate_supported_coverage(assertion, declared_propositions, metadata)?;
        }
        for evidence in assertion
            .support
            .iter()
            .chain(&assertion.contradictions)
            .chain(&assertion.considered)
        {
            let observation = corpus
                .observations
                .iter()
                .find(|item| item.id == evidence.observation_id)
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "pack assertion references missing observation {}",
                        evidence.observation_id
                    ))
                })?;
            if observation.provenance.source_id != evidence.source_id {
                return Err(Error::Invalid(format!(
                    "pack assertion source does not match observation {}",
                    evidence.observation_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_supported_coverage(
    assertion: &DerivedAssertion,
    declared: &[Proposition],
    metadata: &PackMetadata,
) -> Result<()> {
    if !declared.is_empty()
        && (assertion.subject.from.is_none() || assertion.subject.until.is_none())
    {
        return Err(Error::Invalid(format!(
            "pack {} returned a coverage-backed supported assertion whose subject lacks from or until",
            metadata.id
        )));
    }
    for proposition in declared {
        let matching = assertion
            .coverage
            .iter()
            .filter(|decision| {
                decision.requirement.proposition == *proposition
                    && decision.requirement.repository == assertion.subject.repository
                    && decision.requirement.branch == assertion.subject.branch
                    && assertion
                        .subject
                        .from
                        .as_ref()
                        .is_some_and(|from| decision.requirement.interval.from == *from)
                    && assertion
                        .subject
                        .until
                        .as_ref()
                        .is_some_and(|until| decision.requirement.interval.until == *until)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 || matching[0].outcome != CoverageOutcome::Complete {
            return Err(Error::Invalid(format!(
                "pack {} returned supported without complete {:?} coverage for the assertion scope",
                metadata.id, proposition
            )));
        }
    }
    Ok(())
}
