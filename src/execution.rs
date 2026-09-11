//! local command execution and transcripts.
//!
//! [`capture`] records executable identity, argv, named inputs and outputs, exit
//! status, and exact streams. commands receive an empty environment plus explicit
//! values. credential-like arguments are rejected and streams are not redacted.
//! [`verify`] checks the transcript and every referenced blob offline.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::{hex_digest, parse_timestamp};

/// the execution transcript format version this build reads and writes.
pub const TRANSCRIPT_SCHEMA_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// one preserved local command, addressed by the digest of its contents.
pub struct ExecutionTranscript {
    pub id: String,
    pub schema_version: String,
    pub contents: ExecutionContents,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// retained command identity, inputs, timing, exit status, and output.
pub struct ExecutionContents {
    pub tool: ToolIdentity,
    pub argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// a label only. the path is not resolved on verification.
    pub working_directory: Option<String>,
    #[serde(default)]
    /// the explicit values passed. ambient environment is neither passed nor recorded.
    pub environment: BTreeMap<String, String>,
    pub inputs: Vec<NamedBlob>,
    pub started_at: String,
    pub completed_at: String,
    pub exit: ExitStatus,
    pub stdout: RetainedBytes,
    pub stderr: RetainedBytes,
    pub outputs: Vec<NamedBlob>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// what actually ran.
///
/// `reported_version` is metadata. the executable digest is the identity.
pub struct ToolIdentity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// the version reported by the tool.
    pub reported_version: Option<String>,
    pub executable: BlobRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// a named input or output and the content it resolves to.
pub struct NamedBlob {
    pub name: String,
    pub blob: BlobRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// content addressed by sha-256 and size.
pub struct BlobRef {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// a stream preserved exactly, hex-encoded so non-utf8 output survives.
///
/// capture always sets `sanitized` to false. decoding rejects any other value.
pub struct RetainedBytes {
    pub encoding: ByteEncoding,
    pub content: String,
    pub sha256: String,
    pub size: u64,
    /// always false on capture. a sanitized stream refuses to decode.
    pub sanitized: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// how retained stream bytes are encoded.
pub enum ByteEncoding {
    Hex,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// the command's exit code and success flag.
pub struct ExitStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    pub success: bool,
}

#[derive(Debug, Clone)]
/// a named file to record as an input or output.
pub struct NamedPath {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
/// what to run and what to retain.
///
/// the command runs with an empty environment plus `environment`. ambient
/// environment is neither passed nor recorded, and credential-like arguments are refused.
pub struct ExecutionRequest {
    pub tool_name: String,
    pub reported_version: Option<String>,
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub working_directory: Option<PathBuf>,
    /// the command runs with an empty environment plus these explicit values.
    pub environment: BTreeMap<String, String>,
    pub inputs: Vec<NamedPath>,
    pub outputs: Vec<NamedPath>,
}

#[derive(Debug, Clone)]
/// a sealed transcript and the blobs it references.
pub struct ExecutionCapture {
    pub transcript: ExecutionTranscript,
    pub blobs: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
/// the result of verifying one transcript and its blobs offline.
pub struct Verification {
    pub transcript_id: String,
    pub integrity: Integrity,
    pub verified_blobs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// whether a transcript and its blobs still verify.
pub enum Integrity {
    Verified,
    Failed,
}

/// execute a command with an explicit environment and retain exact bytes.
///
/// executable, input, and output files are returned as content-addressed blobs.
///
/// # Errors
///
/// returns an error when an input cannot be read, an argument appears to contain a
/// credential, the command cannot start, or a declared output is absent.
pub fn capture(request: &ExecutionRequest) -> Result<ExecutionCapture> {
    validate_request(request)?;
    let executable_bytes = read_bytes(&request.executable)?;
    let executable = blob_ref(&executable_bytes)?;
    let mut blobs = BTreeMap::from([(executable.sha256.clone(), executable_bytes)]);
    let inputs = read_named_blobs(&request.inputs, &mut blobs)?;

    let started_at = format_time(OffsetDateTime::now_utc())?;
    let mut command = Command::new(&request.executable);
    command
        .args(&request.argv)
        .env_clear()
        .envs(&request.environment);
    if let Some(directory) = &request.working_directory {
        command.current_dir(directory);
    }
    let output = command.output().map_err(|source| Error::Io {
        path: request.executable.clone(),
        source,
    })?;
    let completed_at = format_time(OffsetDateTime::now_utc())?;
    let outputs = read_named_blobs(&request.outputs, &mut blobs)?;
    let contents = ExecutionContents {
        tool: ToolIdentity {
            name: request.tool_name.clone(),
            reported_version: request.reported_version.clone(),
            executable,
        },
        argv: request.argv.clone(),
        working_directory: request
            .working_directory
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        environment: request.environment.clone(),
        inputs,
        started_at,
        completed_at,
        exit: ExitStatus {
            code: output.status.code(),
            success: output.status.success(),
        },
        stdout: retain(&output.stdout)?,
        stderr: retain(&output.stderr)?,
        outputs,
    };
    Ok(ExecutionCapture {
        transcript: seal(contents)?,
        blobs,
    })
}

/// check whether a verified transcript represents the same executable, arguments,
/// declared inputs, working directory, and explicit environment.
///
/// # Errors
///
/// returns an error when the request cannot be inspected.
pub fn matches_request(
    transcript: &ExecutionTranscript,
    request: &ExecutionRequest,
) -> Result<bool> {
    validate_request(request)?;
    let working_directory = request
        .working_directory
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    if transcript.contents.tool.name != request.tool_name
        || transcript.contents.tool.reported_version != request.reported_version
        || transcript.contents.argv != request.argv
        || transcript.contents.working_directory != working_directory
        || transcript.contents.environment != request.environment
    {
        return Ok(false);
    }
    let executable = blob_ref(&read_bytes(&request.executable)?)?;
    let mut ignored = BTreeMap::new();
    let inputs = read_named_blobs(&request.inputs, &mut ignored)?;
    Ok(transcript.contents.tool.executable == executable && transcript.contents.inputs == inputs)
}

/// create a content-addressed execution transcript.
///
/// # Errors
///
/// returns an error when timestamps or retained byte digests are invalid, or the
/// contents cannot be serialized.
pub fn seal(contents: ExecutionContents) -> Result<ExecutionTranscript> {
    validate_contents(&contents)?;
    let bytes = serde_json::to_vec(&contents).map_err(Error::Serialize)?;
    Ok(ExecutionTranscript {
        id: format!("exec_{}", &hex_digest(&bytes)[..20]),
        schema_version: TRANSCRIPT_SCHEMA_VERSION.into(),
        contents,
    })
}

/// verify transcript identity, embedded streams, and all external blobs offline.
///
/// # Errors
///
/// returns an error when a referenced blob is missing or any content was changed.
pub fn verify(
    transcript: &ExecutionTranscript,
    blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<Verification> {
    let sealed = seal(transcript.contents.clone())?;
    if sealed.id != transcript.id || transcript.schema_version != TRANSCRIPT_SCHEMA_VERSION {
        return Err(Error::Invalid(format!(
            "execution transcript identity mismatch: {}",
            transcript.id
        )));
    }
    let mut refs = vec![&transcript.contents.tool.executable];
    refs.extend(transcript.contents.inputs.iter().map(|item| &item.blob));
    refs.extend(transcript.contents.outputs.iter().map(|item| &item.blob));
    let mut verified = Vec::new();
    for reference in refs {
        let bytes = blobs.get(&reference.sha256).ok_or_else(|| {
            Error::Invalid(format!("missing execution blob: {}", reference.sha256))
        })?;
        if blob_ref(bytes)? != *reference {
            return Err(Error::Invalid(format!(
                "execution blob failed integrity: {}",
                reference.sha256
            )));
        }
        verified.push(reference.sha256.clone());
    }
    verified.sort();
    verified.dedup();
    Ok(Verification {
        transcript_id: transcript.id.clone(),
        integrity: Integrity::Verified,
        verified_blobs: verified,
    })
}

/// recover exact retained stdout bytes.
///
/// # Errors
///
/// returns an error if the encoded content is malformed or fails its digest.
pub fn stdout_bytes(transcript: &ExecutionTranscript) -> Result<Vec<u8>> {
    decode_retained(&transcript.contents.stdout)
}

/// recover exact retained stderr bytes.
///
/// # Errors
///
/// returns an error if the encoded content is malformed or fails its digest.
pub fn stderr_bytes(transcript: &ExecutionTranscript) -> Result<Vec<u8>> {
    decode_retained(&transcript.contents.stderr)
}

fn validate_request(request: &ExecutionRequest) -> Result<()> {
    if request.tool_name.trim().is_empty() {
        return Err(Error::Invalid("tool name must not be empty".into()));
    }
    let sensitive = ["token", "password", "secret", "authorization", "credential"];
    for argument in &request.argv {
        let option = argument
            .trim_start_matches('-')
            .split_once('=')
            .map_or(argument.as_str(), |(name, _)| name)
            .to_ascii_lowercase();
        if sensitive.iter().any(|word| option.contains(word)) {
            return Err(Error::Invalid(format!(
                "refusing to retain credential-like argument: {argument}"
            )));
        }
    }
    Ok(())
}

fn validate_contents(contents: &ExecutionContents) -> Result<()> {
    let started = parse_timestamp(&contents.started_at)?;
    let completed = parse_timestamp(&contents.completed_at)?;
    if started > completed {
        return Err(Error::Invalid(
            "execution completes before it starts".into(),
        ));
    }
    decode_retained(&contents.stdout)?;
    decode_retained(&contents.stderr)?;
    Ok(())
}

fn read_named_blobs(
    paths: &[NamedPath],
    blobs: &mut BTreeMap<String, Vec<u8>>,
) -> Result<Vec<NamedBlob>> {
    let mut named = Vec::with_capacity(paths.len());
    for item in paths {
        let bytes = read_bytes(&item.path)?;
        let blob = blob_ref(&bytes)?;
        blobs.entry(blob.sha256.clone()).or_insert(bytes);
        named.push(NamedBlob {
            name: item.name.clone(),
            blob,
        });
    }
    named.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(named)
}

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn blob_ref(bytes: &[u8]) -> Result<BlobRef> {
    Ok(BlobRef {
        sha256: hex_digest(bytes),
        size: u64::try_from(bytes.len())
            .map_err(|_| Error::Invalid("content is too large to address".into()))?,
    })
}

fn retain(bytes: &[u8]) -> Result<RetainedBytes> {
    Ok(RetainedBytes {
        encoding: ByteEncoding::Hex,
        content: hex_encode(bytes),
        sha256: hex_digest(bytes),
        size: u64::try_from(bytes.len())
            .map_err(|_| Error::Invalid("stream is too large to retain".into()))?,
        sanitized: false,
    })
}

fn decode_retained(retained: &RetainedBytes) -> Result<Vec<u8>> {
    let bytes = hex_decode(&retained.content)?;
    if retained.sanitized {
        return Err(Error::Invalid(
            "sanitized execution stream cannot claim exact-byte preservation".into(),
        ));
    }
    if blob_ref(&bytes)?
        != (BlobRef {
            sha256: retained.sha256.clone(),
            size: retained.size,
        })
    {
        return Err(Error::Invalid(
            "retained execution stream failed integrity".into(),
        ));
    }
    Ok(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::Invalid("invalid hexadecimal byte encoding".into()));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Invalid("invalid hexadecimal byte encoding".into())),
    }
}

fn format_time(value: OffsetDateTime) -> Result<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| Error::Invalid(format!("cannot format execution timestamp: {error}")))
}
